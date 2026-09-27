# The node model a binary XML fragment expands into, plus template binding. A
# template body is parsed once and kept as a tree of elements and placeholders,
# then every instance binds that tree against its own substitution values, so
# the parsed tree is never mutated in place.

from .values import TYPE_NULL, Variant


class Node:
    # base class so a walk never needs isinstance chains for the simple nodes
    __slots__ = ()

    def text(self):
        return ""


class Text(Node):
    # literal character data inside an element
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value

    def text(self):
        return self.value

    def __repr__(self):
        return "Text(%r)" % (self.value[:40],)


class Element(Node):
    # attributes are kept as a list of [name, value] pairs so order survives
    __slots__ = ("tag", "attributes", "content", "origin")

    def __init__(self, tag, attributes=None, content=None, origin=None):
        self.tag = tag
        self.attributes = attributes if attributes is not None else []
        self.content = content if content is not None else []
        # origin records whether the element came from a template or a plain stream
        self.origin = origin

    def __repr__(self):
        return "Element(%s, attrs=%d, children=%d)" % (self.tag, len(self.attributes), len(self.content))

    def attribute(self, name):
        # case insensitive lookup, None when absent
        lowered = name.lower()
        for key, value in self.attributes:
            if key.lower() == lowered:
                return value
        return None

    def attribute_text(self, name, default=""):
        value = self.attribute(name)
        if value is None:
            return default
        if isinstance(value, Variant):
            return value.text
        return str(value)

    def find_all(self, tag):
        # depth first search for every descendant element with this tag
        found = []
        for node in self.content:
            if isinstance(node, Element):
                if node.tag == tag:
                    found.append(node)
                found.extend(node.find_all(tag))
        return found

    def find(self, tag):
        found = self.find_all(tag)
        return found[0] if found else None

    def child(self, tag):
        # direct child only, used for System, EventData and UserData
        for node in self.content:
            if isinstance(node, Element) and node.tag == tag:
                return node
        return None

    def children_named(self, tag):
        return [node for node in self.content if isinstance(node, Element) and node.tag == tag]

    def text_content(self):
        # concatenated text of every descendant in document order
        parts = []

        def walk(nodes):
            for node in nodes:
                if isinstance(node, Text):
                    parts.append(node.value)
                elif isinstance(node, Element):
                    walk(node.content)
                elif isinstance(node, Variant):
                    parts.append(node.text)
                elif isinstance(node, list):
                    walk(node)
                else:
                    parts.append(str(getattr(node, "value", "")))

        walk(self.content)
        return "".join(parts)

    def walk(self):
        # yield this element then every descendant element
        yield self
        for node in self.content:
            if isinstance(node, Element):
                for item in node.walk():
                    yield item

    def path(self):
        # dotted tag path built from the tags above this element
        return self.tag


class Placeholder(Node):
    # a substitution slot inside a template body, filled when an instance binds
    __slots__ = ("index", "type_id", "conditional")

    def __init__(self, index, type_id, conditional=False):
        self.index = index
        self.type_id = type_id
        self.conditional = conditional

    def __repr__(self):
        return "Placeholder(index=%d, type=0x%02x, conditional=%s)" % (self.index, self.type_id, self.conditional)


class CharRef(Node):
    # character reference token, kept as text because it renders identically
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value

    def text(self):
        return self.value


class EntityRef(Node):
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name

    def text(self):
        return "&%s;" % self.name


class ProcessingInstruction(Node):
    __slots__ = ("target", "data", "kind")

    def __init__(self, target, data="", kind="target"):
        self.target = target
        self.data = data
        # kind distinguishes the target token from the data token
        self.kind = kind

    def text(self):
        return self.data


class TemplateBody:
    # a parsed template definition, reused by every instance pointing at it
    __slots__ = ("offset", "template_id", "guid", "data_length", "nodes", "placeholder_count", "element_count")

    def __init__(self, offset, template_id, guid, data_length, nodes):
        self.offset = offset
        self.template_id = template_id
        self.guid = guid
        self.data_length = data_length
        self.nodes = nodes
        self.placeholder_count = max_placeholder(nodes) + 1
        self.element_count = sum(1 for _ in iter_elements(nodes))

    def __repr__(self):
        return "TemplateBody(offset=0x%x, id=%d, elements=%d, placeholders=%d)" % (
            self.offset,
            self.template_id,
            self.element_count,
            self.placeholder_count,
        )


class Binding:
    # the result of binding one template body against one instance's values
    __slots__ = ("nodes", "missing", "suppressed", "values")

    def __init__(self, nodes, missing, suppressed, values):
        self.nodes = nodes
        self.missing = missing
        self.suppressed = suppressed
        self.values = values


def iter_elements(nodes):
    # walk a node list and yield every element in document order
    for node in nodes:
        if isinstance(node, Element):
            yield node
            for item in iter_elements(node.content):
                yield item


def max_placeholder(nodes):
    # highest substitution index referenced anywhere in a node list
    highest = -1
    for node in nodes:
        if isinstance(node, Placeholder):
            highest = max(highest, node.index)
        elif isinstance(node, Element):
            for _, value in node.attributes:
                if isinstance(value, Placeholder):
                    highest = max(highest, value.index)
            highest = max(highest, max_placeholder(node.content))
    return highest


def bind(nodes, substitutions):
    # Bind a parsed template body against one instance's values. A normal
    # substitution always resolves, a missing one becomes empty text. A
    # conditional substitution whose value is null drops the element or
    # attribute holding it, which is how optional fields disappear from the
    # event viewer, so the decision is made while building each element.
    missing = []
    suppressed = [0]

    def resolve(node):
        # returns (value, suppress) for one placeholder
        if node.index >= len(substitutions):
            missing.append(node.index)
            if node.conditional:
                suppressed[0] += 1
                return None, True
            return "", False
        variant = substitutions[node.index]
        if variant is None:
            missing.append(node.index)
            if node.conditional:
                suppressed[0] += 1
                return None, True
            return "", False
        if node.conditional and (variant.type_id == TYPE_NULL or variant.text == ""):
            suppressed[0] += 1
            return None, True
        return variant, False

    def bind_value(value):
        if isinstance(value, Placeholder):
            return resolve(value)
        if isinstance(value, Text) or isinstance(value, CharRef):
            return value.value, False
        return value, False

    def append_value(result, value):
        # a BinXml value carries a whole subtree rather than text, so it is
        # spliced in place instead of being turned into an escaped string
        nested = getattr(value, "nested", None)
        if nested:
            result.extend(nested)
            return
        result.append(Text(value.text if isinstance(value, Variant) else str(value)))

    def bind_attributes(node):
        attributes = []
        for name, value in node.attributes:
            resolved, drop = bind_value(value)
            if drop or resolved is None:
                # a null substitution behind an attribute leaves the attribute in
                # place and empty, which is what the event viewer shows
                attributes.append([name, ""])
                continue
            attributes.append([name, resolved])
        return attributes

    def conditional_only(node):
        # an element whose entire content is one null conditional substitution
        # disappears together with its tag
        if len(node.content) != 1:
            return False
        child = node.content[0]
        return isinstance(child, Placeholder) and child.conditional

    def bind_nodes(source):
        result = []
        for node in source:
            if isinstance(node, (Text, CharRef, EntityRef, ProcessingInstruction)):
                result.append(node)
                continue
            if isinstance(node, Variant) or not isinstance(node, (Placeholder, Element)):
                # a literal value token sitting in a template body is content too
                append_value(result, node)
                continue
            if isinstance(node, Placeholder):
                value, drop = resolve(node)
                if drop or value is None or (isinstance(value, str) and value == ""):
                    continue
                append_value(result, value)
                continue
            if isinstance(node, Element):
                if conditional_only(node):
                    value, drop = resolve(node.content[0])
                    # a null conditional substitution leaves the element standing
                    # with empty content rather than removing the tag
                    content = []
                    if not drop and value is not None:
                        append_value(content, value)
                    result.append(Element(node.tag, bind_attributes(node), content, node.origin))
                    continue
                result.append(Element(node.tag, bind_attributes(node), bind_nodes(node.content), node.origin))
        return result

    return Binding(bind_nodes(nodes), missing, suppressed[0], substitutions)
