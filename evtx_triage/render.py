# XML rendering of bound node trees: escaping, self closing tags, and the
# indented form used by the dump command. Control characters that XML 1.0 cannot
# represent are replaced rather than dropped, so a payload never loses bytes
# silently without a marker.

from .nodes import CharRef, Element, EntityRef, ProcessingInstruction, Text
from .values import Variant

# tab, newline and carriage return are legal in XML, everything else below 0x20
# is not, and hostile or simply binary payloads do contain those bytes
ILLEGAL_XML_CHARS = {}
for _code in range(0x20):
    if _code not in (0x09, 0x0A, 0x0D):
        ILLEGAL_XML_CHARS[chr(_code)] = "."
del _code


def escape_text(value):
    # element content escaping, illegal control characters replaced first
    if not value:
        return ""
    out = []
    for char in value:
        replacement = ILLEGAL_XML_CHARS.get(char)
        if replacement is not None:
            out.append(replacement)
        elif char == "&":
            out.append("&amp;")
        elif char == "<":
            out.append("&lt;")
        elif char == ">":
            out.append("&gt;")
        else:
            out.append(char)
    return "".join(out)


def escape_attribute(value):
    # attribute escaping, also covers the double quote and the apostrophe
    if not value:
        return ""
    escaped = escape_text(value)
    if '"' in escaped:
        escaped = escaped.replace('"', "&quot;")
    if "'" in escaped:
        escaped = escaped.replace("'", "&apos;")
    return escaped


def value_text(value):
    # a Variant renders as its text, a string as itself, anything else is empty
    if isinstance(value, Variant):
        return value.text
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return str(value)


def attributes_text(element):
    parts = []
    for name, value in element.attributes:
        parts.append(' %s="%s"' % (name, escape_attribute(value_text(value))))
    return "".join(parts)


def render_xml(nodes):
    # compact rendering, one string, matching what the event viewer shows
    parts = []

    def render_node(node):
        if isinstance(node, Text):
            parts.append(escape_text(node.value))
            return
        if isinstance(node, Variant):
            # a literal value token inside a template body
            parts.append(escape_text(node.text))
            return
        if isinstance(node, CharRef):
            parts.append(escape_text(node.value))
            return
        if isinstance(node, EntityRef):
            parts.append(node.text())
            return
        if isinstance(node, ProcessingInstruction):
            if node.kind == "target" and not node.data:
                parts.append("<?%s?>" % node.target)
            else:
                parts.append("<?%s %s?>" % (node.target, node.data))
            return
        if not isinstance(node, Element):
            return
        if not node.content:
            parts.append("<%s%s/>" % (node.tag, attributes_text(node)))
            return
        parts.append("<%s%s>" % (node.tag, attributes_text(node)))
        for child in node.content:
            render_node(child)
        parts.append("</%s>" % node.tag)

    for node in nodes:
        render_node(node)
    return "".join(parts)


def render_pretty(nodes, indent=0):
    # indented rendering for the dump command, one element per line
    lines = []

    def walk(source, depth):
        spacing = "  " * depth
        for node in source:
            if isinstance(node, (Text, CharRef, EntityRef)):
                text = escape_text(node.text()).strip()
                if text:
                    lines.append(spacing + text)
                continue
            if isinstance(node, ProcessingInstruction):
                continue
            if not isinstance(node, Element):
                continue
            if not node.content:
                lines.append("%s<%s%s/>" % (spacing, node.tag, attributes_text(node)))
                continue
            lines.append("%s<%s%s>" % (spacing, node.tag, attributes_text(node)))
            walk(node.content, depth + 1)
            lines.append("%s</%s>" % (spacing, node.tag))

    walk(nodes, indent)
    return "\n".join(lines)


def flatten(nodes, prefix=""):
    # flatten a node tree into dotted key paths, used by the payload extractor
    # for UserData blobs whose shape depends on the provider
    flat = []
    for node in nodes:
        if not isinstance(node, Element):
            continue
        path = node.tag if not prefix else prefix + "." + node.tag
        attributes = dict((name, value_text(value)) for name, value in node.attributes)
        children = [child for child in node.content if isinstance(child, Element)]
        text = "".join(child.value for child in node.content if isinstance(child, Text)).strip()
        if not children:
            flat.append((path, text, attributes))
            continue
        flat.extend(flatten(children, path))
    return flat
