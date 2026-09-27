# The binary XML decoder: the token grammar that fills a record, the template
# instances it points at, and the substitution values that complete them. A
# template body is parsed once per chunk and cached, then bound per instance,
# which is what keeps a log with tens of thousands of records cheap to read.

from .chunk import CHUNK_SIZE
from .errors import BinXmlError, FormatError, TruncatedError
from .nodes import (
    CharRef,
    Element,
    EntityRef,
    Placeholder,
    ProcessingInstruction,
    TemplateBody,
    Text,
    bind,
)
from .render import render_pretty, render_xml
from .values import TYPE_NULL, decode_value, null_variant

# token identifiers, the low nibble of the token byte
TOKEN_EOF = 0x00
TOKEN_OPEN_START_ELEMENT = 0x01
TOKEN_CLOSE_START_ELEMENT = 0x02
TOKEN_CLOSE_EMPTY_ELEMENT = 0x03
TOKEN_CLOSE_ELEMENT = 0x04
TOKEN_VALUE = 0x05
TOKEN_ATTRIBUTE = 0x06
TOKEN_CDATA = 0x07
TOKEN_CHAR_REF = 0x08
TOKEN_ENTITY_REF = 0x09
TOKEN_PI_TARGET = 0x0A
TOKEN_PI_DATA = 0x0B
TOKEN_TEMPLATE_INSTANCE = 0x0C
TOKEN_SUBSTITUTION = 0x0D
TOKEN_CONDITIONAL_SUBSTITUTION = 0x0E
TOKEN_FRAGMENT_HEADER = 0x0F

# high nibble flag on an open start element, meaning it carries attributes
FLAG_HAS_ATTRIBUTES = 0x40

TOKEN_NAMES = (
    "end of stream",
    "open start element",
    "close start element",
    "close empty element",
    "close element",
    "value",
    "attribute",
    "cdata",
    "character reference",
    "entity reference",
    "processing instruction target",
    "processing instruction data",
    "template instance",
    "substitution",
    "conditional substitution",
    "fragment header",
)

# limits that stop a corrupted stream from being walked forever
MAX_DEPTH = 64
MAX_TOKENS_PER_FRAGMENT = 400000
MAX_SUBSTITUTIONS = 4096
DEPENDENCY_TEMPLATE = 0xFFFF


def token_name(token):
    low = token & 0x0F
    if low < len(TOKEN_NAMES):
        return TOKEN_NAMES[low]
    return "unknown 0x%02x" % token


class BxmlParser:
    # One parser per chunk. Offsets here are chunk relative, which is what the
    # string and template references in the stream use, and the record span is
    # handed in so the walk can never leave the record it belongs to.
    def __init__(self, chunk, source=None, limit=None, recover=True):
        self.chunk = chunk
        self.reader = chunk.reader
        self.source = source or (chunk.source or "chunk %d" % chunk.index)
        self.limit = limit if limit is not None else CHUNK_SIZE
        self.recover = recover
        self.last_end = 0
        self.templates = {}
        self.template_ids = {}
        self.template_errors = []
        self._parsing = set()
        self.stats = {
            "records_parsed": 0,
            "records_damaged": 0,
            "templates_parsed": 0,
            "template_instances": 0,
            "substitutions": 0,
            "max_depth": 0,
        }

    def render_xml(self, nodes, pretty=False):
        if pretty:
            return render_pretty(nodes)
        return render_xml(nodes)

    def error(self, message, offset):
        return BinXmlError(message, offset=self.chunk.offset_of(offset), source=self.source)

    def parse_record(self, record):
        # returns (nodes, problem). A damaged record yields whatever was walked
        # before the failure plus a reason, unless recovery is switched off.
        start = record.bxml_offset()
        end = record.bxml_end()
        self.last_end = start
        if end - start < 4:
            return [], "payload of %d bytes is too small to hold a token stream" % (end - start)
        self.limit = min(end, CHUNK_SIZE)
        try:
            nodes, cursor = self._stream(start, self.limit, 0)
        except (FormatError, TruncatedError, BinXmlError) as problem:
            self.stats["records_damaged"] += 1
            if not self.recover:
                raise
            return [], str(problem)
        self.last_end = cursor
        self.stats["records_parsed"] += 1
        return nodes, None

    def parse_fragment(self, offset, end=None):
        # walk one token stream; a fragment normally starts with a four byte
        # header and then a template instance, but plain elements are legal too
        if end is None:
            end = self.limit
        end = min(end, self.limit)
        nodes, cursor = self._stream(offset, end, 0)
        self.last_end = cursor
        return nodes

    def parse_template_table(self):
        # parse every template the chunk advertises, which warms the cache and
        # surfaces damaged templates during verification instead of mid report
        for template_offset in self.chunk.template_table_offsets():
            try:
                self.template(template_offset)
            except (FormatError, TruncatedError, BinXmlError) as problem:
                self.template_errors.append({"offset": template_offset, "reason": str(problem)})
        return len(self.templates)

    def template(self, template_offset):
        # a template body, parsed once and reused by every instance
        if template_offset in self.templates:
            return self.templates[template_offset]
        if template_offset in self._parsing:
            raise self.error("template at 0x%x refers to itself" % template_offset, template_offset)
        definition = self.chunk.template(template_offset)
        self._parsing.add(template_offset)
        try:
            body_start = definition.data_offset
            body_end = min(definition.data_offset + definition.data_length, CHUNK_SIZE)
            nodes, _ = self._stream(body_start, body_end, 0)
        finally:
            self._parsing.discard(template_offset)
        body = TemplateBody(definition.offset, definition.template_id, definition.guid, definition.data_length, nodes)
        self.templates[template_offset] = body
        self.template_ids[definition.template_id] = body
        self.stats["templates_parsed"] += 1
        return body

    def _stream(self, offset, end, depth):
        # walk tokens until the end of the span, the end of the stream, or the
        # token that closes the enclosing element. Returns (nodes, cursor).
        if depth > MAX_DEPTH:
            raise self.error("token nesting deeper than %d levels" % MAX_DEPTH, offset)
        nodes = []
        tokens = 0
        while offset < end:
            tokens += 1
            if tokens > MAX_TOKENS_PER_FRAGMENT:
                raise self.error("token stream did not end after %d tokens" % MAX_TOKENS_PER_FRAGMENT, offset)
            token = self.reader.u8(offset)
            low = token & 0x0F
            if low == TOKEN_EOF:
                return nodes, offset + 1
            if low == TOKEN_FRAGMENT_HEADER:
                offset += 4
                continue
            if low == TOKEN_OPEN_START_ELEMENT:
                element, offset = self._element(offset, end, depth)
                if element is not None:
                    nodes.append(element)
                continue
            if low == TOKEN_CLOSE_START_ELEMENT:
                offset += 1
                continue
            if low in (TOKEN_CLOSE_EMPTY_ELEMENT, TOKEN_CLOSE_ELEMENT):
                # the caller consumes the closing token so that one close marker
                # can never be swallowed twice and shift every sibling after it
                return nodes, offset
            if low == TOKEN_VALUE:
                value, offset = self._value(offset, end, depth, as_text=True)
                if isinstance(value, list):
                    nodes.extend(value)
                elif value is not None:
                    nodes.append(value)
                continue
            if low in (TOKEN_SUBSTITUTION, TOKEN_CONDITIONAL_SUBSTITUTION):
                nodes.append(self._substitution(offset))
                offset += 4
                continue
            if low == TOKEN_TEMPLATE_INSTANCE:
                produced, offset = self._template_instance(offset, depth)
                nodes.extend(produced)
                continue
            if low == TOKEN_ATTRIBUTE:
                # an attribute outside an element is malformed, but stepping over
                # it keeps the rest of the fragment readable
                _, offset = self._attribute(offset, end, depth)
                continue
            if low == TOKEN_CDATA:
                text, offset = self._cdata(offset, end)
                nodes.append(Text(text))
                continue
            if low == TOKEN_CHAR_REF:
                nodes.append(CharRef(chr(self.reader.u16(offset + 1))))
                offset += 3
                continue
            if low == TOKEN_ENTITY_REF:
                name, offset = self._named_string(offset, 5)
                nodes.append(EntityRef(name))
                continue
            if low == TOKEN_PI_TARGET:
                target, offset = self._named_string(offset, 5)
                nodes.append(ProcessingInstruction(target, "", "target"))
                continue
            if low == TOKEN_PI_DATA:
                length = self.reader.u16(offset + 1)
                text = self.reader.utf16(offset + 3, max(0, length // 2), "pi data")
                nodes.append(ProcessingInstruction("", text, "data"))
                offset += 3 + length
                continue
            raise self.error("unknown token 0x%02x (%s)" % (token, token_name(token)), offset)
        return nodes, offset

    def _element(self, offset, end, depth):
        # header: token, dependency id, declared size, name offset, and an
        # attribute list size when the attribute flag is set
        token = self.reader.u8(offset)
        cursor = offset + 1
        dependency_id = self.reader.u16(cursor)
        cursor += 2
        self.reader.u32(cursor)
        cursor += 4
        name_offset = self.reader.u32(cursor)
        cursor += 4
        # A name stored past the element lives inline right after the fixed part
        # of the header and before the attribute list size, which is the order
        # real logs use and the order walked here.
        tag = self._name(name_offset, offset)
        if name_offset > offset:
            cursor += self.chunk.string_length(name_offset)
        has_attributes = bool(token & FLAG_HAS_ATTRIBUTES)
        if has_attributes:
            cursor += 4
        attributes = []
        while cursor + 4 <= end and (self.reader.u8(cursor) & 0x0F) == TOKEN_ATTRIBUTE:
            pair, cursor = self._attribute(cursor, end, depth)
            if pair is not None:
                attributes.append(pair)
        empty = False
        if cursor < end:
            marker = self.reader.u8(cursor) & 0x0F
            if marker == TOKEN_CLOSE_START_ELEMENT:
                cursor += 1
            elif marker == TOKEN_CLOSE_EMPTY_ELEMENT:
                cursor += 1
                empty = True
        if empty:
            return Element(tag, attributes, [], origin="stream"), cursor
        content, cursor = self._stream(cursor, end, depth + 1)
        if cursor < end:
            marker = self.reader.u8(cursor) & 0x0F
            if marker in (TOKEN_CLOSE_ELEMENT, TOKEN_CLOSE_EMPTY_ELEMENT):
                cursor += 1
        return Element(tag, attributes, content, origin="stream"), cursor

    def _name(self, name_offset, offset):
        # A name stored past the structure that references it lives inline and is
        # stepped over separately; a shared name sits in the string table below
        # the record area, so its offset is always lower than the reference.
        if not name_offset:
            return "?"
        try:
            return self.chunk.string(name_offset)
        except (FormatError, TruncatedError):
            return "?"

    def _attribute(self, offset, end, depth):
        # token, name offset, then the value token
        cursor = offset + 1
        name_offset = self.reader.u32(cursor)
        cursor += 4
        name = self._name(name_offset, offset)
        if name_offset > offset:
            cursor += self.chunk.string_length(name_offset)
        value, cursor = self._value(cursor, end, depth)
        return [name, value], cursor

    def _content_node(self, variant):
        # a literal inside element content becomes text, but a BinXml literal
        # carries a subtree that has to be spliced in where it stands
        if variant.nested:
            return list(variant.nested)
        return Text(variant.text)

    def _value(self, offset, end, depth, as_text=False):
        # the value of an attribute or an element is always a token
        if offset >= end:
            return None, offset
        token = self.reader.u8(offset)
        low = token & 0x0F
        if low == TOKEN_VALUE:
            type_id = self.reader.u8(offset + 1)
            variant = decode_value(self.reader, offset + 2, type_id, None, self)
            cursor = offset + 2 + max(0, variant.size)
            if as_text:
                return self._content_node(variant), cursor
            return variant, cursor
        if low in (TOKEN_SUBSTITUTION, TOKEN_CONDITIONAL_SUBSTITUTION):
            return self._substitution(offset), offset + 4
        if low == TOKEN_TEMPLATE_INSTANCE:
            produced, cursor = self._template_instance(offset, depth)
            return produced, cursor
        if low == TOKEN_OPEN_START_ELEMENT:
            return self._element(offset, end, depth)
        if low == TOKEN_CDATA:
            text, cursor = self._cdata(offset, end)
            return Text(text), cursor
        if low == TOKEN_CHAR_REF:
            return CharRef(chr(self.reader.u16(offset + 1))), offset + 3
        if low == TOKEN_ENTITY_REF:
            name, cursor = self._named_string(offset, 5)
            return EntityRef(name), cursor
        raise self.error("token %s is not valid where a value was expected" % token_name(token), offset)

    def _substitution(self, offset):
        # a substitution slot, filled when the enclosing template binds
        token = self.reader.u8(offset)
        index = self.reader.u16(offset + 1)
        type_id = self.reader.u8(offset + 3)
        return Placeholder(index, type_id, (token & 0x0F) == TOKEN_CONDITIONAL_SUBSTITUTION)

    def _cdata(self, offset, end):
        # u16 length covering the UTF-16 payload and its terminator
        length = self.reader.u16(offset + 1)
        chars = max(0, (length - 2) // 2)
        text = self.reader.utf16(offset + 3, chars, "cdata section")
        cursor = offset + 3 + length
        if cursor > end:
            cursor = end
        return text, cursor

    def _named_string(self, offset, header_size):
        # entity names and instruction targets are stored like attribute names
        name_offset = self.reader.u32(offset + 1)
        cursor = offset + header_size
        name = self._name(name_offset, offset)
        if name_offset > offset:
            cursor += self.chunk.string_length(name_offset)
        return name, cursor

    def _template_instance(self, offset, depth):
        # token, version byte, template id, offset of the template definition
        if depth + 1 > MAX_DEPTH:
            raise self.error("template nesting deeper than %d levels" % MAX_DEPTH, offset)
        self.reader.u8(offset + 1)
        template_id = self.reader.u32(offset + 2)
        template_offset = self.reader.u32(offset + 6)
        cursor = offset + 10
        body = None
        if template_offset:
            body = self.template(template_offset)
        if template_offset > offset and body is not None:
            # the definition is resident, stored right after the instance header
            cursor = max(cursor, body.offset + 24 + body.data_length)
        count = self.reader.u32(cursor)
        cursor += 4
        if count > MAX_SUBSTITUTIONS:
            raise self.error("template instance declares %d substitutions" % count, cursor)
        descriptors = []
        for _ in range(count):
            size = self.reader.u16(cursor)
            type_id = self.reader.u8(cursor + 2)
            descriptors.append((size, type_id))
            cursor += 4
        values = []
        for size, type_id in descriptors:
            if type_id == TYPE_NULL and size == 0:
                values.append(null_variant())
                continue
            variant = decode_value(self.reader, cursor, type_id, size, self)
            values.append(variant)
            # the descriptor size is authoritative, but a zero size means the
            # value carries its own length, and an empty string really does take
            # no room, so the cursor follows what the decoder consumed
            step = size if size > 0 else variant.size
            cursor += step
        self.stats["template_instances"] += 1
        self.stats["substitutions"] += len(values)
        self.stats["max_depth"] = max(self.stats["max_depth"], depth + 1)
        if body is None:
            return [], cursor
        bound = bind(body.nodes, values)
        return bound.nodes, cursor

    def describe(self):
        return {
            "templates_cached": len(self.templates),
            "template_errors": len(self.template_errors),
            "stats": dict(self.stats),
        }
