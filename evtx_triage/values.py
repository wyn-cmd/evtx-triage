# Decoding of the EVTX variant value types. These are the leaves of a binary XML
# stream: an event carries its payload as substitution values that each declare a
# type, and this module turns those bytes into the text the event viewer shows.

import base64

from .errors import FormatError, ValueDecodeError
from .helpers import filetime_to_datetime, isoformat

# variant type identifiers from the EVTX binary XML specification
TYPE_NULL = 0x00
TYPE_WSTRING = 0x01
TYPE_ANSI_STRING = 0x02
TYPE_INT8 = 0x03
TYPE_UINT8 = 0x04
TYPE_INT16 = 0x05
TYPE_UINT16 = 0x06
TYPE_INT32 = 0x07
TYPE_UINT32 = 0x08
TYPE_INT64 = 0x09
TYPE_UINT64 = 0x0A
TYPE_REAL32 = 0x0B
TYPE_REAL64 = 0x0C
TYPE_BOOL = 0x0D
TYPE_BINARY = 0x0E
TYPE_GUID = 0x0F
TYPE_SIZET = 0x10
TYPE_FILETIME = 0x11
TYPE_SYSTEMTIME = 0x12
TYPE_SID = 0x13
TYPE_HEX32 = 0x14
TYPE_HEX64 = 0x15
TYPE_BINXML = 0x21
TYPE_WSTRING_ARRAY = 0x81

# the top bit of a type id marks an array of the base type
ARRAY_FLAG = 0x80

TYPE_NAMES = {
    TYPE_NULL: "Null",
    TYPE_WSTRING: "String",
    TYPE_ANSI_STRING: "AnsiString",
    TYPE_INT8: "Int8",
    TYPE_UINT8: "UInt8",
    TYPE_INT16: "Int16",
    TYPE_UINT16: "UInt16",
    TYPE_INT32: "Int32",
    TYPE_UINT32: "UInt32",
    TYPE_INT64: "Int64",
    TYPE_UINT64: "UInt64",
    TYPE_REAL32: "Real32",
    TYPE_REAL64: "Real64",
    TYPE_BOOL: "Bool",
    TYPE_BINARY: "Binary",
    TYPE_GUID: "Guid",
    TYPE_SIZET: "SizeT",
    TYPE_FILETIME: "FileTime",
    TYPE_SYSTEMTIME: "SysTime",
    TYPE_SID: "Sid",
    TYPE_HEX32: "HexInt32",
    TYPE_HEX64: "HexInt64",
    TYPE_BINXML: "BinXml",
    TYPE_WSTRING_ARRAY: "StringArray",
}

# fixed widths, used both for arrays and for walking past values
FIXED_WIDTHS = {
    TYPE_INT8: 1,
    TYPE_UINT8: 1,
    TYPE_INT16: 2,
    TYPE_UINT16: 2,
    TYPE_INT32: 4,
    TYPE_UINT32: 4,
    TYPE_INT64: 8,
    TYPE_UINT64: 8,
    TYPE_REAL32: 4,
    TYPE_REAL64: 8,
    TYPE_BOOL: 4,
    TYPE_GUID: 16,
    TYPE_SIZET: 8,
    TYPE_FILETIME: 8,
    TYPE_SYSTEMTIME: 16,
    TYPE_HEX32: 4,
    TYPE_HEX64: 8,
}

MAX_SID_SUB_AUTHORITIES = 15


def type_name(type_id):
    # name for a variant type, arrays and unknown identifiers included
    if type_id == TYPE_WSTRING_ARRAY:
        return TYPE_NAMES[TYPE_WSTRING_ARRAY]
    if type_id & ARRAY_FLAG:
        base = type_id & ~ARRAY_FLAG
        return "ArrayOf%s" % TYPE_NAMES.get(base, "0x%02x" % base)
    return TYPE_NAMES.get(type_id, "Unknown0x%02x" % type_id)


class Variant:
    # one decoded value: declared type, rendered text and byte length
    __slots__ = ("type_id", "kind", "text", "raw", "size", "number", "nested")

    def __init__(self, type_id, text, size, raw=b"", number=None, nested=None):
        self.type_id = type_id
        self.kind = type_name(type_id)
        self.text = text
        self.size = size
        self.raw = raw
        self.number = number
        # nested holds a parsed binary XML fragment when the type is BinXml
        self.nested = nested

    def __repr__(self):
        if len(self.text) > 60:
            return "Variant(%s, %r...)" % (self.kind, self.text[:60])
        return "Variant(%s, %r)" % (self.kind, self.text)

    def __str__(self):
        return self.text

    def as_int(self, default=None):
        # numeric view used by rules comparing EventID, Level and friends
        if self.number is not None:
            return int(self.number)
        try:
            return int(self.text.strip(), 0)
        except (ValueError, AttributeError):
            return default

    def is_null(self):
        return self.type_id == TYPE_NULL or self.text == ""

    def as_dict(self):
        return {"kind": self.kind, "type_id": self.type_id, "text": self.text, "size": self.size}


def null_variant():
    return Variant(TYPE_NULL, "", 0)


def decode_value(reader, offset, type_id, size=None, parser=None):
    # Decode one value. size is the byte length the substitution descriptor
    # declared, or None when the type itself fixes the width. parser is only used
    # for BinXml values, which contain a nested token stream.
    if type_id == TYPE_NULL:
        return null_variant()

    if type_id == TYPE_BINXML:
        return _decode_binxml(reader, offset, size, parser)

    if type_id == TYPE_WSTRING_ARRAY:
        return _decode_string_array(reader, offset, size)

    if type_id & ARRAY_FLAG and (type_id & ~ARRAY_FLAG) in FIXED_WIDTHS:
        return _decode_numeric_array(reader, offset, type_id & ~ARRAY_FLAG)

    if type_id == TYPE_WSTRING:
        if size is not None:
            chars = max(0, size // 2)
            text = reader.utf16(offset, chars, "wstring value")
            return Variant(type_id, text.rstrip("\x00"), size, raw=reader.raw(offset, size, "wstring value"))
        chars = reader.u16(offset)
        text = reader.utf16(offset + 2, chars, "wstring value")
        return Variant(type_id, text.rstrip("\x00"), 2 + chars * 2)

    if type_id == TYPE_ANSI_STRING:
        if size is not None:
            text = reader.ansi(offset, size, "ansi value")
            return Variant(type_id, text.rstrip("\x00"), size, raw=reader.raw(offset, size, "ansi value"))
        length = reader.u16(offset)
        text = reader.ansi(offset + 2, length, "ansi value")
        return Variant(type_id, text.rstrip("\x00"), 2 + length)

    if type_id == TYPE_BINARY:
        if size is not None:
            blob = reader.raw(offset, size, "binary value")
            return Variant(type_id, base64.b64encode(blob).decode("ascii"), size, raw=blob)
        length = reader.u32(offset)
        blob = reader.raw(offset + 4, length, "binary value")
        return Variant(type_id, base64.b64encode(blob).decode("ascii"), 4 + length, raw=blob)

    if type_id == TYPE_SID:
        return _decode_sid(reader, offset)

    if type_id == TYPE_SIZET:
        if size == 4:
            value = reader.u32(offset)
            return Variant(type_id, str(value), 4, number=value)
        value = reader.u64(offset)
        return Variant(type_id, str(value), 8, number=value)

    if type_id == TYPE_GUID:
        return Variant(type_id, "{" + reader.guid(offset) + "}", 16)

    if type_id == TYPE_FILETIME:
        raw = reader.u64(offset)
        moment = filetime_to_datetime(raw)
        if moment is None:
            return Variant(type_id, "1601-01-01 00:00:00", 8, number=raw)
        return Variant(type_id, isoformat(moment), 8, number=raw)

    if type_id == TYPE_SYSTEMTIME:
        return _decode_systemtime(reader, offset)

    if type_id == TYPE_HEX32:
        # the stored bytes are little endian, and the value is displayed as the
        # number they encode, zero padded to the full width of the type
        value = reader.u32(offset)
        return Variant(type_id, "0x%08x" % value, 4, number=value)
    if type_id == TYPE_HEX64:
        value = reader.u64(offset)
        return Variant(type_id, "0x%016x" % value, 8, number=value)

    width = FIXED_WIDTHS.get(type_id)
    if width is None:
        raise ValueDecodeError("no decoder for variant type 0x%02x" % type_id, offset=reader.offset_of(offset), source=reader.source)

    if type_id == TYPE_INT8:
        value = reader.i8(offset)
    elif type_id == TYPE_UINT8:
        value = reader.u8(offset)
    elif type_id == TYPE_INT16:
        value = reader.i16(offset)
    elif type_id == TYPE_UINT16:
        value = reader.u16(offset)
    elif type_id == TYPE_INT32:
        value = reader.i32(offset)
    elif type_id == TYPE_UINT32:
        value = reader.u32(offset)
    elif type_id == TYPE_INT64:
        value = reader.i64(offset)
    elif type_id == TYPE_UINT64:
        value = reader.u64(offset)
    elif type_id == TYPE_REAL32:
        value = reader.f32(offset)
    elif type_id == TYPE_REAL64:
        value = reader.f64(offset)
    else:
        # the only remaining fixed width type is the boolean
        raw = reader.i32(offset)
        return Variant(type_id, "True" if raw else "False", 4, number=1 if raw else 0)
    return Variant(type_id, str(value), width, number=value)


def _decode_binxml(reader, offset, size, parser):
    # a BinXml value holds its own token stream, so it needs the parser to turn
    # it into nodes and text
    if size is None:
        size = max(0, len(reader) - offset)
    if parser is None:
        return Variant(TYPE_BINXML, "", size, raw=reader.raw(offset, size, "binxml value"))
    nodes = parser.parse_fragment(offset, offset + size)
    consumed = max(0, parser.last_end - offset)
    return Variant(TYPE_BINXML, parser.render_xml(nodes), consumed, nested=nodes)


def _decode_systemtime(reader, offset):
    # eight little endian shorts: year, month, day of week, day, hour, minute,
    # second, millisecond
    year = reader.u16(offset)
    month = reader.u16(offset + 2)
    day = reader.u16(offset + 6)
    hour = reader.u16(offset + 8)
    minute = reader.u16(offset + 10)
    second = reader.u16(offset + 12)
    millis = reader.u16(offset + 14)
    if year == 0:
        return Variant(TYPE_SYSTEMTIME, "", 16)
    text = "%04d-%02d-%02d %02d:%02d:%02d" % (year, month, day, hour, minute, second)
    if millis:
        text += ".%06d" % (millis * 1000)
    return Variant(TYPE_SYSTEMTIME, text, 16)


def _decode_sid(reader, offset):
    # revision, sub authority count, six byte big endian authority, then the
    # little endian sub authorities
    revision = reader.u8(offset)
    count = reader.u8(offset + 1)
    if count > MAX_SID_SUB_AUTHORITIES:
        raise FormatError(
            "SID with %d sub authorities is out of range" % count,
            offset=reader.offset_of(offset),
            source=reader.source,
        )
    authority = int.from_bytes(reader.raw(offset + 2, 6, "sid authority"), "big")
    parts = ["S-%d-%d" % (revision, authority)]
    position = offset + 8
    for _ in range(count):
        parts.append(str(reader.u32(position)))
        position += 4
    return Variant(TYPE_SID, "-".join(parts), 8 + 4 * count)


def _decode_numeric_array(reader, offset, base_type):
    # an array of a fixed width type is a u16 count followed by the elements
    count = reader.u16(offset)
    width = FIXED_WIDTHS[base_type]
    position = offset + 2
    texts = []
    for _ in range(count):
        texts.append(decode_value(reader, position, base_type).text)
        position += width
    return Variant(base_type | ARRAY_FLAG, "; ".join(texts), position - offset)


def _decode_string_array(reader, offset, size):
    # a string array is a length prefix then NUL separated UTF-16 strings, shown
    # one <string> fragment per entry
    if size is not None:
        blob = reader.raw(offset, size, "string array")
        consumed = size
    else:
        length = reader.u16(offset)
        blob = reader.raw(offset + 2, length, "string array")
        consumed = 2 + length
    parts = []
    current = bytearray()
    for index in range(0, len(blob) - 1, 2):
        pair = blob[index:index + 2]
        if pair == b"\x00\x00":
            # a NUL pair closes one entry, and an empty entry is still an entry
            parts.append(current.decode("utf-16-le", errors="replace"))
            current = bytearray()
            continue
        current += pair
    if current:
        parts.append(current.decode("utf-16-le", errors="replace"))
    # the array is NUL terminated, so only the trailing empty entry goes
    while parts and parts[-1] == "":
        parts.pop()
    text = "".join("<string>%s</string>\n" % item for item in parts)
    return Variant(TYPE_WSTRING_ARRAY, text, consumed)
