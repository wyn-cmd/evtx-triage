# A synthetic EVTX writer for the tests. It emits real chunk headers, real CRC32
# checksums, genuine template instances with substitution arrays, and inline name
# strings, so the parser can be exercised end to end without shipping anybody
# else's event logs. Names are written inline right after the element that first
# uses them, which is the layout real logs use, so the chunk string table stays
# empty and every reference is an inline offset.

import struct
import uuid
import zlib
from datetime import datetime

CHUNK_SIZE = 65536
FILE_HEADER_SIZE = 4096
CHUNK_HEADER_SIZE = 512
RECORD_MAGIC = 0x00002A2A
FRAGMENT_HEADER = bytes((0x0F, 0x01, 0x00, 0x00))
WINDOWS_EPOCH = datetime(1601, 1, 1)

TOKEN_OPEN_ELEMENT = 0x01
TOKEN_OPEN_ELEMENT_ATTRS = 0x41
TOKEN_CLOSE_START = 0x02
TOKEN_CLOSE_EMPTY = 0x03
TOKEN_CLOSE_ELEMENT = 0x04
TOKEN_VALUE = 0x05
TOKEN_ATTRIBUTE = 0x06
TOKEN_TEMPLATE_INSTANCE = 0x0C
TOKEN_SUBSTITUTION = 0x0D
TOKEN_CONDITIONAL = 0x0E

TYPE_IDS = {
    "null": 0x00,
    "wstring": 0x01,
    "string": 0x02,
    "int8": 0x03,
    "uint8": 0x04,
    "int16": 0x05,
    "uint16": 0x06,
    "int32": 0x07,
    "uint32": 0x08,
    "int64": 0x09,
    "uint64": 0x0A,
    "real32": 0x0B,
    "real64": 0x0C,
    "bool": 0x0D,
    "binary": 0x0E,
    "guid": 0x0F,
    "sizet": 0x10,
    "filetime": 0x11,
    "systime": 0x12,
    "sid": 0x13,
    "hex32": 0x14,
    "hex64": 0x15,
    "stringarray": 0x81,
}


def filetime_exact(value):
    # tick exact FILETIME, integer maths only so far away dates stay precise
    delta = value - WINDOWS_EPOCH
    return (delta.days * 86400 + delta.seconds) * 10000000 + delta.microseconds * 10


def utf16(text):
    return text.encode("utf-16-le")


def name_string(text):
    # the name string structure an inline name or table entry points at
    return struct.pack("<IHH", 0, 0x1234, len(text)) + utf16(text) + b"\x00\x00"


def sid_bytes(text):
    # revision, sub authority count, six byte authority, little endian sub arrays
    parts = text.split("-")
    if parts[0].upper() != "S":
        raise ValueError("not a sid: %s" % text)
    authorities = [int(item) for item in parts[3:]]
    out = struct.pack("<BB", int(parts[1]), len(authorities))
    out += int(parts[2]).to_bytes(6, "big")
    for value in authorities:
        out += struct.pack("<I", value)
    return out


def value_bytes(kind, value, literal=False):
    # payload for one value and its variant type id. Substitution values are raw
    # because the descriptor carries the length, literal tokens inside a template
    # carry their own length prefix.
    if kind == "wstring":
        body = utf16(value)
        # a literal holds the character count, an ANSI literal holds byte count
        return (struct.pack("<H", len(value)) + body if literal else body), TYPE_IDS[kind]
    if kind == "string":
        body = value.encode("utf-8")
        return (struct.pack("<H", len(body)) + body if literal else body), TYPE_IDS[kind]
    if kind == "stringarray":
        body = b"".join(utf16(item) + b"\x00\x00" for item in value)
        return (struct.pack("<H", len(body)) + body if literal else body), TYPE_IDS[kind]
    if kind == "binary":
        # a sized value holds the data alone, its length lives in the descriptor
        return (struct.pack("<I", len(value)) + value if literal else value), TYPE_IDS[kind]
    if kind in ("int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64", "sizet", "hex32", "hex64"):
        codes = {"int8": "b", "uint8": "B", "int16": "h", "uint16": "H", "int32": "i", "uint32": "I", "int64": "q", "uint64": "Q", "sizet": "Q", "hex32": "I", "hex64": "Q"}
        return struct.pack("<" + codes[kind], value), TYPE_IDS[kind]
    if kind == "real32":
        return struct.pack("<f", value), TYPE_IDS[kind]
    if kind == "real64":
        return struct.pack("<d", value), TYPE_IDS[kind]
    if kind == "bool":
        return struct.pack("<I", 1 if value else 0), TYPE_IDS[kind]
    if kind == "guid":
        return uuid.UUID(value).bytes_le, TYPE_IDS[kind]
    if kind == "filetime":
        return struct.pack("<Q", filetime_exact(value)), TYPE_IDS[kind]
    if kind == "systime":
        stamp = struct.pack("<8H", value.year, value.month, value.isoweekday() % 7, value.day, value.hour, value.minute, value.second, value.microsecond // 1000)
        return stamp, TYPE_IDS[kind]
    if kind == "sid":
        return sid_bytes(value), TYPE_IDS[kind]
    if kind == "null":
        return b"", TYPE_IDS[kind]
    raise ValueError("unknown value kind %s" % kind)


def literal_value(kind, value):
    # a Value token with an inline value, used for literals such as Data names
    payload, type_id = value_bytes(kind, value, literal=True)
    return bytes((TOKEN_VALUE, type_id)) + payload


def substitution(index, kind, conditional=False):
    token = TOKEN_CONDITIONAL if conditional else TOKEN_SUBSTITUTION
    return bytes((token,)) + struct.pack("<H", index) + bytes((TYPE_IDS[kind],))


class Stream:
    # binxml tokens written at a known chunk offset, so an inline name can point
    # at itself without a second pass
    def __init__(self, base):
        self.base = base
        self.parts = []

    def position(self):
        return self.base + sum(len(part) for part in self.parts)

    def add(self, data):
        self.parts.append(data)
        return self

    def patch(self, position, data):
        # rewrite reserved bytes once the layout is known
        target = position - self.base
        consumed = 0
        for index, part in enumerate(self.parts):
            if consumed <= target < consumed + len(part):
                inner = target - consumed
                self.parts[index] = part[:inner] + data + part[inner + len(data):]
                return self
            consumed += len(part)
        raise IndexError("patch outside the stream")

    def value(self, kind, value):
        return self.add(literal_value(kind, value))

    def attribute(self, name, value_bytes_):
        self.add(bytes((TOKEN_ATTRIBUTE,)))
        position = self.position()
        self.add(struct.pack("<I", 0))
        offset = self.position()
        self.add(name_string(name))
        self.patch(position, struct.pack("<I", offset))
        self.add(value_bytes_)
        return self

    def open(self, tag, attributes=()):
        # returns the position of the element size field for patching later
        token = TOKEN_OPEN_ELEMENT_ATTRS if attributes else TOKEN_OPEN_ELEMENT
        self.add(bytes((token,)))
        self.add(struct.pack("<H", 0xFFFF))
        size_position = self.position()
        self.add(struct.pack("<I", 0))
        name_position = self.position()
        self.add(struct.pack("<I", 0))
        name_offset = self.position()
        self.add(name_string(tag))
        self.patch(name_position, struct.pack("<I", name_offset))
        if attributes:
            list_position = self.position()
            self.add(struct.pack("<I", 0))
            start = self.position()
            for name, payload in attributes:
                self.attribute(name, payload)
            self.patch(list_position, struct.pack("<I", self.position() - start))
        return size_position

    def close(self, size_position, empty=False):
        self.add(bytes((TOKEN_CLOSE_EMPTY if empty else TOKEN_CLOSE_ELEMENT,)) if not empty else bytes((TOKEN_CLOSE_EMPTY,)))
        self.patch(size_position, struct.pack("<I", self.position() - size_position + 4))
        return self

    def bytes(self):
        return b"".join(self.parts)


class EvtxBuilder:
    # builds a complete evtx file, with as many chunks as asked for
    def __init__(self, chunks=1, template_id=0x11223344):
        self.chunk_count = chunks
        self.template_id = template_id
        self.events = []
        self.next_record_id = 1

    def add_event(self, event_id, payload=None, channel="Security", provider="Microsoft-Windows-Security-Auditing", computer="TESTHOST", timestamp=None, level=4, task=0, opcode=0, keywords=0x8020000000000000, user_id="S-1-5-18", record_id=None, guid="54849625-5478-4994-a5ba-3e3b0328c30d", template=True, payload_kind="EventData"):
        # payload is a mapping of name to (kind, value) so every type can be exercised
        self.events.append({
            "event_id": int(event_id),
            "payload": dict(payload or {}),
            "channel": channel,
            "provider": provider,
            "computer": computer,
            "timestamp": timestamp or datetime(2024, 5, 4, 12, 0, 0),
            "level": level,
            "task": task,
            "opcode": opcode,
            "keywords": keywords,
            "user_id": user_id,
            "record_id": self.next_record_id if record_id is None else record_id,
            "guid": guid,
            "template": template,
            "payload_kind": payload_kind,
        })
        self.next_record_id += 1
        return self.events[-1]

    def system_values(self, entry):
        # the substitutions the System section consumes, in template order
        return [
            ("wstring", entry["provider"]),
            ("guid", entry["guid"]),
            ("uint16", entry["event_id"]),
            ("uint8", 0),
            ("uint8", entry["level"]),
            ("uint16", entry["task"]),
            ("uint8", entry["opcode"]),
            ("hex64", entry["keywords"]),
            ("filetime", entry["timestamp"]),
            ("uint64", entry["record_id"]),
            ("wstring", entry["channel"]),
            ("wstring", entry["computer"]),
            ("sid", entry["user_id"]),
        ]

    def template_body(self, entry, base):
        # the token stream one event is described by, placeholders included
        stream = Stream(base)
        stream.add(FRAGMENT_HEADER)
        payload_keys = sorted(entry["payload"])
        data_children = []
        for offset, key in enumerate(payload_keys):
            kind = entry["payload"][key][0]
            data_children.append(("Data", (("Name", literal_value("wstring", key)),), (substitution(13 + offset, kind, kind == "null"),)))
        wrapper = "UserData" if entry["payload_kind"] == "UserData" else "EventData"

        def element(spec):
            tag, attributes, content = spec
            size_position = stream.open(tag, attributes)
            if content:
                stream.add(bytes((TOKEN_CLOSE_START,)))
                for item in content:
                    if isinstance(item, tuple):
                        element(item)
                    else:
                        stream.add(item)
                stream.close(size_position, empty=False)
            else:
                stream.close(size_position, empty=True)

        xmlns = literal_value("wstring", "http://schemas.microsoft.com/win/2004/08/events/event")
        specs = (
            "Event",
            (("xmlns", xmlns),),
            (
                ("System", (), (
                    ("Provider", (("Name", substitution(0, "wstring")), ("Guid", substitution(1, "guid"))), ()),
                    ("EventID", (("Qualifiers", literal_value("wstring", "")),), (substitution(2, "uint16"),)),
                    ("Version", (), (substitution(3, "uint8"),)),
                    ("Level", (), (substitution(4, "uint8"),)),
                    ("Task", (), (substitution(5, "uint16"),)),
                    ("Opcode", (), (substitution(6, "uint8"),)),
                    ("Keywords", (), (substitution(7, "hex64"),)),
                    ("TimeCreated", (("SystemTime", substitution(8, "filetime")),), ()),
                    ("EventRecordID", (), (substitution(9, "uint64"),)),
                    ("Channel", (), (substitution(10, "wstring"),)),
                    ("Computer", (), (substitution(11, "wstring"),)),
                    ("Security", (("UserID", substitution(12, "sid")),), ()),
                )),
                (wrapper, (), tuple(data_children)),
            ),
        )
        element(specs)
        return stream.bytes()

    def plain_body(self, entry, base):
        # a record with no template at all, every value written inline
        stream = Stream(base)
        size_position = stream.open("Event", (("xmlns", literal_value("wstring", "http://schemas.microsoft.com/win/2004/08/events/event")),))
        stream.add(bytes((TOKEN_CLOSE_START,)))
        system_size = stream.open("System")
        stream.add(bytes((TOKEN_CLOSE_START,)))
        channel_size = stream.open("Channel")
        stream.value("wstring", entry["channel"])
        stream.close(channel_size)
        computer_size = stream.open("Computer")
        stream.value("wstring", entry["computer"])
        stream.close(computer_size)
        stream.close(system_size)
        data_size = stream.open("EventData")
        stream.add(bytes((TOKEN_CLOSE_START,)))
        id_size = stream.open("Data", (("Name", literal_value("wstring", "EventID")),))
        stream.value("uint16", entry["event_id"])
        stream.close(id_size)
        for key, (kind, value) in sorted(entry["payload"].items()):
            wrapper_size = stream.open("Data", (("Name", literal_value("wstring", key)),))
            stream.value("wstring" if kind == "null" else kind, "" if kind == "null" else value)
            stream.close(wrapper_size)
        stream.close(data_size)
        stream.close(size_position)
        return stream.bytes()

    def record_bytes(self, entry, offset):
        # one record: header, payload, repeated size
        if entry["template"]:
            stream = Stream(offset + 24)
            stream.add(FRAGMENT_HEADER)
            stream.add(bytes((TOKEN_TEMPLATE_INSTANCE, 0x01)))
            stream.add(struct.pack("<I", self.template_id))
            definition_position = stream.position() + 4
            stream.add(struct.pack("<I", definition_position))
            # remember where this definition landed so the chunk template table
            # can point at it, which is what lets later records share it
            if not hasattr(self, "_pending_templates"):
                self._pending_templates = []
            self._pending_templates.append(definition_position)
            body = self.template_body(entry, definition_position + 24)
            # the template id occupies the first four bytes of the definition's
            # guid field, so the header is next_offset, id inside guid, length
            stream.add(struct.pack("<I", 0))
            stream.add(struct.pack("<I", self.template_id))
            stream.add(uuid.UUID(entry["guid"]).bytes_le[4:])
            stream.add(struct.pack("<I", len(body)))
            stream.add(body)
            values = self.system_values(entry) + [entry["payload"][key] for key in sorted(entry["payload"])]
            stream.add(struct.pack("<I", len(values)))
            for kind, value in values:
                payload, type_id = value_bytes(kind, value)
                stream.add(struct.pack("<H", len(payload)) + bytes((type_id, 0)))
            for kind, value in values:
                payload, _type_id = value_bytes(kind, value)
                stream.add(payload)
            payload_bytes = stream.bytes()
        else:
            payload_bytes = self.plain_body(entry, offset + 24)
        size = 24 + len(payload_bytes) + 4
        # records are padded to a four byte boundary, which is what lets a
        # damaged chunk be resynced by scanning on that stride
        padding = (-len(payload_bytes)) % 4
        payload_bytes = payload_bytes + b"\x00" * padding
        size = 24 + len(payload_bytes) + 4
        header = struct.pack("<II", RECORD_MAGIC, size)
        header += struct.pack("<Q", entry["record_id"]) + struct.pack("<Q", filetime_exact(entry["timestamp"]))
        return header + payload_bytes + struct.pack("<I", size)

    def build_chunk(self, entries):
        # header, records, slack. the trailing checksum covers header and data.
        body = bytearray()
        offset = CHUNK_HEADER_SIZE
        first_number = last_number = None
        self._pending_templates = []
        for entry in entries:
            record = self.record_bytes(entry, offset)
            if len(body) + len(record) > CHUNK_SIZE - CHUNK_HEADER_SIZE - 128:
                break
            body.extend(record)
            offset += len(record)
            if first_number is None:
                first_number = entry["record_id"]
            last_number = entry["record_id"]
        next_record_offset = CHUNK_HEADER_SIZE + len(body)
        header = bytearray(CHUNK_HEADER_SIZE)
        header[0:8] = b"ElfChnk\x00"
        struct.pack_into("<QQQQ", header, 0x08, first_number or 0, last_number or 0, first_number or 0, last_number or 0)
        struct.pack_into("<II", header, 0x28, 128, next_record_offset - 4 if body else 0)
        struct.pack_into("<I", header, 0x30, next_record_offset)
        # the template table lists where each inline definition lives, so it has
        # to be written before the header checksum is taken
        for index, template_offset in enumerate(self._pending_templates[:32]):
            struct.pack_into("<I", header, 0x180 + (index * 4), template_offset)
        struct.pack_into("<I", header, 0x34, zlib.crc32(bytes(body)) & 0xFFFFFFFF)
        struct.pack_into("<I", header, 0x7C, zlib.crc32(bytes(header[0x00:0x78]) + bytes(header[0x80:0x200])) & 0xFFFFFFFF)
        return bytes(header) + bytes(body) + b"\x00" * (CHUNK_SIZE - CHUNK_HEADER_SIZE - len(body))

    def build(self):
        # the file: header, then the chunks with the declared count and checksum
        count = max(1, self.chunk_count)
        per_chunk = max(1, -(-len(self.events) // count)) if self.events else 1
        groups = [self.events[index:index + per_chunk] for index in range(0, len(self.events), per_chunk)] or [[]]
        chunks = [self.build_chunk(group) for group in groups]
        header = bytearray(FILE_HEADER_SIZE)
        header[0:8] = b"ElfFile\x00"
        struct.pack_into("<QQQ", header, 0x08, 0, len(chunks) - 1, self.next_record_id)
        struct.pack_into("<I", header, 0x20, 128)
        struct.pack_into("<HH", header, 0x24, 1, 3)
        struct.pack_into("<H", header, 0x28, FILE_HEADER_SIZE)
        struct.pack_into("<H", header, 0x2A, len(chunks))
        struct.pack_into("<I", header, 0x78, 1)
        struct.pack_into("<I", header, 0x7C, zlib.crc32(bytes(header[0:0x78])) & 0xFFFFFFFF)
        return bytes(header) + b"".join(chunks)

    def write(self, path):
        with open(path, "wb") as handle:
            handle.write(self.build())
        return path
