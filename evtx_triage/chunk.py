# The 64 KB chunk: a 512 byte header, the string table and template table it
# points at, and the event records that follow. This module also carries the
# damage handling, because a chunk is the unit that survives corruption: when a
# record header is unreadable the rest of the chunk is still worth reading.

from .errors import FormatError, TruncatedError
from .helpers import filetime_to_datetime
from .reader import Reader

CHUNK_SIZE = 65536
CHUNK_HEADER_SIZE = 512
CHUNK_MAGIC = b"ElfChnk\x00"
CHUNK_RECORDS_OFFSET = 0x200
STRING_TABLE_OFFSET = 0x80
STRING_TABLE_ENTRIES = 64
TEMPLATE_TABLE_OFFSET = 0x180
TEMPLATE_TABLE_ENTRIES = 32
RECORD_MAGIC = 0x00002a2a
RECORD_HEADER_SIZE = 0x18
MIN_RECORD_SIZE = 0x1C
SIGNATURE_SCAN_STEP = 2


class ChunkHeader:
    # layout, all little endian:
    #   0x00 magic 8 bytes, 0x08 file_first_record_number u64, 0x10 file_last u64,
    #   0x18 log_first_record_number u64, 0x20 log_last u64, 0x28 header_size u32,
    #   0x2C last_record_offset u32, 0x30 next_record_offset u32, 0x34 data_checksum u32,
    #   0x38 unused 68 bytes, 0x7C header_checksum u32
    def __init__(self, reader):
        self.reader = reader
        self.magic = bytes(reader.raw(0x00, 8, "chunk signature"))
        self.file_first_record_number = reader.u64(0x08)
        self.file_last_record_number = reader.u64(0x10)
        self.log_first_record_number = reader.u64(0x18)
        self.log_last_record_number = reader.u64(0x20)
        self.header_size = reader.u32(0x28)
        self.last_record_offset = reader.u32(0x2C)
        self.next_record_offset = reader.u32(0x30)
        self.data_checksum = reader.u32(0x34)
        self.header_checksum = reader.u32(0x7C)

    def signature_ok(self):
        return self.magic == CHUNK_MAGIC

    def validate(self):
        if not self.signature_ok():
            raise FormatError("chunk signature is %r, expected ElfChnk" % (self.magic,), offset=0, source=self.reader.source)

    def record_area_valid(self):
        # the used record area must start at the fixed offset and stay in bounds
        return CHUNK_RECORDS_OFFSET <= self.next_record_offset <= CHUNK_SIZE

    def verify_header_checksum(self):
        # covers 0x00..0x78 and 0x80..0x200, deliberately skipping 0x78..0x80.
        # The region was confirmed against real logs: including the template
        # table is what makes the stored checksum match.
        computed = self.reader.crc32_parts([(0x00, 0x78), (STRING_TABLE_OFFSET, 0x180)])
        return computed == self.header_checksum, computed

    def verify_data_checksum(self):
        # covers the used part of the record area only
        if not self.record_area_valid():
            return False, None
        size = self.next_record_offset - CHUNK_RECORDS_OFFSET
        computed = self.reader.crc32(CHUNK_RECORDS_OFFSET, size, "chunk data checksum")
        return computed == self.data_checksum, computed

    def is_empty(self):
        return (not self.record_area_valid()) or self.next_record_offset <= CHUNK_RECORDS_OFFSET

    def record_count_hint(self):
        if self.log_first_record_number and self.log_last_record_number >= self.log_first_record_number:
            return self.log_last_record_number - self.log_first_record_number + 1
        return 0

    def describe(self):
        header_ok, header_computed = self.verify_header_checksum()
        data_ok, data_computed = self.verify_data_checksum()
        return {
            "signature_ok": self.signature_ok(),
            "header_size": self.header_size,
            "file_first_record_number": self.file_first_record_number,
            "file_last_record_number": self.file_last_record_number,
            "log_first_record_number": self.log_first_record_number,
            "log_last_record_number": self.log_last_record_number,
            "last_record_offset": self.last_record_offset,
            "next_record_offset": self.next_record_offset,
            "empty": self.is_empty(),
            "header_checksum_ok": header_ok,
            "header_checksum_computed": header_computed,
            "data_checksum_ok": data_ok,
            "data_checksum_computed": data_computed,
        }


class Record:
    # one event record: a 24 byte header, the binary XML payload, then a copy of
    # the size in the final four bytes as a consistency check
    def __init__(self, reader, offset):
        self.reader = reader
        self.offset = offset
        self.absolute_offset = reader.offset_of(offset)
        self.magic = reader.u32(offset)
        self.size = reader.u32(offset + 0x04)
        self.record_id = reader.u64(offset + 0x08)
        self.written_time = reader.u64(offset + 0x10)
        self.written_datetime = filetime_to_datetime(self.written_time)
        self.damaged = False
        self.damage_reason = None
        self.verify()

    def __repr__(self):
        return "Record(id=%s, offset=0x%x, size=%d%s)" % (self.record_id, self.offset, self.size, ", damaged" if self.damaged else "")

    def mark(self, reason):
        # first reason wins, so the most fundamental problem is the one reported
        self.damaged = True
        if self.damage_reason is None:
            self.damage_reason = reason

    def verify(self):
        if self.magic != RECORD_MAGIC:
            self.mark("record signature 0x%08x is not 0x00002a2a" % self.magic)
            return
        if self.size < MIN_RECORD_SIZE:
            self.mark("record size %d is below the %d byte minimum" % (self.size, MIN_RECORD_SIZE))
            return
        if self.offset + self.size > len(self.reader):
            self.mark("record size %d runs past the end of the chunk" % self.size)
            return
        trailing = self.reader.u32(self.offset + self.size - 4)
        if trailing != self.size:
            self.mark("trailing size %d does not match header size %d" % (trailing, self.size))

    def end(self):
        return self.offset + self.size

    def payload_available(self):
        # the payload is everything between the header and the trailing size copy
        return self.size >= MIN_RECORD_SIZE and self.offset + self.size <= len(self.reader)

    def bxml_offset(self):
        return self.offset + RECORD_HEADER_SIZE

    def bxml_end(self):
        return self.offset + self.size - 4

    def payload(self):
        # raw binary XML bytes of this record
        if not self.payload_available():
            return b""
        return bytes(self.reader.raw(self.bxml_offset(), self.bxml_end() - self.bxml_offset(), "record payload"))

    def payload_reader(self):
        # a reader whose offsets are absolute file offsets, for error messages
        return Reader(
            self.reader.data,
            base=self.reader.base,
            source="%s record %s" % (self.reader.source or "chunk", self.record_id),
        )

    def as_dict(self):
        return {
            "record_id": self.record_id,
            "offset": self.offset,
            "absolute_offset": self.absolute_offset,
            "size": self.size,
            "written_time": self.written_time,
            "written_datetime": self.written_datetime,
            "damaged": self.damaged,
            "damage_reason": self.damage_reason,
        }


class Chunk:
    # one 64 KB chunk plus its caches; string and template lookups are cached
    # because records in the same chunk point at the same shared structures
    def __init__(self, data, index=0, file_offset=0, source=None):
        if len(data) < CHUNK_SIZE:
            raise TruncatedError(
                "chunk %d needs %d bytes but only %d are available" % (index, CHUNK_SIZE, len(data)),
                offset=file_offset,
                source=source,
            )
        self.data = data
        self.index = index
        self.file_offset = file_offset
        self.source = source
        self.reader = Reader(data, base=file_offset, source=source)
        self.header = ChunkHeader(self.reader)
        self.damage = []
        self.recovered_bytes = 0
        self._strings = {}
        self._templates = {}

    def __repr__(self):
        return "Chunk(index=%d, records=%d, damaged=%d)" % (self.index, self.record_count(), len(self.damage))

    def offset_of(self, chunk_offset):
        return self.file_offset + chunk_offset

    def string_table_offsets(self):
        # the 64 u32 entries at 0x80, zero means the slot is unused
        offsets = []
        for slot in range(STRING_TABLE_ENTRIES):
            value = self.reader.u32(STRING_TABLE_OFFSET + slot * 4)
            if value:
                offsets.append(value)
        return offsets

    def template_table_offsets(self):
        # the 32 u32 entries at 0x180, zero means the slot is unused
        offsets = []
        for slot in range(TEMPLATE_TABLE_ENTRIES):
            value = self.reader.u32(TEMPLATE_TABLE_OFFSET + slot * 4)
            if value:
                offsets.append(value)
        return offsets

    def string(self, chunk_offset):
        # a name in the chunk string table: u32 next offset, u16 hash, u16 length
        # in UTF-16 code units, then the characters and a terminator
        if chunk_offset in self._strings:
            return self._strings[chunk_offset]
        if chunk_offset < CHUNK_HEADER_SIZE or chunk_offset + 8 > CHUNK_SIZE:
            raise FormatError("string offset 0x%x is outside the chunk" % chunk_offset, offset=self.offset_of(chunk_offset), source=self.source)
        length = self.reader.u16(chunk_offset + 0x06)
        if chunk_offset + 8 + length * 2 > CHUNK_SIZE:
            raise FormatError("string at 0x%x declares %d characters that do not fit" % (chunk_offset, length), offset=self.offset_of(chunk_offset), source=self.source)
        text = self.reader.utf16(chunk_offset + 0x08, length, "chunk string")
        self._strings[chunk_offset] = text
        return text

    def string_length(self, chunk_offset):
        # byte length of a name structure, used to skip inline names in the stream
        if chunk_offset < CHUNK_HEADER_SIZE or chunk_offset + 8 > CHUNK_SIZE:
            return 0
        return 2 * self.reader.u16(chunk_offset + 0x06) + 10

    def template(self, chunk_offset):
        # an inline template definition: u32 next offset, u32 template id,
        # 16 byte guid, u32 data length at 0x14, then the binary XML body
        if chunk_offset in self._templates:
            return self._templates[chunk_offset]
        if chunk_offset < CHUNK_HEADER_SIZE or chunk_offset + 24 > CHUNK_SIZE:
            raise FormatError("template offset 0x%x is outside the chunk" % chunk_offset, offset=self.offset_of(chunk_offset), source=self.source)
        reading = self.reader
        definition = TemplateDefinition(
            offset=chunk_offset,
            next_offset=reading.u32(chunk_offset),
            template_id=reading.u32(chunk_offset + 0x04),
            guid=reading.guid(chunk_offset + 0x04),
            data_length=reading.u32(chunk_offset + 0x14),
            data_offset=chunk_offset + 0x18,
        )
        if definition.data_offset + definition.data_length > CHUNK_SIZE:
            raise FormatError(
                "template at 0x%x declares %d bytes of body that do not fit in the chunk" % (chunk_offset, definition.data_length),
                offset=self.offset_of(chunk_offset),
                source=self.source,
            )
        self._templates[chunk_offset] = definition
        return definition

    def record_area(self):
        # the byte span between the fixed start and the write pointer
        if not self.header.record_area_valid():
            return (CHUNK_RECORDS_OFFSET, CHUNK_RECORDS_OFFSET)
        return (CHUNK_RECORDS_OFFSET, self.header.next_record_offset)

    def slack_bytes(self):
        start, end = self.record_area()
        return max(0, CHUNK_SIZE - end)

    def waste_bytes(self):
        # slack plus whatever the recovery scan skipped, reported as dead space
        return self.slack_bytes() + self.recovered_bytes

    def record_count(self):
        if self.header.is_empty():
            return 0
        start, end = self.record_area()
        count = 0
        position = start
        while position < end:
            record = Record(self.reader, position)
            if record.damaged:
                return count
            count += 1
            position = record.end()
        return count

    def records(self, recover=True):
        # Yields every readable record. A record that fails verification either
        # stops the walk (recover off) or is skipped by scanning forward for the
        # next signature, which keeps the rest of the chunk readable.
        if self.header.is_empty():
            return
        start, end = self.record_area()
        position = start
        guard = 0
        while position < end and guard < CHUNK_SIZE:
            guard += 1
            record = None
            try:
                record = Record(self.reader, position)
            except (FormatError, TruncatedError) as problem:
                self.damage.append({"offset": position, "size": None, "reason": str(problem)})
            if record is not None and not record.damaged:
                yield record
                advance = record.size
                if advance < MIN_RECORD_SIZE:
                    advance = MIN_RECORD_SIZE
                position += advance
                continue
            if record is not None:
                self.damage.append({"offset": position, "size": record.size, "reason": record.damage_reason})
            if not recover:
                return
            # valid records sit on an even boundary and the scan keeps that
            # stride, so it must resume on the same parity it started from
            position = self._resync(position, end)
            if position is None:
                return

    def _resync(self, position, end):
        # scan forward for the next record signature, counting the dead bytes
        skipped_start = position
        while position + MIN_RECORD_SIZE <= end:
            if self.reader.u32(position) == RECORD_MAGIC:
                candidate = Record(self.reader, position)
                if not candidate.damaged:
                    self.recovered_bytes += position - skipped_start
                    return position
            position += SIGNATURE_SCAN_STEP
        self.recovered_bytes += max(0, end - skipped_start)
        return None

    def verify(self):
        report = self.header.describe()
        report["index"] = self.index
        report["file_offset"] = self.file_offset
        report["records_readable"] = self.record_count()
        report["records_claimed"] = self.header.record_count_hint()
        report["slack_bytes"] = self.slack_bytes()
        return report


class TemplateDefinition:
    # an inline template as stored in the chunk, before the body is parsed
    __slots__ = ("offset", "next_offset", "template_id", "guid", "data_length", "data_offset")

    def __init__(self, offset, next_offset, template_id, guid, data_length, data_offset):
        self.offset = offset
        self.next_offset = next_offset
        self.template_id = template_id
        self.guid = guid
        self.data_length = data_length
        self.data_offset = data_offset

    def end(self):
        return self.data_offset + self.data_length

    def length(self):
        return 24 + self.data_length

    def __repr__(self):
        return "TemplateDefinition(offset=0x%x, id=%d, guid=%s, %d bytes)" % (self.offset, self.template_id, self.guid, self.data_length)
