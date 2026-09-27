# The 4096 byte file header that fronts every EVTX file. It records how many
# chunks are present, whether the log is dirty (never closed cleanly), and the
# record id the next write would receive.

from .errors import FormatError, TruncatedError, UnsupportedVersionError
from .reader import Reader

FILE_HEADER_SIZE = 4096
FILE_MAGIC = b"ElfFile\x00"
CHUNK_SIZE = 65536
FILE_HEADER_CHECKSUM_SIZE = 0x78


class FileHeader:
    # layout, all little endian:
    #   0x00 magic 8 bytes, 0x08 oldest_chunk u64, 0x10 current_chunk_number u64,
    #   0x18 next_record_number u64, 0x20 header_size u32, 0x24 minor_version u16,
    #   0x26 major_version u16, 0x28 header_chunk_size u16, 0x2A chunk_count u16,
    #   0x2C unused 76 bytes, 0x78 flags u32, 0x7C checksum u32
    def __init__(self, data, source=None):
        self.source = source
        if len(data) < FILE_HEADER_SIZE:
            raise TruncatedError(
                "file header needs %d bytes but only %d are available" % (FILE_HEADER_SIZE, len(data)),
                offset=0,
                source=source,
            )
        self.reader = Reader(data[:FILE_HEADER_SIZE], base=0, source=source)
        self.magic = bytes(self.reader.raw(0x00, 8, "file signature"))
        self.oldest_chunk = self.reader.u64(0x08)
        self.current_chunk_number = self.reader.u64(0x10)
        self.next_record_number = self.reader.u64(0x18)
        self.header_size = self.reader.u32(0x20)
        self.minor_version = self.reader.u16(0x24)
        self.major_version = self.reader.u16(0x26)
        self.header_chunk_size = self.reader.u16(0x28)
        self.chunk_count = self.reader.u16(0x2A)
        self.unused = bytes(self.reader.raw(0x2C, 0x4C, "file header reserved area"))
        self.flags = self.reader.u32(0x78)
        self.checksum = self.reader.u32(0x7C)

    def __repr__(self):
        return "FileHeader(chunks=%d, records_next=%d, version=%s)" % (self.chunk_count, self.next_record_number, self.version_string())

    def signature_ok(self):
        return self.magic == FILE_MAGIC

    def validate(self):
        # a hard failure: this is not an event log at all, or a version this
        # parser does not understand
        if not self.signature_ok():
            raise FormatError("not an EVTX file, signature is %r" % (self.magic,), offset=0, source=self.source)
        if self.major_version != 3 or self.minor_version != 1:
            raise UnsupportedVersionError(
                "unsupported event log version %d.%d" % (self.major_version, self.minor_version),
                offset=0x24,
                source=self.source,
            )

    def verify_checksum(self):
        # the header checksum covers the first 120 bytes only
        computed = self.reader.crc32(0, FILE_HEADER_CHECKSUM_SIZE, "file header checksum")
        return computed == self.checksum, computed

    def is_dirty(self):
        return bool(self.flags & 0x01)

    def is_full(self):
        return bool(self.flags & 0x02)

    def flag_names(self):
        names = []
        if self.is_dirty():
            names.append("dirty")
        if self.is_full():
            names.append("full")
        if self.flags & ~0x03:
            names.append("unknown-bits-0x%x" % (self.flags & ~0x03))
        return names

    def wrapped(self):
        # a first chunk number above one means the log wrapped and older chunks
        # were overwritten by newer ones
        return self.oldest_chunk > 1

    def chunk_offsets(self):
        # every chunk is 64 KB and they follow the 4096 byte header directly
        return [FILE_HEADER_SIZE + index * CHUNK_SIZE for index in range(self.chunk_count)]

    def chunk_index_at(self, offset):
        if offset < FILE_HEADER_SIZE:
            return None
        return (offset - FILE_HEADER_SIZE) // CHUNK_SIZE

    def version_string(self):
        return "%d.%d" % (self.major_version, self.minor_version)

    def describe(self):
        checksum_ok, computed = self.verify_checksum()
        return {
            "format": self.version_string(),
            "chunk_count": self.chunk_count,
            "oldest_chunk": self.oldest_chunk,
            "current_chunk_number": self.current_chunk_number,
            "next_record_number": self.next_record_number,
            "header_size": self.header_size,
            "header_chunk_size": self.header_chunk_size,
            "flags": self.flags,
            "flag_names": self.flag_names(),
            "dirty": self.is_dirty(),
            "full": self.is_full(),
            "wrapped": self.wrapped(),
            "checksum": self.checksum,
            "checksum_computed": computed,
            "checksum_ok": checksum_ok,
        }
