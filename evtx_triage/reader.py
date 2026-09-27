# Bounds checked little endian reader. Every accessor validates the slice it is
# about to touch, so a corrupted size field raises a FormatError naming the byte
# offset instead of producing a struct.error or silently reading a short slice.

import struct
import uuid
import zlib

from .errors import FormatError, TruncatedError


class Reader:
    # read-only window over a bytes object, base is the absolute file offset of
    # data[0] so every error message can report a real file position
    __slots__ = ("data", "base", "source")

    def __init__(self, data, base=0, source=None):
        self.data = data
        self.base = base
        self.source = source

    def __len__(self):
        return len(self.data)

    def size(self):
        return len(self.data)

    def offset_of(self, offset):
        # translate a buffer offset into the absolute file offset
        return self.base + offset

    def __repr__(self):
        return "Reader(size=%d, base=0x%x, source=%r)" % (len(self.data), self.base, self.source)

    def check(self, offset, size, what="read"):
        # refuse any access that would run past either end of the buffer
        if size < 0:
            raise FormatError("negative length %d requested for %s" % (size, what), offset=self.offset_of(offset), source=self.source)
        if offset < 0:
            raise FormatError("negative offset requested for %s" % what, offset=self.offset_of(offset), source=self.source)
        if offset + size > len(self.data):
            raise TruncatedError(
                "wanted %d bytes for %s but only %d remain" % (size, what, len(self.data) - offset),
                offset=self.offset_of(offset),
                source=self.source,
            )

    def has(self, offset, size):
        # non raising probe used before attempting an optional structure
        return offset >= 0 and size >= 0 and offset + size <= len(self.data)

    def raw(self, offset, size, what="bytes"):
        self.check(offset, size, what)
        return self.data[offset:offset + size]

    def u8(self, offset):
        self.check(offset, 1, "u8")
        return self.data[offset]

    def i8(self, offset):
        self.check(offset, 1, "i8")
        return struct.unpack_from("<b", self.data, offset)[0]

    def u16(self, offset):
        self.check(offset, 2, "u16")
        return struct.unpack_from("<H", self.data, offset)[0]

    def i16(self, offset):
        self.check(offset, 2, "i16")
        return struct.unpack_from("<h", self.data, offset)[0]

    def u32(self, offset):
        self.check(offset, 4, "u32")
        return struct.unpack_from("<I", self.data, offset)[0]

    def i32(self, offset):
        self.check(offset, 4, "i32")
        return struct.unpack_from("<i", self.data, offset)[0]

    def u64(self, offset):
        self.check(offset, 8, "u64")
        return struct.unpack_from("<Q", self.data, offset)[0]

    def i64(self, offset):
        self.check(offset, 8, "i64")
        return struct.unpack_from("<q", self.data, offset)[0]

    def f32(self, offset):
        self.check(offset, 4, "f32")
        return struct.unpack_from("<f", self.data, offset)[0]

    def f64(self, offset):
        self.check(offset, 8, "f64")
        return struct.unpack_from("<d", self.data, offset)[0]

    def u16_be(self, offset):
        self.check(offset, 2, "u16be")
        return struct.unpack_from(">H", self.data, offset)[0]

    def u32_be(self, offset):
        self.check(offset, 4, "u32be")
        return struct.unpack_from(">I", self.data, offset)[0]

    def utf16(self, offset, chars, what="utf-16 string"):
        # chars counts UTF-16 code units, so the byte span is twice that
        self.check(offset, chars * 2, what)
        return self.data[offset:offset + chars * 2].decode("utf-16-le", errors="replace")

    def ansi(self, offset, length, what="ansi string"):
        # the format says ANSI, but writers on non english hosts emit UTF-8 and
        # some emit half converted codepage bytes, so try both before latin-1
        self.check(offset, length, what)
        blob = self.data[offset:offset + length]
        try:
            return blob.decode("utf-8")
        except UnicodeDecodeError:
            return blob.decode("latin-1", errors="replace")

    def guid(self, offset):
        self.check(offset, 16, "guid")
        return str(uuid.UUID(bytes_le=bytes(self.data[offset:offset + 16])))

    def crc32(self, offset, size, what="crc32 region"):
        self.check(offset, size, what)
        return zlib.crc32(self.data[offset:offset + size]) & 0xFFFFFFFF

    def crc32_parts(self, regions):
        # CRC32 over several disjoint regions, needed by the chunk header whose
        # checksum skips the eight bytes around offset 0x78
        value = 0
        for offset, size in regions:
            self.check(offset, size, "crc32 region")
            value = zlib.crc32(self.data[offset:offset + size], value)
        return value & 0xFFFFFFFF
