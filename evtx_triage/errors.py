# Error types shared by every layer of the parser. Each failure carries the byte
# offset it happened at so a damaged log is reported precisely instead of dying
# with a bare traceback halfway through a two gigabyte file.


class EvtxError(Exception):
    # base class for every error this package raises
    pass


class FormatError(EvtxError):
    # the bytes on disk do not match the EVTX structure that was expected
    def __init__(self, message, offset=None, source=None):
        self.message = message
        self.offset = offset
        self.source = source
        detail = message
        if offset is not None:
            detail = "%s (at offset 0x%x)" % (message, offset)
        if source is not None:
            detail = "%s [%s]" % (detail, source)
        super().__init__(detail)


class TruncatedError(FormatError):
    # a structure claims to be larger than the buffer that holds it
    pass


class UnsupportedVersionError(FormatError):
    # anything that is not the version 3.1 header EVTX has always shipped
    pass


class ChecksumError(FormatError):
    # a CRC32 stored in the file disagrees with the bytes it covers
    def __init__(self, message, expected=None, actual=None, offset=None):
        self.expected = expected
        self.actual = actual
        if expected is not None and actual is not None:
            message = "%s (stored 0x%08x, computed 0x%08x)" % (message, expected, actual)
        super().__init__(message, offset=offset)


class RecordError(FormatError):
    # one event record is unreadable while the rest of the chunk is fine
    pass


class BinXmlError(FormatError):
    # a binary XML stream does not follow the token grammar
    pass


class ValueDecodeError(FormatError):
    # a variant value could not be turned into text
    pass
