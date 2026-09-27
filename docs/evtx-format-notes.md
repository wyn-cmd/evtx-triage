# EVTX format notes

What the binary format actually looks like, written down from what the parser had to do to read real logs. Every line here was confirmed against a real 26 chunk Security log and checked with python-evtx, not copied from a summary.

## File header, 4096 bytes

    0x00  8    magic, "ElfFile\0"
    0x08  8    oldest chunk number
    0x10  8    current chunk number
    0x18  8    next record identifier
    0x20  4    header size, 128
    0x24  2    minor version, 1
    0x26  2    major version, 3
    0x28  2    header block size, 4096
    0x2A  2    chunk count
    0x2C  76   unused
    0x78  4    flags, bit 0 dirty, bit 1 full
    0x7C  4    CRC32 of bytes 0x00 to 0x78

A "dirty" flag means the log was never closed cleanly, which is normal for a live system and worth reporting.

## Chunk, 65536 bytes each, starting at 4096 + index * 65536

    0x00    8    magic, "ElfChnk\0"
    0x08    8    first event record number in the file
    0x10    8    last event record number in the file
    0x18    8    first event record number in the log
    0x20    8    last event record number in the log
    0x28    4    header size, 128
    0x2C    4    offset of the last record
    0x30    4    offset of the next free byte, which is where the records end
    0x34    4    CRC32 of the record area
    0x38    68   unused
    0x7C    4    CRC32 of bytes 0x00 to 0x78 and 0x80 to 0x200
    0x80    256  string table, 64 offsets of 4 bytes
    0x180   128  template table, 32 offsets of 4 bytes
    0x200   ...  records

Two things are worth knowing. The header checksum deliberately skips bytes 0x78 to 0x80, and it covers the whole string and template table area up to 0x200, not just the string table. Getting either wrong means every checksum on every real file fails. The table offsets are chunk relative, so the same template offset appears in every chunk.

## Record

    0x00    4    magic, 0x00002a2a
    0x04    4    size, including this header and the trailing size copy
    0x08    8    record identifier
    0x10    8    written time, FILETIME
    0x18    ...  binary XML
    size-4  4    size again

Records are four byte aligned in practice, which is what makes a forward scan for the magic on an even stride work when a header is damaged. Scanning on an odd stride finds nothing.

A record may be a template instance, or a plain binary XML stream with no template at all. Both occur, and a plain stream starts straight into an element token.

## Binary XML tokens

    0x00  end of stream              0x08  character reference
    0x01  open start element         0x09  entity reference
    0x02  close start element        0x0A  processing instruction target
    0x03  close empty element        0x0B  processing instruction data
    0x04  close element              0x0C  template instance
    0x05  value                      0x0D  normal substitution
    0x06  attribute                  0x0E  conditional substitution
    0x07  CDATA section              0x0F  fragment header, four bytes

The high nibble carries flags. For an open start element, attribute and value token, bit 0x40 means "more data follows": an element carries an attribute list, an attribute carries a further attribute, a value carries a further value.

## Open start element

    byte    token, 0x01 or 0x41
    word    dependency identifier, normally 0xFFFF
    dword   declared size, ignored by every reader including this one
    dword   offset of the name string
    ...     the name string itself, when the offset points past this element
    dword   attribute list size, only when the attribute flag is set
    ...     attributes, then the close start element token

The order matters and it is easy to get wrong: the inline name string comes immediately after the fixed part of the header, and the four byte attribute list size comes after the name, not before it.

The dependency identifier looks meaningful and is not. A reader can ignore it entirely and still read every real log; treating 0xFFFF as "the content is supplied by a template instance here" makes the parser walk off the end of the buffer.

## Attribute

    byte    token, 0x06 or 0x46
    dword   offset of the name string
    ...     the name string itself, when the offset points past this attribute
    ...     the value, which is a token: a value token, a substitution, or a template instance

## Name string

    dword   offset of the next name string, 0 for the last one
    word    hash
    word    length in characters
    ...     UTF-16LE characters
    2       terminator

Total size is length * 2 + 10 bytes, which is the number an element header has to skip when the name is inline.

## Template instance

    byte    token, 0x0C
    byte    version, 1
    dword   template identifier
    dword   offset of the template definition, chunk relative
    ...     the definition, only when that offset points past this instance
    dword   number of substitution values
    ...     four bytes per value: word size, byte type, byte padding
    ...     the values themselves, in order

A template definition that is already defined earlier in the chunk, or listed in the chunk template table, is shared, so the instance is ten bytes and the substitution array follows immediately.

## Template definition

    0x00  4    offset of the next definition, 0 for the last one
    0x04  4    template identifier, which is also the first four bytes of the guid
    0x04  16   guid
    0x14  4    length of the template body
    0x18  ...  the template body, a binary XML stream that usually opens with a fragment header

The template identifier and the guid overlap: there is no separate identifier field, the identifier is the first four bytes of the guid. Writing both separately produces a definition that is four bytes too long and every reader will misalign on it.

## Substitution values

The declared size in the descriptor is authoritative and tells the reader how far to advance. A size of zero means the value occupies nothing at all, not one byte, and not a length prefixed value. Advancing by one byte on a zero size silently corrupts every later value in the same record, which shows up as a shifted guid, a swapped string, or a hex value with an extra digit.

Strings are the exception to the "size is the whole value" rule in one direction: a literal string inside a template body carries its own length prefix, and for a UTF-16 literal that prefix counts characters while for an ANSI literal it counts bytes.

## Value types

    0x00  null          0x0B  float32        0x14  hex32
    0x01  UTF-16        0x0C  float64        0x15  hex64
    0x02  ANSI          0x0D  boolean        0x20  event handle
    0x03  int8          0x0E  binary         0x21  nested binary XML
    0x04  uint8         0x0F  guid           0x81  array of UTF-16 strings
    0x05  int16         0x10  size           0x80 | type means an array
    0x06  uint16        0x11  FILETIME
    0x07  int32         0x12  system time
    0x08  uint32        0x13  SID
    0x09  int64
    0x0A  uint64

A hex32 or hex64 is displayed as the number its bytes encode, zero padded to the full width of the type, so a keywords field reads 0x8020000000000000 and not the byte order it was stored in.

## Two things that catch readers out

A conditional substitution whose value is null leaves the element standing with empty content. Real logs contain empty Data elements, and dropping them loses the name attribute that carries the field name.

A substitution value of type 0x21 is a whole nested binary XML fragment, usually the EventData block of a security event. It has to be parsed and spliced into the tree in place. Treating it as text produces an event whose entire payload is escaped markup, and every reader that skips it reports empty payloads for thousands of events.
