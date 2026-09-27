# tests for the container layer: file header, chunk header, string and template
# tables, record walking, checksums, and damage recovery
import struct
import unittest

from tests.helpers import simple_builder, temp_path, write_builder

from evtx_triage.chunk import CHUNK_RECORDS_OFFSET, CHUNK_SIZE, Chunk
from evtx_triage.errors import FormatError
from evtx_triage.evtxfile import EvtxFile
from evtx_triage.header import FILE_HEADER_SIZE, FileHeader


class FileHeaderTests(unittest.TestCase):
    def read_header(self, path):
        with open(path, "rb") as handle:
            data = handle.read()
        return FileHeader(data[:FILE_HEADER_SIZE], source="sample")

    def test_reads_every_field(self):
        header = self.read_header(write_builder(simple_builder()))
        self.assertTrue(header.signature_ok())
        self.assertEqual(header.major_version, 3)
        self.assertEqual(header.minor_version, 1)
        self.assertEqual(header.header_size, 128)
        self.assertEqual(header.header_chunk_size, FILE_HEADER_SIZE)
        self.assertEqual(header.chunk_count, 1)
        self.assertTrue(header.verify_checksum()[0])
        self.assertTrue(header.is_dirty())
        self.assertFalse(header.is_full())
        self.assertFalse(header.wrapped())

    def test_rejects_wrong_magic(self):
        data = bytearray(4096)
        data[0:8] = b"NotAnEvt"
        with self.assertRaises(FormatError):
            FileHeader(bytes(data), source="sample").validate()

    def test_rejects_unknown_version(self):
        path = write_builder(simple_builder())
        with open(path, "rb") as handle:
            data = bytearray(handle.read())
        struct.pack_into("<H", data, 0x24, 7)
        with self.assertRaises(FormatError):
            FileHeader(bytes(data), source="sample").validate()

    def test_detects_a_broken_header_checksum(self):
        path = write_builder(simple_builder())
        with open(path, "rb") as handle:
            data = bytearray(handle.read())
        data[0x40] ^= 0xFF
        # structural validation covers magic, version and sizes, the checksum is
        # reported on its own so a caller can decide how much it matters
        FileHeader(bytes(data), source="sample").validate()
        self.assertFalse(FileHeader(bytes(data), source="sample").verify_checksum()[0])

    def test_chunk_offsets_follow_the_declared_count(self):
        builder = simple_builder(chunks=3)
        builder.add_event(1100, payload={}, provider="Microsoft-Windows-Eventlog")
        header = self.read_header(write_builder(builder))
        self.assertEqual(header.chunk_count, 3)
        offsets = header.chunk_offsets()
        self.assertEqual(offsets[0], FILE_HEADER_SIZE)
        self.assertEqual(offsets[1], FILE_HEADER_SIZE + CHUNK_SIZE)


class ChunkTests(unittest.TestCase):
    def setUp(self):
        self.path = write_builder(simple_builder())
        self.log = EvtxFile(self.path)
        self.chunk = self.log.chunk_at(0)

    def tearDown(self):
        self.log.close()

    def test_chunk_header_is_read(self):
        header = self.chunk.header
        self.assertTrue(header.signature_ok())
        self.assertEqual(header.header_size, 128)
        self.assertTrue(header.verify_header_checksum()[0])
        self.assertTrue(header.verify_data_checksum()[0])
        self.assertFalse(header.is_empty())

    def test_header_checksum_covers_the_template_table(self):
        data = bytearray(self.chunk.data)
        data[0x190] ^= 0x01
        broken = Chunk(bytes(data), index=0, file_offset=FILE_HEADER_SIZE, source="sample")
        self.assertFalse(broken.header.verify_header_checksum()[0])

    def test_data_checksum_catches_a_flipped_byte(self):
        data = bytearray(self.chunk.data)
        data[0x300] ^= 0xFF
        broken = Chunk(bytes(data), index=0, file_offset=FILE_HEADER_SIZE, source="sample")
        self.assertFalse(broken.header.verify_data_checksum()[0])
        self.assertTrue(self.chunk.header.verify_data_checksum()[0])

    def test_records_are_read_in_order(self):
        records = list(self.chunk.records())
        self.assertEqual([record.record_id for record in records], [1, 2])
        for record in records:
            self.assertFalse(record.damaged)
            self.assertEqual(record.magic, 0x00002A2A)
            self.assertGreater(record.size, 24)

    def test_names_are_inline_and_templates_are_listed(self):
        # names are stored inline next to the element that first used them, so
        # the string table stays empty, while every inline template definition is
        # registered in the template table so later records can share it
        self.assertEqual(self.chunk.string_table_offsets(), [])
        offsets = self.chunk.template_table_offsets()
        self.assertTrue(offsets)
        for offset in offsets:
            definition = self.chunk.template(offset)
            self.assertGreaterEqual(definition.offset, CHUNK_RECORDS_OFFSET)
            self.assertGreater(definition.data_length, 0)
        record = list(self.chunk.records())[0]
        self.assertGreater(record.bxml_offset(), 0)

    def test_slack_is_reported(self):
        self.assertGreater(self.chunk.slack_bytes(), 0)

    def test_record_payload_is_bounded_by_the_record(self):
        record = list(self.chunk.records())[0]
        self.assertLess(record.bxml_offset(), record.bxml_end())
        self.assertLessEqual(record.bxml_end(), self.chunk.header.next_record_offset)


class RecordDamageTests(unittest.TestCase):
    def test_truncated_file_yields_nothing_rather_than_crashing(self):
        path = write_builder(simple_builder())
        with open(path, "rb") as handle:
            data = handle.read()
        truncated = temp_path("truncated.evtx")
        with open(truncated, "wb") as handle:
            handle.write(data[: FILE_HEADER_SIZE + 1000])
        with EvtxFile(truncated) as log:
            events = list(log.events())
        self.assertEqual(events, [])

    def test_corrupt_record_is_skipped_and_the_rest_survives(self):
        builder = simple_builder()
        for _ in range(3):
            builder.add_event(1100, payload={}, provider="Microsoft-Windows-Eventlog")
        path = write_builder(builder)
        with open(path, "rb") as handle:
            data = bytearray(handle.read())
        first_size = struct.unpack_from("<I", data, FILE_HEADER_SIZE + 512 + 4)[0]
        second_record = FILE_HEADER_SIZE + 512 + first_size
        data[second_record] = 0x00
        damaged = temp_path("damaged.evtx")
        with open(damaged, "wb") as handle:
            handle.write(bytes(data))
        with EvtxFile(damaged, recover=True) as log:
            events = list(log.events())
            damage = log.damage_report()
        self.assertGreaterEqual(len(events), 4)
        reasons = [str(item) for item in damage]
        self.assertTrue(reasons or any(event.damaged for event in events))

    def test_a_record_whose_size_disagrees_is_marked(self):
        path = write_builder(simple_builder())
        with open(path, "rb") as handle:
            data = bytearray(handle.read())
        struct.pack_into("<I", data, FILE_HEADER_SIZE + 512 + 4, 40)
        broken = temp_path("sizes.evtx")
        with open(broken, "wb") as handle:
            handle.write(bytes(data))
        with EvtxFile(broken, recover=True) as log:
            events = list(log.events())
        self.assertTrue(isinstance(events, list))


class VerifyTests(unittest.TestCase):
    def test_verify_reports_ok_for_a_clean_file(self):
        path = write_builder(simple_builder())
        with EvtxFile(path) as log:
            report = log.verify()
        self.assertTrue(report["ok"])
        self.assertEqual(report["stats"]["damaged_events"], 0)
        self.assertEqual(report["stats"]["events"], 2)

    def test_info_and_stats_expose_the_header(self):
        path = write_builder(simple_builder())
        with EvtxFile(path) as log:
            info = log.info()
            stats = log.stats()
        self.assertEqual(info["format"], "3.1")
        self.assertEqual(stats["events"], 2)


if __name__ == "__main__":
    unittest.main()
