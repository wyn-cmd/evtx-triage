# one test per variant value type, round tripped through the fixture writer
import base64
import unittest
from datetime import datetime

from tests.helpers import BASE_TIME, read_events, write_builder

from tests.fixtures.evtx_builder import EvtxBuilder


def payload_of(kind, value, key="Value"):
    builder = EvtxBuilder(chunks=1)
    builder.add_event(1, payload={key: (kind, value)}, timestamp=BASE_TIME)
    path = write_builder(builder)
    return read_events(path)[0].payload[key]


class VariantValueTests(unittest.TestCase):
    def test_strings(self):
        self.assertEqual(payload_of("wstring", "hello world"), "hello world")
        self.assertEqual(payload_of("string", "ansi text"), "ansi text")

    def test_unicode_survives(self):
        self.assertEqual(payload_of("wstring", "cafe \u0394\u03a3"), "cafe \u0394\u03a3")

    def test_signed_and_unsigned_integers(self):
        self.assertEqual(payload_of("uint8", 250), "250")
        self.assertEqual(payload_of("int8", -8), "-8")
        self.assertEqual(payload_of("uint16", 65535), "65535")
        self.assertEqual(payload_of("int16", -300), "-300")
        self.assertEqual(payload_of("uint32", 4000000000), "4000000000")
        self.assertEqual(payload_of("int32", -2000000000), "-2000000000")
        self.assertEqual(payload_of("uint64", 18000000000000000000), "18000000000000000000")
        self.assertEqual(payload_of("int64", -5000000000), "-5000000000")
        self.assertEqual(payload_of("sizet", 4096), "4096")

    def test_reals(self):
        self.assertAlmostEqual(float(payload_of("real32", 1.5)), 1.5, places=5)
        self.assertAlmostEqual(float(payload_of("real64", 2.25)), 2.25, places=9)

    def test_boolean(self):
        self.assertEqual(payload_of("bool", True).lower(), "true")
        self.assertEqual(payload_of("bool", False).lower(), "false")

    def test_binary_is_base64(self):
        text = payload_of("binary", b"abc123")
        self.assertEqual(base64.b64decode(text), b"abc123")

    def test_guid(self):
        text = payload_of("guid", "00112233-4455-6677-8899-aabbccddeeff")
        self.assertEqual(text.lower(), "{00112233-4455-6677-8899-aabbccddeeff}")

    def test_sid(self):
        self.assertEqual(payload_of("sid", "S-1-5-21-1-2-3"), "S-1-5-21-1-2-3")
        self.assertEqual(payload_of("sid", "S-1-5-18"), "S-1-5-18")

    def test_hex_values_are_the_number_not_the_byte_order(self):
        # the stored bytes are little endian and the value printed is the number
        # they encode, so this must not come back byte reversed
        self.assertEqual(payload_of("hex32", 0xC000006D), "0xc000006d")
        self.assertEqual(payload_of("hex64", 0xC000000000000001), "0xc000000000000001")

    def test_filetime(self):
        text = payload_of("filetime", datetime(2024, 5, 4, 12, 30, 15, 500000))
        self.assertTrue(text.startswith("2024-05-04 12:30:15"), text)

    def test_systemtime(self):
        text = payload_of("systime", datetime(2024, 5, 4, 12, 30, 15))
        self.assertTrue(text.startswith("2024-05-04 12:30:15"), text)

    def test_string_array_reports_entries(self):
        text = payload_of("stringarray", ["alpha", "beta"])
        self.assertIn("<string>alpha</string>", text)
        self.assertIn("<string>beta</string>", text)

    def test_null_value_leaves_an_empty_element(self):
        # a null conditional substitution keeps the tag and empties it, which is
        # what the event viewer shows
        self.assertEqual(payload_of("null", None), "")


class ValueEdgeCaseTests(unittest.TestCase):
    def test_zero_and_max_values(self):
        self.assertEqual(payload_of("uint32", 0), "0")
        self.assertEqual(payload_of("hex64", 0), "0x0000000000000000")
        self.assertEqual(payload_of("wstring", ""), "")

    def test_many_values_in_one_event(self):
        builder = EvtxBuilder(chunks=1)
        payload = {
            "A": ("wstring", "one"),
            "B": ("uint32", 2),
            "C": ("hex64", 3),
            "D": ("sid", "S-1-5-18"),
            "E": ("bool", True),
        }
        builder.add_event(4688, payload=payload, timestamp=BASE_TIME)
        event = read_events(write_builder(builder))[0]
        self.assertEqual(event.payload["A"], "one")
        self.assertEqual(event.payload["B"], "2")
        self.assertEqual(event.payload["C"], "0x0000000000000003")
        self.assertEqual(event.payload["D"], "S-1-5-18")
        self.assertEqual(event.payload["E"].lower(), "true")


if __name__ == "__main__":
    unittest.main()
