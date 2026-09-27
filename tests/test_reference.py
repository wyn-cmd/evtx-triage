# Ground truth checks against python-evtx, which is not a dependency of this
# project. When it is installed the fixture writer and the parser are compared
# with an independent reader, and when EVTX_TRIAGE_SAMPLES points at a directory
# of real logs the two parsers are compared record by record.
import os
import re
import unittest
from datetime import timedelta

from tests.helpers import BASE_TIME, read_events, write_builder
from tests.fixtures.evtx_builder import EvtxBuilder

try:
    import Evtx.Evtx as reference_evtx
except ImportError:
    reference_evtx = None

SAMPLES = os.environ.get("EVTX_TRIAGE_SAMPLES", "")

# the reference renders a record as one long xml string, so the few fields worth
# comparing are pulled out with regexes instead of an xml parser
EVENT_ID = re.compile(r"<EventID[^>]*>(-?\d+)</EventID>")
CHANNEL = re.compile(r"<Channel>([^<]*)</Channel>")
COMPUTER = re.compile(r"<Computer>([^<]*)</Computer>")
PROVIDER = re.compile(r'<Provider\b[^>]*?\sName="([^"]*)"')
DATA_VALUE = re.compile(r'<Data Name="([^"]+)">([^<]*)</Data>')


def reference_fields(xml_text):
    event_id = EVENT_ID.search(xml_text)
    channel = CHANNEL.search(xml_text)
    computer = COMPUTER.search(xml_text)
    provider = PROVIDER.search(xml_text)
    return {
        "event_id": event_id.group(1) if event_id else "",
        "channel": channel.group(1) if channel else "",
        "computer": computer.group(1) if computer else "",
        "provider": provider.group(1) if provider else "",
        "payload": dict(DATA_VALUE.findall(xml_text)),
    }


def sample_files(limit=2):
    if not SAMPLES or not os.path.isdir(SAMPLES):
        return []
    names = [name for name in sorted(os.listdir(SAMPLES)) if name.lower().endswith(".evtx")]
    return [os.path.join(SAMPLES, name) for name in names[:limit]]


@unittest.skipUnless(reference_evtx is not None, "python-evtx is not installed")
class FixtureAgreementTests(unittest.TestCase):
    def test_the_reference_reads_a_fixture_written_here(self):
        builder = EvtxBuilder(chunks=1)
        builder.add_event(
            4624,
            payload={"TargetUserName": ("wstring", "alice"), "LogonType": ("uint32", 3), "IpAddress": ("wstring", "203.0.113.9")},
            timestamp=BASE_TIME,
        )
        path = write_builder(builder)
        with reference_evtx.Evtx(path) as log:
            records = list(log.records())
            self.assertEqual(len(records), 1)
            xml_text = records[0].xml()
        fields = reference_fields(xml_text)
        self.assertEqual(fields["event_id"], "4624")
        self.assertEqual(fields["channel"], "Security")
        self.assertEqual(fields["computer"], "TESTHOST")
        self.assertEqual(fields["payload"]["TargetUserName"], "alice")
        self.assertEqual(fields["payload"]["LogonType"], "3")

    def test_both_parsers_agree_on_the_fixture(self):
        # a single record whose payload covers the value types both parsers
        # render the same way. python-evtx cannot follow a shared inline template
        # from a later record or a later chunk in a synthetic file, this parser
        # can, and the real sample test below covers that sharing where real logs
        # actually use it
        builder = EvtxBuilder(chunks=1)
        builder.add_event(
            4624,
            payload={
                "TargetUserName": ("wstring", "alice"),
                "LogonType": ("uint32", 3),
                "SubjectLogonId": ("hex64", 0x3E7),
                "TargetUserSid": ("sid", "S-1-5-21-1-2-3-1001"),
                "LogonGuid": ("guid", "00112233-4455-6677-8899-aabbccddeeff"),
                "ElevatedToken": ("bool", True),
            },
            timestamp=BASE_TIME,
        )
        path = write_builder(builder)
        mine = read_events(path)
        self.assertEqual(len(mine), 1)
        with reference_evtx.Evtx(path) as log:
            theirs = [reference_fields(record.xml()) for record in log.records()]
        self.assertEqual(len(theirs), 1)
        reference = theirs[0]
        self.assertEqual(str(mine[0].event_id), reference["event_id"])
        self.assertEqual(mine[0].channel, reference["channel"])
        self.assertEqual(mine[0].computer, reference["computer"])
        self.assertEqual(mine[0].provider, reference["provider"])
        for key, value in reference["payload"].items():
            self.assertEqual(mine[0].payload.get(key, ""), value, key)


@unittest.skipUnless(reference_evtx is not None and SAMPLES, "no reference parser or no EVTX_TRIAGE_SAMPLES directory")
class RealSampleAgreementTests(unittest.TestCase):
    def test_record_counts_match(self):
        files = sample_files()
        self.assertTrue(files, "no .evtx files found in EVTX_TRIAGE_SAMPLES")
        for path in files:
            with reference_evtx.Evtx(path) as log:
                reference_count = len(list(log.records()))
            self.assertEqual(len(read_events(path)), reference_count, path)

    def test_fields_match_on_the_first_records(self):
        files = sample_files()
        self.assertTrue(files)
        for path in files:
            mine = read_events(path)[:200]
            with reference_evtx.Evtx(path) as log:
                theirs = [reference_fields(record.xml()) for record in list(log.records())[:200]]
            for event, reference in zip(mine, theirs):
                self.assertEqual(str(event.event_id), reference["event_id"], "record %s" % event.record_id)
                self.assertEqual(event.channel, reference["channel"], "record %s" % event.record_id)
                self.assertEqual(event.computer, reference["computer"], "record %s" % event.record_id)
                self.assertEqual(event.provider, reference["provider"], "record %s" % event.record_id)


if __name__ == "__main__":
    unittest.main()
