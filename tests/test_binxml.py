# tests for the binary XML decoder: token walking, templates, substitution
# binding, and template free records
import unittest
from datetime import timedelta

from tests.helpers import BASE_TIME, read_events, write_builder
from tests.fixtures.evtx_builder import EvtxBuilder

from evtx_triage.render import render_xml


class TemplateRecordTests(unittest.TestCase):
    def setUp(self):
        self.builder = EvtxBuilder(chunks=1)
        self.builder.add_event(
            4624,
            payload={"TargetUserName": ("wstring", "alice"), "LogonType": ("uint32", 3), "IpAddress": ("wstring", "10.0.0.9")},
            timestamp=BASE_TIME,
            level=0,
            task=12544,
            keywords=0x8020000000000000,
            user_id="S-1-5-21-1-2-3",
        )
        self.event = read_events(write_builder(self.builder))[0]

    def test_system_fields_come_through(self):
        event = self.event
        self.assertEqual(event.event_id, "4624")
        self.assertEqual(event.provider, "Microsoft-Windows-Security-Auditing")
        self.assertEqual(event.channel, "Security")
        self.assertEqual(event.computer, "TESTHOST")
        self.assertEqual(event.level, 0)
        self.assertEqual(event.task, 12544)
        self.assertEqual(event.keywords, "0x8020000000000000")

    def test_attributes_built_from_substitutions(self):
        self.assertEqual(self.event.provider_guid.lower(), "{54849625-5478-4994-a5ba-3e3b0328c30d}")
        self.assertEqual(self.event.user_id, "S-1-5-21-1-2-3")

    def test_timestamps(self):
        self.assertEqual(self.event.timestamp, BASE_TIME)
        self.assertEqual(self.event.record_written, BASE_TIME)
        self.assertEqual(self.event.timestamp_source, "event")

    def test_payload_values(self):
        self.assertEqual(self.event.payload["TargetUserName"], "alice")
        self.assertEqual(self.event.payload["LogonType"], "3")
        self.assertEqual(self.event.payload["IpAddress"], "10.0.0.9")
        self.assertEqual(self.event.payload_kind, "EventData")

    def test_record_id_is_read(self):
        self.assertEqual(self.event.record_id, 1)

    def test_rendered_xml_is_well_formed(self):
        xml = render_xml(self.event.nodes)
        self.assertTrue(xml.startswith("<Event "))
        self.assertIn("<EventID", xml)
        self.assertIn("4624", xml)
        self.assertIn('Name="TargetUserName"', xml)
        self.assertTrue(xml.rstrip().endswith("</Event>"))

    def test_searchable_text_includes_payload(self):
        text = self.event.searchable_text()
        self.assertIn("alice", text)
        self.assertIn("10.0.0.9", text)

    def test_as_dict_shape(self):
        data = self.event.as_dict()
        self.assertEqual(data["event_id"], "4624")
        self.assertEqual(data["payload"]["LogonType"], "3")
        self.assertEqual(data["channel"], "Security")


class TemplateSharingTests(unittest.TestCase):
    def test_events_with_the_same_keys_share_one_template(self):
        builder = EvtxBuilder(chunks=1)
        for offset in range(4):
            builder.add_event(4625, payload={"TargetUserName": ("wstring", "bob")}, timestamp=BASE_TIME + timedelta(seconds=offset))
        events = read_events(write_builder(builder))
        self.assertEqual([event.event_id for event in events], ["4625"] * 4)
        self.assertEqual([event.payload["TargetUserName"] for event in events], ["bob"] * 4)

    def test_events_with_different_keys_do_not_collide(self):
        builder = EvtxBuilder(chunks=1)
        builder.add_event(4625, payload={"A": ("wstring", "one")}, timestamp=BASE_TIME)
        builder.add_event(4720, payload={"B": ("wstring", "two"), "C": ("uint32", 7)}, timestamp=BASE_TIME + timedelta(minutes=1))
        events = read_events(write_builder(builder))
        self.assertEqual(events[0].payload, {"A": "one"})
        self.assertEqual(events[1].payload, {"B": "two", "C": "7"})
        self.assertEqual([event.event_id for event in events], ["4625", "4720"])

    def test_userdata_payload_is_flattened(self):
        builder = EvtxBuilder(chunks=1)
        builder.add_event(1000, payload={"SubjectUserName": ("wstring", "svc")}, payload_kind="UserData", timestamp=BASE_TIME)
        event = read_events(write_builder(builder))[0]
        self.assertEqual(event.payload_kind, "UserData")
        self.assertEqual(event.payload["SubjectUserName"], "svc")


class PlainRecordTests(unittest.TestCase):
    def test_record_without_a_template_still_reads(self):
        # some writers store a plain element stream instead of a template
        # instance, and the decoder handles both shapes
        builder = EvtxBuilder(chunks=1)
        builder.add_event(4625, payload={"TargetUserName": ("wstring", "bob")}, timestamp=BASE_TIME, template=False)
        events = read_events(write_builder(builder))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].payload["TargetUserName"], "bob")
        self.assertEqual(events[0].computer, "TESTHOST")
        self.assertEqual(events[0].channel, "Security")

    def test_mixed_records_in_one_chunk(self):
        builder = EvtxBuilder(chunks=1)
        builder.add_event(4624, payload={"TargetUserName": ("wstring", "alice")}, timestamp=BASE_TIME)
        builder.add_event(4625, payload={"TargetUserName": ("wstring", "bob")}, timestamp=BASE_TIME + timedelta(seconds=1), template=False)
        builder.add_event(1102, payload={}, timestamp=BASE_TIME + timedelta(seconds=2))
        events = read_events(write_builder(builder))
        self.assertEqual(len(events), 3)
        self.assertEqual(events[2].event_id, "1102")


class MultiChunkTests(unittest.TestCase):
    def test_events_spread_over_chunks_are_all_read(self):
        builder = EvtxBuilder(chunks=3)
        for offset in range(9):
            builder.add_event(4624 + offset, payload={"Index": ("uint32", offset)}, timestamp=BASE_TIME + timedelta(minutes=offset))
        events = read_events(write_builder(builder))
        self.assertEqual(len(events), 9)
        self.assertEqual(events[8].payload["Index"], "8")

    def test_conditional_null_keeps_the_element_in_place(self):
        builder = EvtxBuilder(chunks=1)
        builder.add_event(4624, payload={"TargetUserName": ("wstring", "alice"), "ProcessName": ("null", None)}, timestamp=BASE_TIME)
        event = read_events(write_builder(builder))[0]
        self.assertEqual(event.payload["TargetUserName"], "alice")
        self.assertEqual(event.payload["ProcessName"], "")
        self.assertIn('Name="ProcessName"', render_xml(event.nodes))


if __name__ == "__main__":
    unittest.main()
