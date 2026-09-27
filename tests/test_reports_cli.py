# tests for the renderers and the command line, driven through main() so the
# argument parsing and the exit codes are covered too
import contextlib
import csv
import io
import json
import unittest
from datetime import timedelta

from tests.helpers import BASE_TIME, analyze_path, read_events, write_builder
from tests.fixtures.evtx_builder import EvtxBuilder

from evtx_triage.cli import main
from evtx_triage.report import (render_dump, render_events_csv, render_findings_csv, render_json, render_markdown, render_text, severity_rank, write_output)
from evtx_triage.triage import summarize


def benign_log():
    builder = EvtxBuilder(chunks=1)
    builder.add_event(4624, payload={"TargetUserName": ("wstring", "alice"), "LogonType": ("uint32", 3)}, timestamp=BASE_TIME)
    builder.add_event(4624, payload={"TargetUserName": ("wstring", "alice"), "LogonType": ("uint32", 3)}, timestamp=BASE_TIME + timedelta(minutes=5))
    return write_builder(builder)


def noisy_log():
    builder = EvtxBuilder(chunks=1)
    builder.add_event(1102, payload={"SubjectUserName": ("wstring", "alice")}, timestamp=BASE_TIME)
    builder.add_event(4720, payload={"TargetUserName": ("wstring", "backdoor")}, timestamp=BASE_TIME + timedelta(minutes=1))
    return write_builder(builder)


def capture(arguments):
    # run the cli with stdout captured, returning the text and the exit code
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(arguments)
    return code, buffer.getvalue()


class RendererTests(unittest.TestCase):
    def setUp(self):
        self.path = noisy_log()
        self.report = analyze_path(self.path)

    def test_text_report_leads_with_the_counts(self):
        text = render_text(self.report, summarize(self.report))
        self.assertIn("EVTX TRIAGE REPORT", text)
        self.assertIn("EVT-LOG-CLEARED", text)
        self.assertIn("SEVERITY", text)

    def test_json_report_is_machine_readable(self):
        payload = json.loads(render_json(self.report, summarize(self.report)))
        self.assertEqual(payload["summary"]["events"], 2)
        self.assertTrue(any(finding["rule_id"] == "EVT-LOG-CLEARED" for finding in payload["findings"]))

    def test_markdown_report_starts_with_a_heading(self):
        self.assertTrue(render_markdown(self.report, summarize(self.report)).startswith("#"))

    def test_findings_csv_has_a_header_and_a_row(self):
        rows = list(csv.reader(io.StringIO(render_findings_csv(self.report["findings"]))))
        self.assertIn("rule_id", rows[0])
        self.assertGreaterEqual(len(rows), 2)

    def test_events_csv_lists_records(self):
        rows = list(csv.reader(io.StringIO(render_events_csv(self.report["events"]))))
        self.assertIn("record_id", rows[0])
        self.assertEqual(len(rows), 3)

    def test_dump_renders_xml(self):
        text = render_dump(read_events(self.path), limit=1)
        self.assertIn("<Event", text)
        self.assertIn("EventID", text)

    def test_severity_ranking_is_ordered(self):
        self.assertGreater(severity_rank("critical"), severity_rank("high"))
        self.assertGreater(severity_rank("high"), severity_rank("medium"))
        self.assertGreater(severity_rank("medium"), severity_rank("low"))

    def test_write_output_creates_a_file(self):
        target = self.path + ".report.txt"
        write_output("hello", target)
        with open(target, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "hello")


class CliTests(unittest.TestCase):
    def test_info_exits_clean(self):
        code, text = capture(["info", benign_log()])
        self.assertEqual(code, 0)
        self.assertIn("3.1", text)

    def test_verify_reports_a_healthy_file(self):
        code, text = capture(["verify", benign_log()])
        self.assertEqual(code, 0)
        self.assertIn("checksum", text.lower())

    def test_stats_counts_events(self):
        code, text = capture(["stats", benign_log()])
        self.assertEqual(code, 0)
        self.assertIn("2", text)

    def test_triage_exits_non_zero_when_findings_are_serious(self):
        code, text = capture(["triage", noisy_log()])
        self.assertEqual(code, 1)
        self.assertIn("EVT-LOG-CLEARED", text)

    def test_triage_on_a_quiet_log_exits_clean(self):
        code, _ = capture(["triage", benign_log()])
        self.assertEqual(code, 0)

    def test_triage_json_format(self):
        code, text = capture(["triage", noisy_log(), "--format", "json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(text)["summary"]["events"], 2)

    def test_dump_honours_the_limit(self):
        code, text = capture(["dump", benign_log(), "--limit", "1", "--format", "xml-pretty"])
        self.assertEqual(code, 0)
        self.assertEqual(text.count("<Event "), 1)

    def test_dump_filters_by_event_id(self):
        code, text = capture(["dump", noisy_log(), "--event-id", "1102"])
        self.assertEqual(code, 0)
        self.assertIn("1102", text)
        self.assertNotIn("<EventID>4720</EventID>", text)

    def test_rules_command_lists_the_catalogue(self):
        code, text = capture(["rules"])
        self.assertEqual(code, 0)
        self.assertIn("EVT-LOG-CLEARED", text)

    def test_rules_command_shows_one_rule(self):
        code, text = capture(["rules", "EVT-LOG-CLEARED"])
        self.assertEqual(code, 0)
        self.assertIn("T1070.001", text)

    def test_entities_command_lists_accounts(self):
        code, text = capture(["entities", benign_log()])
        self.assertEqual(code, 0)
        self.assertIn("alice", text)

    def test_timeline_command_runs(self):
        code, text = capture(["timeline", noisy_log()])
        self.assertEqual(code, 0)
        self.assertIn("Security", text)

    def test_verify_prints_a_chunk_table(self):
        # the human readable form is a table, not a dump of the verification
        # dictionary, and it always ends with totals and a damage line
        code, text = capture(["verify", benign_log()])
        self.assertEqual(code, 0)
        self.assertIn("chunk", text)
        self.assertIn("readable", text)
        self.assertIn("totals:", text)
        self.assertIn("damage:", text)

    def test_missing_file_is_reported_without_a_traceback(self):
        code, text = capture(["info", "/nonexistent/sample.evtx"])
        self.assertNotEqual(code, 0)
        self.assertIn("no such file", text.lower())


if __name__ == "__main__":
    unittest.main()
