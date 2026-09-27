# tests for the detection layer: static rules, correlation rules, entities and
# the episode timeline
import unittest
from datetime import timedelta

from tests.helpers import BASE_TIME, analyze_path, read_events, write_builder
from tests.fixtures.evtx_builder import EvtxBuilder

from evtx_triage.correlations import CORRELATION_RULES
from evtx_triage.entities import Entities, harvest, is_private
from evtx_triage.rules import evaluate
from evtx_triage.rules_data import RULES
from evtx_triage.timeline import build_episodes, channel_coverage, histogram


def rules_for(findings):
    return set(finding.rule_id for finding in findings)


def run_rules(events):
    # the static rules only, correlation rules are exercised on their own below
    return evaluate(events, RULES, correlation_rules=())


def run_all(events):
    return evaluate(events, RULES, CORRELATION_RULES)


def payload_event(event_id, **payload):
    builder = EvtxBuilder(chunks=1)
    builder.add_event(event_id, payload=payload, timestamp=BASE_TIME)
    return read_events(write_builder(builder))[0]


class StaticRuleTests(unittest.TestCase):
    def test_event_log_cleared_is_critical(self):
        found = [finding for finding in run_rules([payload_event(1102, SubjectUserName=("wstring", "alice"))]) if finding.rule_id == "EVT-LOG-CLEARED"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "critical")
        self.assertEqual(found[0].technique, "T1070.001")

    def test_event_log_cleared_fires_on_the_system_channel_too(self):
        builder = EvtxBuilder(chunks=1)
        builder.add_event(104, payload={}, channel="System", provider="Microsoft-Windows-Eventlog")
        self.assertIn("EVT-LOG-CLEARED", rules_for(run_rules(read_events(write_builder(builder)))))

    def test_log_service_stop_is_high(self):
        self.assertIn("EVT-LOG-SERVICE-STOP", rules_for(run_rules([payload_event(1100, SubjectUserName=("wstring", "alice"))])))

    def test_account_created(self):
        self.assertIn("EVT-ACCOUNT-CREATED", rules_for(run_rules([payload_event(4720, TargetUserName=("wstring", "newuser"))])))

    def test_privileged_group_membership_change(self):
        event = payload_event(4728, MemberName=("wstring", "CN=bob"), GroupName=("wstring", "Administrators"))
        self.assertIn("EVT-GROUP-ADD", rules_for(run_rules([event])))

    def test_service_install(self):
        builder = EvtxBuilder(chunks=1)
        builder.add_event(7045, payload={"ServiceName": ("wstring", "evil"), "ImagePath": ("wstring", "C:\\evil.exe")}, channel="System", provider="Service Control Manager")
        self.assertIn("EVT-SERVICE-INSTALL", rules_for(run_rules(read_events(write_builder(builder)))))

    def test_scheduled_task_creation(self):
        self.assertIn("EVT-SCHEDULED-TASK", rules_for(run_rules([payload_event(4698, TaskName=("wstring", "\\Updater"))])))

    def test_suspicious_process_creation(self):
        event = payload_event(
            4688,
            NewProcessName=("wstring", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            CommandLine=("wstring", "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"),
        )
        found = [finding for finding in run_rules([event]) if finding.rule_id == "EVT-PROCESS-SUSPICIOUS"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")

    def test_benign_process_creation_is_quiet(self):
        event = payload_event(4688, NewProcessName=("wstring", "C:\\Windows\\System32\\notepad.exe"), CommandLine=("wstring", "notepad.exe report.txt"))
        self.assertNotIn("EVT-PROCESS-SUSPICIOUS", rules_for(run_rules([event])))

    def test_kerberoasting_style_ticket(self):
        event = payload_event(4769, ServiceName=("wstring", "MSSQLSvc/db"), TicketEncryptionType=("hex32", 0x17))
        self.assertIn("EVT-KERBEROAST", rules_for(run_rules([event])))

    def test_rule_catalogue_is_well_formed(self):
        identifiers = [rule.rule_id for rule in RULES]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertGreaterEqual(len(identifiers), 20)
        for rule in RULES:
            self.assertTrue(rule.event_ids)
            self.assertTrue(rule.technique.startswith("T"))
            self.assertIn(rule.severity, ("info", "low", "medium", "high", "critical"))

    def test_findings_are_returned_worst_first(self):
        events = [payload_event(1102, SubjectUserName=("wstring", "alice")), payload_event(4672, PrivilegeList=("wstring", "SeDebugPrivilege"))]
        findings = run_rules(events)
        self.assertGreaterEqual(len(findings), 2)
        scores = [finding.score for finding in findings]
        self.assertEqual(scores, sorted(scores, reverse=True))


class CorrelationTests(unittest.TestCase):
    def builder_with(self, entries):
        builder = EvtxBuilder(chunks=1)
        for event_id, payload, offset in entries:
            builder.add_event(event_id, payload=payload, timestamp=BASE_TIME + timedelta(seconds=offset))
        return read_events(write_builder(builder))

    def test_repeated_failures_raise_a_brute_force_finding(self):
        events = self.builder_with([
            (4625, {"TargetUserName": ("wstring", "alice"), "IpAddress": ("wstring", "203.0.113.5")}, offset)
            for offset in range(0, 60, 10)
        ])
        found = [finding for finding in run_all(events) if finding.rule_id == "EVT-BRUTE-FORCE"]
        self.assertEqual(len(found), 1)
        self.assertIn("203.0.113.5", found[0].detail)

    def test_failures_spread_beyond_the_window_do_not_fire(self):
        events = self.builder_with([
            (4625, {"TargetUserName": ("wstring", "alice"), "IpAddress": ("wstring", "203.0.113.5")}, offset * 600)
            for offset in range(5)
        ])
        self.assertNotIn("EVT-BRUTE-FORCE", rules_for(run_all(events)))

    def test_success_after_failures_is_flagged(self):
        entries = [
            (4625, {"TargetUserName": ("wstring", "alice"), "IpAddress": ("wstring", "203.0.113.5")}, offset)
            for offset in (0, 20, 40)
        ]
        entries.append((4624, {"TargetUserName": ("wstring", "alice"), "LogonType": ("uint32", 3), "IpAddress": ("wstring", "203.0.113.5")}, 60))
        found = [finding for finding in run_all(self.builder_with(entries)) if finding.rule_id == "EVT-SUCCESS-AFTER-FAILURES"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "critical")

    def test_channel_gap_is_reported(self):
        # the gap rule only speaks up for a channel that had been busy, so the
        # stream needs more than a couple of records around the quiet stretch
        entries = [(4624, {"TargetUserName": ("wstring", "alice")}, offset) for offset in (0, 60, 120)]
        entries += [(4624, {"TargetUserName": ("wstring", "alice")}, 120 + 86400 + offset) for offset in (0, 60, 120)]
        self.assertIn("EVT-CHANNEL-GAP", rules_for(run_all(self.builder_with(entries))))


class EntityTests(unittest.TestCase):
    def test_private_address_classification(self):
        self.assertTrue(is_private("10.0.0.1"))
        self.assertTrue(is_private("192.168.1.20"))
        self.assertTrue(is_private("127.0.0.1"))
        self.assertFalse(is_private("203.0.113.9"))
        self.assertFalse(is_private("not an address"))

    def test_harvest_collects_accounts_hosts_and_addresses(self):
        builder = EvtxBuilder(chunks=1)
        builder.add_event(4624, payload={"TargetUserName": ("wstring", "alice"), "IpAddress": ("wstring", "203.0.113.9")}, timestamp=BASE_TIME)
        entities = Entities()
        for event in read_events(write_builder(builder)):
            harvest(event, entities)
        self.assertIn("alice", entities.accounts)
        self.assertIn("TESTHOST", entities.hosts)
        self.assertIn("203.0.113.9", entities.addresses)
        self.assertNotIn("203.0.113.9", entities.private_addresses)
        self.assertIn("alice", entities.as_dict()["accounts"])


class TimelineTests(unittest.TestCase):
    def test_episodes_split_on_a_gap(self):
        builder = EvtxBuilder(chunks=1)
        for offset in range(3):
            builder.add_event(4624, payload={}, timestamp=BASE_TIME + timedelta(minutes=offset))
        for offset in range(3):
            builder.add_event(4624, payload={}, timestamp=BASE_TIME + timedelta(hours=6, minutes=offset))
        events = read_events(write_builder(builder))
        episodes = build_episodes(events, [])
        self.assertEqual(len(episodes), 2)
        self.assertEqual(sum(len(episode.events) for episode in episodes), 6)

    def test_coverage_lists_each_channel(self):
        builder = EvtxBuilder(chunks=1)
        builder.add_event(4624, payload={}, timestamp=BASE_TIME)
        builder.add_event(1, payload={}, channel="System", provider="Kernel-General", timestamp=BASE_TIME + timedelta(minutes=1))
        channels = set(item["channel"] for item in channel_coverage(read_events(write_builder(builder))))
        self.assertEqual(channels, {"Security", "System"})

    def test_histogram_counts_by_key(self):
        builder = EvtxBuilder(chunks=1)
        builder.add_event(4624, payload={}, timestamp=BASE_TIME)
        builder.add_event(4624, payload={}, timestamp=BASE_TIME + timedelta(seconds=1))
        builder.add_event(1102, payload={}, timestamp=BASE_TIME + timedelta(seconds=2))
        rows = histogram(read_events(write_builder(builder)), lambda event: event.event_id)
        counts = dict((row["key"], row["count"]) for row in rows)
        self.assertEqual(counts["4624"], 2)
        self.assertEqual(counts["1102"], 1)
        self.assertEqual(rows[0]["key"], "4624")


class AnalyzeTests(unittest.TestCase):
    def test_analyze_returns_a_report(self):
        builder = EvtxBuilder(chunks=1)
        builder.add_event(1102, payload={}, timestamp=BASE_TIME)
        report = analyze_path(write_builder(builder))
        self.assertEqual(len(report["events"]), 1)
        self.assertTrue(any(finding.rule_id == "EVT-LOG-CLEARED" for finding in report["findings"]))

    def test_min_severity_filters_findings(self):
        builder = EvtxBuilder(chunks=1)
        builder.add_event(4672, payload={"PrivilegeList": ("wstring", "SeDebugPrivilege")}, timestamp=BASE_TIME)
        quiet = analyze_path(write_builder(builder), min_severity="medium")
        self.assertEqual(quiet["findings"], [])

    def test_correlation_can_be_switched_off(self):
        builder = EvtxBuilder(chunks=1)
        for offset in range(6):
            builder.add_event(4625, payload={"TargetUserName": ("wstring", "alice")}, timestamp=BASE_TIME + timedelta(seconds=offset))
        with_correlation = analyze_path(write_builder(builder))
        without = analyze_path(write_builder(builder), correlate=False)
        self.assertIn("EVT-BRUTE-FORCE", set(finding.rule_id for finding in with_correlation["findings"]))
        self.assertNotIn("EVT-BRUTE-FORCE", set(finding.rule_id for finding in without["findings"]))

    def test_entities_appear_in_the_report(self):
        builder = EvtxBuilder(chunks=1)
        builder.add_event(4624, payload={"TargetUserName": ("wstring", "alice"), "IpAddress": ("wstring", "203.0.113.9")}, timestamp=BASE_TIME)
        report = analyze_path(write_builder(builder))
        self.assertIn("alice", report["entities"].accounts)
        self.assertIn("203.0.113.9", report["entities"].addresses)
        self.assertNotIn("203.0.113.9", report["entities"].private_addresses)


if __name__ == "__main__":
    unittest.main()
