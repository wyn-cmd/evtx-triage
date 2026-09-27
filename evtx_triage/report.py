# Renderers. The same analysis is printed as plain text for a terminal, as JSON
# for anything downstream, as CSVs for a spreadsheet, and as markdown for a
# writeup. Nothing here reads the logs again, it only formats what it is handed.

import csv
import io
import json
from datetime import datetime

from .helpers import isoformat
from .rules import SEVERITY_NAMES, SEVERITY_ORDER
from .triage import summarize

SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def _seconds_text(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return "%ds" % seconds
    if seconds < 3600:
        return "%dm" % (seconds // 60)
    if seconds < 86400:
        return "%dh%dm" % (seconds // 3600, (seconds % 3600) // 60)
    return "%dd%dh" % (seconds // 86400, (seconds % 86400) // 3600)


def _bar(count, largest, width=24):
    if not largest:
        return ""
    filled = int(round(width * count / float(largest)))
    return "#" * max(filled, 1 if count else 0)


def severity_tally(findings):
    # ordered worst first, including the severities that saw nothing
    tally = dict((name, 0) for name in SEVERITY_NAMES)
    for finding in findings:
        tally[finding.severity] = tally.get(finding.severity, 0) + 1
    return tally


def technique_tally(findings):
    counts = {}
    for finding in findings:
        if finding.technique:
            counts[finding.technique] = counts.get(finding.technique, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def render_text(report, summary=None):
    # the human facing report: what was read, what was found, in what order
    summary = summary if summary is not None else summarize(report)
    lines = []
    lines.append("EVTX TRIAGE REPORT")
    lines.append("=" * 72)
    lines.append("generated      : %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("files          : %d" % summary["files"])
    lines.append("events parsed  : %d" % summary["events"])
    lines.append("damaged records: %d" % summary["damaged_records"])
    if summary["first_event"]:
        lines.append("window         : %s -> %s" % (summary["first_event"], summary["last_event"]))
    lines.append("findings       : %d" % summary["findings"])
    lines.append("")
    for info in report["files"]:
        header = info["header"]
        lines.append("- %s" % info["path"])
        lines.append("    %s, %d bytes, %d chunks, %d records, %d damaged" % (header.get("format", "?"), info["size"], info["chunks"], info["records"], info["damaged"]))
        flags = ", ".join(header.get("flag_names", ())) or "none"
        lines.append("    flags: %s, wrapped: %s, checksum ok: %s" % (flags, header.get("wrapped"), header.get("checksum_ok")))
        for note in info["damage_notes"]:
            lines.append("    damage: record %s: %s" % (note["record_id"], note["problem"]))
    lines.append("")
    lines.append("SEVERITY")
    tally = severity_tally(report["findings"])
    largest = max(tally.values()) if tally else 0
    for name in ("critical", "high", "medium", "low", "info"):
        lines.append("  %-9s %4d  %s" % (name, tally.get(name, 0), _bar(tally.get(name, 0), largest)))
    if summary["by_technique"]:
        lines.append("")
        lines.append("MITRE ATT&CK TECHNIQUES")
        for technique, count in sorted(summary["by_technique"].items(), key=lambda item: -item[1]):
            lines.append("  %-14s %4d" % (technique, count))
    lines.append("")
    lines.append("CHANNEL COVERAGE")
    for row in summary["coverage"]:
        lines.append("  %-44s %6d  %s -> %s  quiet %s" % (row["channel"][:44], row["events"], row["first"][:19], row["last"][:19], _seconds_text(row["longest_gap_seconds"])))
    lines.append("")
    lines.append("FINDINGS")
    if not report["findings"]:
        lines.append("  none")
    for finding in report["findings"]:
        lines.append("  [%s] %s  %s" % (SEVERITY_LABELS.get(finding.severity, finding.severity), finding.rule_id, finding.title))
        lines.append("      %s  event %s  channel %s  host %s" % (isoformat(finding.timestamp) or "?", finding.event_id, finding.channel or "-", finding.computer or "-"))
        if finding.technique:
            lines.append("      technique %s, score %d" % (finding.technique, finding.score))
        if finding.account or finding.source_address:
            lines.append("      account %s  source %s" % (finding.account or "-", finding.source_address or "-"))
        if finding.detail:
            lines.append("      %s" % finding.detail[:200])
    lines.append("")
    lines.append("EPISODES (busiest first)")
    if not summary["busiest"]:
        lines.append("  none")
    for episode in summary["busiest"]:
        lines.append("  #%d %s -> %s  worst %s" % (episode["index"], episode["start"][:19], episode["end"][:19], episode["worst_severity"]))
        lines.append("      %d events, %d findings, score %d, hosts %s" % (episode["events"], len(episode["findings"]), episode["score"], ",".join(episode["hosts"]) or "-"))
        lines.append("      accounts %s" % (",".join(episode["accounts"][:6]) or "-"))
        if episode["addresses"]:
            lines.append("      addresses %s" % ",".join(episode["addresses"][:6]))
        for finding in episode["findings"][:6]:
            lines.append("      - %s %s" % (finding["rule_id"], finding["detail"][:120]))
    counts = summary["entity_counts"]
    lines.append("")
    lines.append("ENTITIES")
    lines.append("  accounts %d, hosts %d, addresses %d, processes %d, services %d, tasks %d, shares %d" % (
        counts["accounts"], counts["hosts"], counts["addresses"], counts["processes"], counts["services"], counts["tasks"], counts["shares"]))
    entities = summary["entities"]
    for label in ("accounts", "hosts", "addresses", "services", "tasks", "shares"):
        values = entities[label]
        if values:
            lines.append("  %s: %s" % (label, ", ".join(values[:12]) + (" ..." if len(values) > 12 else "")))
    if summary["sessions"]:
        lines.append("")
        lines.append("LOGON SESSIONS")
        for session in summary["sessions"][:20]:
            lines.append("  %s on %s from %s, %s min, closed %s" % (session["account"] or "-", session["host"] or "-", session["address"] or "-", session["minutes"], session["closed"] or "still open"))
    lines.append("")
    lines.append("TOP EVENT IDS")
    for row in summary["top_events"]:
        lines.append("  %-10s %6d" % (row["key"] or "(none)", row["count"]))
    hourly = summary["hourly"]
    if any(hourly):
        lines.append("")
        lines.append("ACTIVITY BY HOUR (UTC)")
        peak = max(hourly)
        for hour, count in enumerate(hourly):
            if count:
                lines.append("  %02d:00 %6d %s" % (hour, count, _bar(count, peak, 30)))
    return "\n".join(lines) + "\n"


def render_json(report, summary=None, include_events=False, max_events=500):
    # a stable document: summary first, then findings, episodes and entities
    summary = summary if summary is not None else summarize(report)
    document = {
        "tool": "evtx-triage",
        "generated": datetime.now().isoformat(" ", "seconds"),
        "files": report["files"],
        "summary": summary,
        "findings": [finding.as_dict() for finding in report["findings"]],
        "episodes": [episode.as_dict() for episode in report["episodes"]],
        "entities": report["entities"].as_dict(),
    }
    if include_events:
        document["events"] = [event.as_dict() for event in report["events"][:max_events]]
    return json.dumps(document, indent=2, sort_keys=False, default=str)


def render_markdown(report, summary=None):
    # the same content as the text report, shaped for a ticket or a writeup
    summary = summary if summary is not None else summarize(report)
    lines = []
    lines.append("# Windows event log triage")
    lines.append("")
    lines.append("- generated: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("- files: %d" % summary["files"])
    lines.append("- events: %d" % summary["events"])
    lines.append("- window: %s to %s" % (summary["first_event"] or "-", summary["last_event"] or "-"))
    lines.append("- findings: %d" % summary["findings"])
    lines.append("")
    lines.append("## Severity")
    lines.append("")
    lines.append("| severity | count |")
    lines.append("| --- | --- |")
    tally = severity_tally(report["findings"])
    for name in ("critical", "high", "medium", "low", "info"):
        lines.append("| %s | %d |" % (name, tally.get(name, 0)))
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not report["findings"]:
        lines.append("No rule fired.")
    for finding in report["findings"]:
        lines.append("### %s %s" % (SEVERITY_LABELS.get(finding.severity, finding.severity), finding.title))
        lines.append("")
        lines.append("- rule: `%s`" % finding.rule_id)
        lines.append("- technique: %s" % (finding.technique or "-"))
        lines.append("- time: %s" % (isoformat(finding.timestamp) or "?"))
        lines.append("- event: %s on %s" % (finding.event_id, finding.channel or "-"))
        lines.append("- host: %s" % (finding.computer or "-"))
        if finding.account:
            lines.append("- account: %s" % finding.account)
        if finding.source_address:
            lines.append("- source: %s" % finding.source_address)
        if finding.detail:
            lines.append("- detail: %s" % finding.detail)
        lines.append("")
    lines.append("## Channel coverage")
    lines.append("")
    lines.append("| channel | events | first | last | longest quiet |")
    lines.append("| --- | --- | --- | --- | --- |")
    for row in summary["coverage"]:
        lines.append("| %s | %d | %s | %s | %s |" % (row["channel"], row["events"], row["first"], row["last"], _seconds_text(row["longest_gap_seconds"])))
    return "\n".join(lines) + "\n"


def render_events_csv(events, fields=None):
    # one row per event, payload flattened into sorted key=value pairs
    buffer = io.StringIO()
    columns = fields or ("timestamp", "record_id", "channel", "provider", "event_id", "computer", "payload")
    writer = csv.DictWriter(buffer, fieldnames=list(columns), extrasaction="ignore")
    writer.writeheader()
    for event in events:
        writer.writerow(
            {
                "timestamp": isoformat(event.timestamp),
                "record_id": event.record_id,
                "channel": event.channel,
                "provider": event.provider,
                "event_id": event.event_id,
                "computer": event.computer,
                "payload": " ".join("%s=%s" % (key, event.payload[key]) for key in sorted(event.payload)),
            }
        )
    return buffer.getvalue()


def render_findings_csv(findings):
    # one row per finding, evidence flattened
    buffer = io.StringIO()
    columns = ("timestamp", "severity", "rule_id", "title", "technique", "score", "event_id", "channel", "computer", "account", "source_address", "detail")
    writer = csv.DictWriter(buffer, fieldnames=list(columns), extrasaction="ignore")
    writer.writeheader()
    for finding in findings:
        writer.writerow(finding.as_dict())
    return buffer.getvalue()


def render_dump(events, pretty=False, limit=0):
    # the raw event xml, one event after the other
    from .render import render_pretty, render_xml

    parts = []
    for index, event in enumerate(events):
        if limit and index >= limit:
            break
        parts.append(render_pretty(event.nodes) if pretty else render_xml(event.nodes))
    return "\n".join(parts) + ("\n" if parts else "")


def write_output(text, path=None):
    # print or write, returning the text either way so callers can chain
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        print(text, end="" if text.endswith("\n") else "\n")
    return text


def severity_rank(name):
    return SEVERITY_ORDER.get(name, 0)
