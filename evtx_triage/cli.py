# Command line entry point. Every subcommand reads evtx files, does one job, and
# writes either to stdout or to the file named by --output.

import argparse
import sys
from datetime import datetime

from . import __version__
from .errors import EvtxError
from .evtxfile import EvtxFile
from .report import render_dump, render_events_csv, render_findings_csv, render_json, render_markdown, render_text, severity_rank, write_output
from .rules import SEVERITY_NAMES
from .rules_data import RULES, RULE_INDEX
from .timeline import busiest_episodes, channel_coverage, logon_sessions
from .triage import analyze, collect_paths, merged_options, summarize


def build_parser():
    parser = argparse.ArgumentParser(prog="evtx-triage", description="Parse, verify and triage Windows event logs without any dependencies.")
    parser.add_argument("--version", action="version", version="evtx-triage %s" % __version__)
    subparsers = parser.add_subparsers(dest="command")

    info = subparsers.add_parser("info", help="header, chunk and record facts for each file")
    info.add_argument("targets", nargs="+", help="evtx files or directories holding them")
    info.add_argument("--json", action="store_true", help="print the facts as json")

    verify = subparsers.add_parser("verify", help="checksum, structure and damage check")
    verify.add_argument("targets", nargs="+")
    verify.add_argument("--json", action="store_true")
    verify.add_argument("--no-recover", action="store_true", help="stop at the first damaged record instead of recovering")

    dump = subparsers.add_parser("dump", help="print the events as xml, json or csv")
    dump.add_argument("targets", nargs="+")
    dump.add_argument("--format", choices=("xml", "xml-pretty", "json", "csv"), default="xml")
    dump.add_argument("--event-id", action="append", default=[], help="only this event id, repeatable")
    dump.add_argument("--channel", action="append", default=[], help="only this channel, repeatable")
    dump.add_argument("--grep", default="", help="only events whose text contains this")
    dump.add_argument("--since", default="", help="earliest timestamp to include")
    dump.add_argument("--until", default="", help="latest timestamp to include")
    dump.add_argument("--limit", type=int, default=0, help="stop after this many events")
    dump.add_argument("--output", default="")

    triage = subparsers.add_parser("triage", help="run the rules and print a report")
    triage.add_argument("targets", nargs="+")
    triage.add_argument("--format", choices=("text", "json", "markdown", "csv", "findings-csv"), default="text")
    triage.add_argument("--min-severity", choices=SEVERITY_NAMES, default="info")
    triage.add_argument("--gap", type=float, default=15.0, help="minutes of quiet that split episodes")
    triage.add_argument("--rule", action="append", default=[], help="only this rule id, repeatable")
    triage.add_argument("--no-correlate", action="store_true")
    triage.add_argument("--no-recover", action="store_true")
    triage.add_argument("--include-events", action="store_true", help="add parsed events to the json output")
    triage.add_argument("--max-events", type=int, default=0)
    triage.add_argument("--output", default="")

    timeline = subparsers.add_parser("timeline", help="episodes and sessions in time order")
    timeline.add_argument("targets", nargs="+")
    timeline.add_argument("--gap", type=float, default=15.0)
    timeline.add_argument("--limit", type=int, default=20)
    timeline.add_argument("--json", action="store_true")
    timeline.add_argument("--output", default="")

    entities = subparsers.add_parser("entities", help="accounts, hosts, addresses and objects seen")
    entities.add_argument("targets", nargs="+")
    entities.add_argument("--json", action="store_true")
    entities.add_argument("--output", default="")

    stats = subparsers.add_parser("stats", help="event id, channel and provider histograms")
    stats.add_argument("targets", nargs="+")
    stats.add_argument("--limit", type=int, default=15)
    stats.add_argument("--json", action="store_true")

    rules = subparsers.add_parser("rules", help="list the rules or describe one")
    rules.add_argument("rule_id", nargs="?", default="")
    rules.add_argument("--json", action="store_true")
    return parser


def parse_moment(text):
    # a permissive timestamp, date only or date and time, treated as utc
    text = (text or "").strip()
    if not text:
        return None
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, pattern)
        except ValueError:
            continue
    return None


def filter_events(events, args):
    # apply the dump filters in a single pass
    since = parse_moment(getattr(args, "since", ""))
    until = parse_moment(getattr(args, "until", ""))
    wanted_ids = set(getattr(args, "event_id", []) or ())
    wanted_channels = [name.lower() for name in (getattr(args, "channel", []) or ())]
    needle = (getattr(args, "grep", "") or "").lower()
    limit = getattr(args, "limit", 0) or 0
    selected = []
    for event in events:
        if wanted_ids and str(event.event_id) not in wanted_ids:
            continue
        if wanted_channels and not any(event.channel_matches(name) for name in wanted_channels):
            continue
        if since and (event.timestamp is None or event.timestamp < since):
            continue
        if until and (event.timestamp is None or event.timestamp > until):
            continue
        if needle and needle not in event.searchable_text().lower():
            continue
        selected.append(event)
        if limit and len(selected) >= limit:
            break
    return selected


def command_info(args):
    for path in collect_paths(args.targets):
        with EvtxFile(path, recover=True) as log:
            facts = log.info()
            facts["stats"] = log.stats()
        facts["path"] = path
        if args.json:
            write_output(__import__("json").dumps(facts, indent=2, default=str))
            continue
        write_output("FILE %s" % path)
        for key in sorted(facts):
            if key in ("path", "header"):
                continue
            if key == "stats":
                for sub_key in sorted(facts[key]):
                    write_output("  stats.%-22s %s" % (sub_key, facts[key][sub_key]))
                continue
            write_output("  %-22s %s" % (key, facts[key]))
        for key in sorted(facts.get("header", {})):
            write_output("  header.%-15s %s" % (key, facts["header"][key]))
    return 0


def command_verify(args):
    problems = 0
    documents = []
    for path in collect_paths(args.targets):
        with EvtxFile(path, recover=not args.no_recover) as log:
            verification = log.verify()
            damage = log.damage_report()
        documents.append({"path": path, "verification": verification, "damage": damage})
        if not verification.get("ok", False):
            problems += 1
    if args.json:
        write_output(__import__("json").dumps(documents, indent=2, default=str))
        return 1 if problems else 0
    for document in documents:
        print_verification(document)
    return 1 if problems else 0


def print_verification(document):
    # one compact block per file: the header facts, a line per chunk, the
    # damaged regions, and the totals. everything the table leaves out is still
    # available with --json
    verification = document["verification"]
    header = verification.get("header", {})
    chunks = verification.get("chunks", [])
    write_output("FILE  %s" % document["path"])
    write_output("      format %s, %s bytes, %s chunks, header checksum %s" % (
        header.get("format", "?"),
        verification.get("file_size", 0),
        header.get("chunk_count", 0),
        "ok" if verification.get("header_checksum_ok") else "MISMATCH",
    ))
    write_output("      oldest chunk %s, current chunk %s, next record id %s, flags %s" % (
        header.get("oldest_chunk", "?"),
        header.get("current_chunk_number", "?"),
        header.get("next_record_number", "?"),
        ", ".join(header.get("flag_names") or []) or "none",
    ))
    write_output("")
    write_output("      %5s %11s %9s %9s %7s %6s %7s  %s" % (
        "chunk", "offset", "records", "readable", "header", "data", "slack", "state",
    ))
    for chunk in chunks:
        claimed = chunk.get("records_claimed", 0)
        readable = chunk.get("records_readable", 0)
        if chunk.get("empty"):
            state = "empty"
        elif chunk.get("header_checksum_ok") and chunk.get("data_checksum_ok"):
            state = "ok"
        else:
            state = "checksum mismatch"
        write_output("      %5d %11s %9d %9d %7s %6s %7d  %s" % (
            chunk.get("index", 0),
            "0x%08x" % chunk.get("file_offset", 0),
            claimed,
            readable,
            "ok" if chunk.get("header_checksum_ok") else "BAD",
            "ok" if chunk.get("data_checksum_ok") else "BAD",
            chunk.get("slack_bytes", 0),
            state,
        ))
    claimed = sum(chunk.get("records_claimed", 0) for chunk in chunks)
    readable = sum(chunk.get("records_readable", 0) for chunk in chunks)
    slack = sum(chunk.get("slack_bytes", 0) for chunk in chunks)
    write_output("")
    write_output("      totals: %d chunks, %d records declared, %d readable, %d damaged, %d bytes of slack" % (
        len(chunks), claimed, readable, claimed - readable, slack,
    ))
    damage = document.get("damage") or []
    if not damage:
        write_output("      damage: none")
        return
    write_output("      damage: %d region%s" % (len(damage), "" if len(damage) == 1 else "s"))
    for entry in damage:
        write_output("        0x%08x  %6d bytes  %s" % (
            entry.get("offset", 0), entry.get("size", 0), entry.get("reason", ""),
        ))


def command_dump(args):
    events = []
    for path in collect_paths(args.targets):
        with EvtxFile(path, recover=True) as log:
            events.extend(log.events())
    events = filter_events(events, args)
    if args.format == "csv":
        text = render_events_csv(events)
    elif args.format == "json":
        text = __import__("json").dumps([event.as_dict() for event in events], indent=2, default=str)
    else:
        text = render_dump(events, pretty=args.format == "xml-pretty", limit=args.limit)
    write_output(text, args.output or None)
    return 0


def command_triage(args):
    paths = collect_paths(args.targets)
    options = merged_options(
        {
            "gap_minutes": args.gap,
            "min_severity": args.min_severity,
            "max_events": args.max_events,
            "recover": not args.no_recover,
            "correlate": not args.no_correlate,
            "rules": tuple(args.rule),
        }
    )
    report = analyze(paths, options)
    summary = summarize(report)
    if args.format == "json":
        text = render_json(report, summary, include_events=args.include_events)
    elif args.format == "markdown":
        text = render_markdown(report, summary)
    elif args.format == "csv":
        text = render_events_csv(report["events"])
    elif args.format == "findings-csv":
        text = render_findings_csv(report["findings"])
    else:
        text = render_text(report, summary)
    write_output(text, args.output or None)
    return 1 if any(severity_rank(finding.severity) >= severity_rank("medium") for finding in report["findings"]) else 0


def command_timeline(args):
    report = analyze(collect_paths(args.targets), merged_options({"gap_minutes": args.gap}))
    episodes = busiest_episodes(report["episodes"], args.limit)
    if args.json:
        text = __import__("json").dumps([episode.as_dict() for episode in episodes], indent=2, default=str)
    else:
        lines = ["EPISODES (busiest first)", "=" * 72]
        for episode in episodes:
            lines.append("#%d %s -> %s  score %d  worst %s" % (episode.index, episode.start, episode.end, episode.score, episode.worst_severity()))
            lines.append("    %d events, %d findings, hosts %s" % (len(episode.events), len(episode.findings), ",".join(sorted(episode.hosts)) or "-"))
            for finding in episode.findings[:10]:
                lines.append("    - %s [%s] %s" % (finding.timestamp, finding.severity, finding.title))
        lines.append("")
        lines.append("LOGON SESSIONS")
        for session in logon_sessions(report["events"])[: args.limit]:
            lines.append("  %s on %s from %s, %s min, closed %s" % (session["account"] or "-", session["host"] or "-", session["address"] or "-", session["minutes"], session["closed"] or "still open"))
        lines.append("")
        lines.append("CHANNEL COVERAGE")
        for row in channel_coverage(report["events"]):
            lines.append("  %-40s %6d  %s -> %s" % (row["channel"][:40], row["events"], row["first"][:19], row["last"][:19]))
        text = "\n".join(lines) + "\n"
    write_output(text, args.output or None)
    return 0


def command_entities(args):
    report = analyze(collect_paths(args.targets), merged_options())
    entities = report["entities"]
    if args.json:
        text = __import__("json").dumps(entities.as_dict(), indent=2, default=str)
    else:
        lines = ["ENTITIES", "=" * 72]
        counts = entities.counts()
        lines.append("accounts %d, hosts %d, addresses %d, processes %d, services %d, tasks %d, shares %d" % (
            counts["accounts"], counts["hosts"], counts["addresses"], counts["processes"], counts["services"], counts["tasks"], counts["shares"]))
        for label in ("accounts", "hosts", "addresses", "domains", "processes", "services", "tasks", "shares", "objects"):
            values = sorted(getattr(entities, label))
            if values:
                lines.append("")
                lines.append("%s (%d)" % (label.upper(), len(values)))
                for value in values[:60]:
                    lines.append("  %s" % value)
        text = "\n".join(lines) + "\n"
    write_output(text, args.output or None)
    return 0


def command_stats(args):
    report = analyze(collect_paths(args.targets), merged_options())
    summary = summarize(report)
    lines = ["EVENT IDS", "=" * 72]
    for row in summary["top_events"][: args.limit]:
        lines.append("  %-10s %6d" % (row["key"] or "(none)", row["count"]))
    lines.append("")
    lines.append("CHANNELS")
    for row in summary["coverage"][: args.limit]:
        lines.append("  %-44s %6d" % (row["channel"][:44], row["events"]))
    lines.append("")
    lines.append("COMPUTERS")
    for row in summary["top_computers"][: args.limit]:
        lines.append("  %-44s %6d" % (row["key"] or "(none)", row["count"]))
    write_output("\n".join(lines) + "\n")
    return 0


def command_rules(args):
    if not args.rule_id:
        if args.json:
            write_output(__import__("json").dumps([{"rule_id": rule.rule_id, "title": rule.title, "severity": rule.severity, "technique": rule.technique, "event_ids": sorted(rule.event_ids)} for rule in RULES], indent=2))
            return 0
        write_output("RULES (%d)" % len(RULES))
        for rule in RULES:
            write_output("  %-28s %-8s %-12s %s" % (rule.rule_id, rule.severity, rule.technique, rule.title))
        return 0
    rule = RULE_INDEX.get(args.rule_id)
    if rule is None:
        write_output("no rule with id %s" % args.rule_id)
        return 2
    write_output("RULE %s" % rule.rule_id)
    write_output("  title      %s" % rule.title)
    write_output("  severity   %s" % rule.severity)
    write_output("  technique  %s" % rule.technique)
    write_output("  event ids  %s" % ", ".join(sorted(rule.event_ids)))
    write_output("  channels   %s" % (", ".join(rule.channels) or "any"))
    write_output("  score      %d" % rule.score)
    if rule.detail_fields:
        write_output("  fields     %s" % ", ".join(rule.detail_fields))
    if rule.description:
        write_output("  about      %s" % rule.description)
    if rule.tags:
        write_output("  tags       %s" % ", ".join(rule.tags))
    return 0


COMMANDS = {
    "info": command_info,
    "verify": command_verify,
    "dump": command_dump,
    "triage": command_triage,
    "timeline": command_timeline,
    "entities": command_entities,
    "stats": command_stats,
    "rules": command_rules,
}


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    try:
        return COMMANDS[args.command](args)
    except (OSError, EvtxError) as problem:
        # a bad path or an unreadable file is a normal outcome for a command
        # line tool, so it is reported on one line instead of as a traceback
        write_output("evtx-triage: %s" % problem)
        return 1


if __name__ == "__main__":
    sys.exit(main())
