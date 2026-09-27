# The pipeline that ties the layers together: open each log, parse events,
# harvest entities, run the static and correlation rules, build episodes, and
# return one dictionary that any renderer can print.

import os

from .correlations import CORRELATION_RULES
from .entities import Entities, harvest
from .evtxfile import EvtxFile
from .rules import SEVERITY_ORDER, evaluate
from .rules_data import RULES
from .timeline import activity_by_hour, build_episodes, busiest_episodes, channel_coverage, histogram, logon_sessions

# what the analysis uses unless the caller overrides it
DEFAULT_OPTIONS = {
    "gap_minutes": 15,
    "min_severity": "info",
    "max_events": 0,
    "recover": True,
    "correlate": True,
    "rules": (),
    "quiet": False,
}


def merged_options(options=None):
    merged = dict(DEFAULT_OPTIONS)
    if options:
        merged.update(options)
    return merged


def collect_paths(inputs):
    # accept files, directories and globs, return a sorted list of evtx files
    paths = []
    for item in inputs:
        if os.path.isdir(item):
            for root, _dirs, files in os.walk(item):
                for name in sorted(files):
                    if name.lower().endswith(".evtx"):
                        paths.append(os.path.join(root, name))
        else:
            paths.append(item)
    unique = []
    for path in sorted(paths):
        if path not in unique:
            unique.append(path)
    return unique


def load_file(path, options):
    # parse one log and return its events plus the structural facts about it
    events = []
    info = {
        "path": path,
        "size": os.path.getsize(path) if os.path.exists(path) else 0,
        "chunks": 0,
        "records": 0,
        "damaged": 0,
        "damage_notes": [],
        "channels": {},
        "header": {},
        "record_ids": [],
    }
    with EvtxFile(path, recover=options["recover"]) as log:
        info["header"] = log.header.describe()
        info["chunks"] = log.chunk_count()
        for event in log.events():
            if event.damaged:
                info["damaged"] += 1
                if len(info["damage_notes"]) < 5:
                    info["damage_notes"].append({"record_id": event.record_id, "problem": event.problem})
            info["records"] += 1
            channel = event.channel or "(none)"
            info["channels"][channel] = info["channels"].get(channel, 0) + 1
            info["record_ids"].append(event.record_id)
            events.append(event)
            if options["max_events"] and len(events) >= options["max_events"]:
                break
    info["first_record"] = info["record_ids"][0] if info["record_ids"] else None
    info["last_record"] = info["record_ids"][-1] if info["record_ids"] else None
    del info["record_ids"]
    return events, info


def rules_for_options(options):
    wanted = tuple(name.strip() for name in options.get("rules", ()) if name.strip())
    if not wanted:
        return list(RULES)
    return [rule for rule in RULES if rule.rule_id in wanted]


def analyze(paths, options=None):
    # the whole pipeline for a set of files
    options = merged_options(options)
    entities = Entities()
    events = []
    files = []
    for path in paths:
        file_events, info = load_file(path, options)
        files.append(info)
        for event in file_events:
            harvest(event, entities)
            events.append(event)
    findings = []
    if events:
        findings = evaluate(
            events,
            rules_for_options(options),
            CORRELATION_RULES if options["correlate"] else (),
            options,
            entities,
        )
    minimum = SEVERITY_ORDER.get(options["min_severity"], 0)
    findings = [finding for finding in findings if SEVERITY_ORDER.get(finding.severity, 0) >= minimum]
    episodes = build_episodes(events, findings, options["gap_minutes"])
    return {
        "files": files,
        "events": events,
        "findings": findings,
        "episodes": episodes,
        "entities": entities,
        "options": dict((key, value) for key, value in options.items() if key != "rules"),
    }


def summarize(report, limit=25):
    # the counts and lists a report leads with
    events = report["events"]
    findings = report["findings"]
    episodes = report["episodes"]
    dated = [event.timestamp for event in events if event.timestamp is not None]
    tally = {}
    for finding in findings:
        tally[finding.severity] = tally.get(finding.severity, 0) + 1
    techniques = {}
    for finding in findings:
        if finding.technique:
            techniques[finding.technique] = techniques.get(finding.technique, 0) + 1
    coverage = channel_coverage(events)
    return {
        "files": len(report["files"]),
        "events": len(events),
        "damaged_records": sum(info["damaged"] for info in report["files"]),
        "first_event": min(dated).isoformat(" ") if dated else "",
        "last_event": max(dated).isoformat(" ") if dated else "",
        "channels": len(coverage),
        "coverage": coverage,
        "findings": len(findings),
        "by_severity": tally,
        "by_technique": techniques,
        "episodes": len(episodes),
        "busiest": [episode.as_dict(max_findings=5) for episode in busiest_episodes(episodes, limit)],
        "sessions": logon_sessions(events),
        "entities": report["entities"].as_dict(),
        "entity_counts": report["entities"].counts(),
        "top_events": histogram(events, lambda event: event.event_id, 10),
        "top_computers": histogram(events, lambda event: event.computer, 10),
        "hourly": activity_by_hour(events),
    }
