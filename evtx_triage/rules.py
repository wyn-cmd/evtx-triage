# The rule engine. A rule is a small declaration: which channels and event ids it
# cares about, an optional predicate over the parsed payload, and how serious a
# hit is. Correlation rules look at a whole stream instead of one event.

import re

from .entities import IPV4, is_private

# ordered worst first, used for filtering and for the report ordering
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_NAMES = ("info", "low", "medium", "high", "critical")


class Finding:
    # one rule hit, tied to the event that caused it
    __slots__ = ("rule_id", "title", "severity", "technique", "score", "event_id", "channel", "computer", "timestamp", "detail", "evidence", "account", "source_address")

    def __init__(self, rule_id, title, severity, technique, score, event=None, detail="", evidence=None, account="", source_address=""):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.technique = technique
        self.score = score
        self.detail = detail
        self.evidence = evidence or {}
        if event is not None:
            self.event_id = event.event_id
            self.channel = event.channel
            self.computer = event.computer
            self.timestamp = event.timestamp
        else:
            self.event_id = ""
            self.channel = ""
            self.computer = ""
            self.timestamp = None
        self.account = account
        self.source_address = source_address

    def __repr__(self):
        return "Finding(%s, %s, %s)" % (self.rule_id, self.severity, self.event_id)

    def as_dict(self):
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "technique": self.technique,
            "score": self.score,
            "event_id": self.event_id,
            "channel": self.channel,
            "computer": self.computer,
            "timestamp": self.timestamp.isoformat(" ") if self.timestamp else "",
            "account": self.account,
            "source_address": self.source_address,
            "detail": self.detail,
            "evidence": self.evidence,
        }


def matches_any(value, patterns):
    # case insensitive substring search over a list of patterns
    text = (value or "").lower()
    for pattern in patterns:
        if pattern in text:
            return True
    return False


def regex_any(value, patterns):
    text = value or ""
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def event_id_of(event):
    # event ids are compared as text because a record stores them as text and a
    # rule should not care whether it was written as 4624 or "4624"
    return str(event.event_id).strip()


def normalise_ids(values):
    return set(str(value).strip() for value in values)


class Rule:
    # a single event rule
    __slots__ = ("rule_id", "title", "severity", "technique", "channels", "event_ids", "predicate", "score", "detail_fields", "description", "tags")

    def __init__(self, rule_id, title, severity, technique, event_ids, channels=(), predicate=None, score=None, detail_fields=(), description="", tags=()):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.technique = technique
        self.event_ids = normalise_ids(event_ids)
        self.channels = tuple(channels)
        self.predicate = predicate
        self.score = score if score is not None else 10 * (SEVERITY_ORDER.get(severity, 0) + 1)
        self.detail_fields = tuple(detail_fields)
        self.description = description
        self.tags = tuple(tags)

    def applies(self, event):
        # channel filter first, then event id, then the custom predicate
        if self.channels and not any(event.channel_matches(name) for name in self.channels):
            return False
        if self.event_ids and event_id_of(event) not in self.event_ids:
            return False
        if self.predicate is not None and not self.predicate(event):
            return False
        return True

    def detail_for(self, event):
        # pull the declared fields out of the payload in order, skipping empties
        parts = []
        for field in self.detail_fields:
            value = event.payload.get(field)
            if value:
                parts.append("%s=%s" % (field, value.strip()))
        return "; ".join(parts)

    def make_finding(self, event, detail=None, score=None, account="", source_address=""):
        return Finding(
            self.rule_id,
            self.title,
            self.severity,
            self.technique,
            self.score if score is None else score,
            event=event,
            detail=self.detail_for(event) if detail is None else detail,
            evidence={"event_id": event.event_id, "record_id": event.record_id, "channel": event.channel},
            account=account or event.primary_account(),
            source_address=source_address,
        )


class RuleContext:
    # per run state shared by the rules, mostly counters and the clock window
    __slots__ = ("options", "entities", "counters", "notes")

    def __init__(self, options=None, entities=None):
        self.options = options or {}
        self.entities = entities
        self.counters = {}
        self.notes = []

    def option(self, name, default=None):
        return self.options.get(name, default)

    def bump(self, key, amount=1):
        self.counters[key] = self.counters.get(key, 0) + amount
        return self.counters[key]


def evaluate(events, rules, correlation_rules=(), options=None, entities=None):
    # run every static rule over the stream, then the correlation rules, and
    # return findings worst first
    context = RuleContext(options, entities)
    findings = []
    for event in events:
        for rule in rules:
            if rule.applies(event):
                findings.append(rule.make_finding(event))
    for rule in correlation_rules:
        findings.extend(rule.examine(events, context))
    findings.sort(key=lambda item: -item.score)
    return findings


def suspicious_address(event):
    # the remote address of an event, ignoring placeholder values
    address = event.payload.get("IpAddress") or event.payload.get("SourceAddress") or event.payload.get("Address") or ""
    address = address.strip()
    if not address or address in ("-", "::1", "127.0.0.1", "0.0.0.0"):
        return ""
    return address


def public_addresses(events):
    # addresses seen outside private space, the ones worth a second look
    seen = set()
    for event in events:
        for key, value in event.payload.items():
            if not value:
                continue
            if key.lower() in ("ipaddress", "sourceaddress", "destinationaddress", "clientaddress"):
                for candidate in IPV4.findall(value):
                    if not is_private(candidate):
                        seen.add(candidate)
    return sorted(seen)
