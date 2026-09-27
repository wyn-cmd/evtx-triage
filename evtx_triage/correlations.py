# Correlation rules look at the stream as a whole instead of one event: repeated
# failures inside a window, a success that follows a run of failures, and gaps in
# a channel that suggest the log was stopped. They share the Finding type with the
# static rules so the report treats both the same way.

from datetime import datetime, timedelta

from .rules import Finding, SEVERITY_ORDER, event_id_of, normalise_ids, suspicious_address
from .rules_data import logon_type_of

# how many findings a single gap rule may raise, so a log with one long outage
# does not bury everything else
MAX_GAP_FINDINGS = 5


def ordered(events):
    # events in time order, undated ones last
    return sorted(events, key=lambda event: (event.timestamp is None, event.timestamp or datetime.max))


def window_seconds(value):
    return value.total_seconds() if hasattr(value, "total_seconds") else float(value)


def _duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return "%d seconds" % seconds
    if seconds < 3600:
        return "%d minutes" % (seconds // 60)
    if seconds < 86400:
        return "%d hours %d minutes" % (seconds // 3600, (seconds % 3600) // 60)
    return "%d days %d hours" % (seconds // 86400, (seconds % 86400) // 3600)


def _channel_matches(channel, name):
    channel = (channel or "").lower()
    wanted = (name or "").lower()
    return channel == wanted or channel.endswith("/" + wanted)


class WindowRule:
    # fires when threshold or more matching events land on the same key inside
    # the window, once per burst
    __slots__ = ("rule_id", "title", "severity", "technique", "event_ids", "channels", "key_fields", "threshold", "window", "predicate", "score", "account_field")

    def __init__(self, rule_id, title, severity, technique, event_ids, key_fields, threshold, window, channels=(), predicate=None, score=None, account_field=""):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.technique = technique
        self.event_ids = normalise_ids(event_ids)
        self.channels = tuple(channels)
        self.key_fields = tuple(key_fields)
        self.threshold = threshold
        self.window = window
        self.predicate = predicate
        self.score = score if score is not None else 10 * (SEVERITY_ORDER.get(severity, 0) + 1)
        self.account_field = account_field

    def applies(self, event):
        if self.channels and not any(event.channel_matches(name) for name in self.channels):
            return False
        if self.event_ids and event_id_of(event) not in self.event_ids:
            return False
        if self.predicate is not None and not self.predicate(event):
            return False
        return True

    def key_for(self, event):
        parts = []
        for field in self.key_fields:
            value = event.payload.get(field) or getattr(event, field, "")
            parts.append((value or "-").strip().lower())
        return tuple(parts)

    def examine(self, events, context=None):
        options = context.options if context is not None else {}
        threshold = int(options.get(self.rule_id + "_threshold", self.threshold))
        buckets = {}
        for event in events:
            if event.timestamp is None or not self.applies(event):
                continue
            buckets.setdefault(self.key_for(event), []).append(event)
        findings = []
        span = window_seconds(self.window)
        for key, group in buckets.items():
            group = ordered(group)
            start = 0
            reported = False
            for index, event in enumerate(group):
                cutoff = event.timestamp - timedelta(seconds=span)
                while start < index and group[start].timestamp < cutoff:
                    start += 1
                if index - start + 1 >= threshold and not reported:
                    findings.append(self.build_finding(group[start:index + 1], key))
                    reported = True
        return findings

    def build_finding(self, burst, key):
        last = burst[-1]
        first = burst[0]
        seconds = (last.timestamp - first.timestamp).total_seconds() if first.timestamp and last.timestamp else 0
        detail = "%d events in %s for %s" % (len(burst), _duration(seconds), " / ".join(item for item in key if item and item != "-"))
        account = last.payload.get(self.account_field) if self.account_field else last.primary_account()
        return Finding(
            self.rule_id,
            self.title,
            self.severity,
            self.technique,
            self.score,
            event=last,
            detail=detail,
            evidence={
                "count": len(burst),
                "first": first.timestamp.isoformat(" ") if first.timestamp else "",
                "last": last.timestamp.isoformat(" ") if last.timestamp else "",
                "first_record": first.record_id,
                "last_record": last.record_id,
                "key": list(key),
            },
            account=account or "",
            source_address=suspicious_address(last),
        )


class SequenceRule:
    # fires when a success for the same key follows a run of failures
    __slots__ = ("rule_id", "title", "severity", "technique", "failure_ids", "success_ids", "key_fields", "threshold", "window", "channels", "predicate", "success_predicate", "score")

    def __init__(self, rule_id, title, severity, technique, failure_ids, success_ids, key_fields, threshold, window, channels=(), predicate=None, success_predicate=None, score=None):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.technique = technique
        self.failure_ids = normalise_ids(failure_ids)
        self.success_ids = normalise_ids(success_ids)
        self.key_fields = tuple(key_fields)
        self.threshold = threshold
        self.window = window
        self.channels = tuple(channels)
        self.predicate = predicate
        self.success_predicate = success_predicate
        self.score = score if score is not None else 10 * (SEVERITY_ORDER.get(severity, 0) + 1)

    def key_for(self, event):
        return tuple((event.payload.get(field) or getattr(event, field, "") or "-").strip().lower() for field in self.key_fields)

    def relevant(self, event):
        if self.channels and not any(event.channel_matches(name) for name in self.channels):
            return False
        identifier = event_id_of(event)
        if identifier in self.failure_ids:
            return self.predicate is None or self.predicate(event)
        if identifier in self.success_ids:
            return self.success_predicate is None or self.success_predicate(event)
        return False

    def examine(self, events, context=None):
        options = context.options if context is not None else {}
        threshold = int(options.get(self.rule_id + "_threshold", self.threshold))
        span = window_seconds(self.window)
        failures = {}
        findings = []
        for event in ordered([item for item in events if item.timestamp is not None]):
            if not self.relevant(event):
                continue
            key = self.key_for(event)
            if event.event_id in self.failure_ids:
                failures.setdefault(key, []).append(event)
                continue
            cutoff = event.timestamp - timedelta(seconds=span)
            recent = [item for item in failures.get(key, []) if item.timestamp and item.timestamp >= cutoff]
            if len(recent) >= threshold:
                findings.append(self.build_finding(event, recent, key))
                failures[key] = []
        return findings

    def build_finding(self, success, failures, key):
        detail = "%d failed attempts before success as %s" % (len(failures), " / ".join(item for item in key if item and item != "-"))
        if success.event_id == "4624":
            detail += " (logon type %s)" % logon_type_of(success)
        return Finding(
            self.rule_id,
            self.title,
            self.severity,
            self.technique,
            self.score,
            event=success,
            detail=detail,
            evidence={
                "failures": len(failures),
                "first_failure": failures[0].timestamp.isoformat(" ") if failures else "",
                "last_failure": failures[-1].timestamp.isoformat(" ") if failures else "",
                "success_record": success.record_id,
                "key": list(key),
            },
            account=success.primary_account(),
            source_address=suspicious_address(success),
        )


class GapRule:
    # reports quiet stretches in a channel that had been busy, which is what a
    # stopped or cleared log looks like from the outside
    __slots__ = ("rule_id", "title", "severity", "technique", "minimum_gap", "channels", "score")

    def __init__(self, rule_id, title, severity, technique, minimum_gap, channels, score=4):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.technique = technique
        self.minimum_gap = minimum_gap
        self.channels = tuple(channels)
        self.score = score

    def examine(self, events, context=None):
        options = context.options if context is not None else {}
        minutes = float(options.get("gap_minutes", self.minimum_gap.total_seconds() / 60.0))
        if minutes <= 0:
            return []
        grouped = {}
        for event in events:
            if event.timestamp is None:
                continue
            grouped.setdefault(event.channel, []).append(event)
        findings = []
        for channel, group in grouped.items():
            if self.channels and not any(_channel_matches(channel, name) for name in self.channels):
                continue
            stream = ordered(group)
            if len(stream) < 4:
                continue
            gaps = []
            for earlier, later in zip(stream, stream[1:]):
                seconds = (later.timestamp - earlier.timestamp).total_seconds()
                if seconds >= minutes * 60:
                    gaps.append((seconds, earlier, later))
            gaps.sort(reverse=True)
            for seconds, earlier, later in gaps[:MAX_GAP_FINDINGS]:
                findings.append(
                    Finding(
                        self.rule_id,
                        self.title,
                        self.severity,
                        self.technique,
                        self.score,
                        event=later,
                        detail="%s went quiet for %s between records %s and %s" % (channel, _duration(seconds), earlier.record_id, later.record_id),
                        evidence={
                            "channel": channel,
                            "gap_seconds": int(seconds),
                            "before": earlier.timestamp.isoformat(" "),
                            "after": later.timestamp.isoformat(" "),
                            "before_record": earlier.record_id,
                            "after_record": later.record_id,
                        },
                        account=later.primary_account(),
                    )
                )
        return findings


# the correlation rules that ship with the tool
CORRELATION_RULES = (
    WindowRule(
        "EVT-BRUTE-FORCE",
        "Repeated authentication failures",
        "high",
        "T1110",
        (4625, 4771, 4776),
        ("TargetUserName", "IpAddress"),
        threshold=5,
        window=timedelta(minutes=10),
        channels=("Security",),
        account_field="TargetUserName",
    ),
    WindowRule(
        "EVT-LOCKOUT-STORM",
        "Repeated account lockouts",
        "medium",
        "T1110",
        (4740,),
        ("TargetUserName",),
        threshold=3,
        window=timedelta(minutes=15),
        channels=("Security",),
        account_field="TargetUserName",
    ),
    WindowRule(
        "EVT-PASSWORD-SPRAY",
        "Failed logons across many accounts from one address",
        "high",
        "T1110.003",
        (4625,),
        ("IpAddress",),
        threshold=8,
        window=timedelta(minutes=15),
        channels=("Security",),
        account_field="TargetUserName",
    ),
    SequenceRule(
        "EVT-SUCCESS-AFTER-FAILURES",
        "Successful logon after repeated failures",
        "critical",
        "T1078",
        (4625,),
        (4624,),
        ("TargetUserName",),
        threshold=3,
        window=timedelta(minutes=30),
        channels=("Security",),
        success_predicate=lambda event: logon_type_of(event) in ("interactive", "remote interactive", "network", "network cleartext"),
    ),
    GapRule(
        "EVT-CHANNEL-GAP",
        "Channel quiet period",
        "info",
        "T1070",
        minimum_gap=timedelta(minutes=120),
        channels=(),
    ),
)
