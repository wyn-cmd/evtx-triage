# Timeline building: turns a flat stream of events and findings into episodes,
# that is, bursts of activity separated by quiet stretches, plus the coverage
# facts and logon sessions a report wants to state up front.

from datetime import timedelta

from .correlations import ordered
from .rules import SEVERITY_ORDER
from .rules_data import logon_type_of


class Episode:
    # a run of activity with the findings that landed inside it
    __slots__ = ("index", "start", "end", "events", "findings", "hosts", "accounts", "addresses", "techniques", "channels", "score")

    def __init__(self, index, events):
        self.index = index
        self.events = list(events)
        self.findings = []
        self.start = self.events[0].timestamp if self.events else None
        self.end = self.events[-1].timestamp if self.events else None
        self.hosts = set()
        self.accounts = set()
        self.addresses = set()
        self.techniques = set()
        self.channels = set()
        self.score = 0
        self.absorb()

    def absorb(self):
        for event in self.events:
            if event.computer:
                self.hosts.add(event.computer)
            account = event.primary_account()
            if account:
                self.accounts.add(account)
            for key in ("IpAddress", "SourceAddress", "ClientAddress"):
                value = (event.payload.get(key) or "").strip()
                if value and value != "-":
                    self.addresses.add(value)
            if event.channel:
                self.channels.add(event.channel)

    def add_findings(self, findings):
        # findings belong to the episode whose time span contains them
        if self.start is None or self.end is None:
            return
        for finding in findings:
            if finding.timestamp is None:
                continue
            if self.start <= finding.timestamp <= self.end:
                self.findings.append(finding)
                self.techniques.add(finding.technique)
                self.score += finding.score

    def worst_severity(self):
        worst = "info"
        for finding in self.findings:
            if SEVERITY_ORDER.get(finding.severity, 0) > SEVERITY_ORDER.get(worst, 0):
                worst = finding.severity
        return worst

    def duration_minutes(self):
        if not self.start or not self.end:
            return 0.0
        return (self.end - self.start).total_seconds() / 60.0

    def summary(self):
        return "%s to %s (%d events, %d findings, score %d)" % (
            self.start.isoformat(" ") if self.start else "?",
            self.end.isoformat(" ") if self.end else "?",
            len(self.events),
            len(self.findings),
            self.score,
        )

    def as_dict(self, max_findings=20):
        return {
            "index": self.index,
            "start": self.start.isoformat(" ") if self.start else "",
            "end": self.end.isoformat(" ") if self.end else "",
            "duration_minutes": round(self.duration_minutes(), 2),
            "events": len(self.events),
            "score": self.score,
            "worst_severity": self.worst_severity(),
            "hosts": sorted(self.hosts),
            "accounts": sorted(self.accounts),
            "addresses": sorted(self.addresses),
            "channels": sorted(self.channels),
            "techniques": sorted(self.techniques),
            "findings": [finding.as_dict() for finding in self.findings[:max_findings]],
        }


def build_episodes(events, findings, gap_minutes=15):
    # split the stream wherever nothing happened for a while, then attach findings
    stream = ordered([event for event in events if event.timestamp is not None])
    if not stream:
        return []
    gap = timedelta(minutes=gap_minutes)
    groups = [[stream[0]]]
    for event in stream[1:]:
        if event.timestamp - groups[-1][-1].timestamp > gap:
            groups.append([event])
        else:
            groups[-1].append(event)
    episodes = []
    for index, group in enumerate(groups, start=1):
        episode = Episode(index, group)
        episode.add_findings(findings)
        episodes.append(episode)
    return episodes


def busiest_episodes(episodes, limit=5):
    # the episodes carrying the most signal, score first
    return sorted(episodes, key=lambda item: (-item.score, -len(item.findings)))[:limit]


def channel_coverage(events):
    # per channel: event count, the window it covers, and its longest quiet stretch
    grouped = {}
    for event in events:
        grouped.setdefault(event.channel or "(none)", []).append(event)
    rows = []
    for channel, group in grouped.items():
        stream = ordered([event for event in group if event.timestamp is not None])
        longest = 0
        if len(stream) > 1:
            longest = max((later.timestamp - earlier.timestamp).total_seconds() for earlier, later in zip(stream, stream[1:]))
        providers = sorted(set(event.provider for event in group if event.provider))
        rows.append(
            {
                "channel": channel,
                "events": len(group),
                "first": stream[0].timestamp.isoformat(" ") if stream else "",
                "last": stream[-1].timestamp.isoformat(" ") if stream else "",
                "longest_gap_seconds": int(longest),
                "providers": providers[:4],
            }
        )
    rows.sort(key=lambda row: -row["events"])
    return rows


def logon_sessions(events):
    # pair remote logons with the session close events that follow them
    sessions = []
    open_sessions = {}
    for event in ordered([item for item in events if item.timestamp is not None]):
        if event.event_id == "4624" and logon_type_of(event) in ("remote interactive", "network"):
            key = event.payload.get("TargetUserName", "") or event.payload.get("SubjectUserName", "")
            open_sessions[key] = event
        elif event.event_id in ("4778", "25"):
            account = event.payload.get("AccountName") or event.payload.get("UserName") or ""
            if account and account not in open_sessions:
                open_sessions[account] = event
        elif event.event_id in ("4779", "24", "4634"):
            account = event.payload.get("AccountName") or event.payload.get("UserName") or event.primary_account()
            opening = open_sessions.pop(account, None)
            if opening is not None:
                sessions.append(_session_row(account, opening, event))
    for account, opening in open_sessions.items():
        sessions.append(_session_row(account, opening, None))
    sessions.sort(key=lambda item: item["opened"])
    return sessions


def _session_row(account, opening, closing):
    minutes = 0.0
    if closing is not None and opening.timestamp and closing.timestamp:
        minutes = round((closing.timestamp - opening.timestamp).total_seconds() / 60.0, 2)
    return {
        "account": account,
        "opened": opening.timestamp.isoformat(" ") if opening.timestamp else "",
        "closed": closing.timestamp.isoformat(" ") if closing is not None and closing.timestamp else "",
        "minutes": minutes,
        "address": (opening.payload.get("IpAddress") or opening.payload.get("Address") or "").strip(),
        "host": opening.computer,
    }


def histogram(events, key_function, limit=15):
    # a simple count by any derived key, largest first
    counts = {}
    for event in events:
        key = key_function(event)
        if key:
            counts[key] = counts.get(key, 0) + 1
    rows = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [{"key": key, "count": count} for key, count in rows]


def activity_by_hour(events):
    # events per hour of day, useful for spotting activity outside office hours
    buckets = [0] * 24
    for event in events:
        if event.timestamp is not None:
            buckets[event.timestamp.hour] += 1
    return buckets
