# The Event model: one record turned into named fields. Everything a rule or a
# report needs is pulled out here once, so no other module has to walk the node
# tree, and the raw payload stays attached for the dump command.

from .helpers import isoformat
from .nodes import Element
from .render import flatten

# time formats seen in the SystemTime attribute across Windows versions
TIME_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S")


def parse_timestamp(text):
    # tolerant parse of the TimeCreated value, None when it is not a timestamp
    if not text:
        return None
    from datetime import datetime

    cleaned = text.strip()
    for pattern in TIME_FORMATS:
        try:
            return datetime.strptime(cleaned, pattern)
        except ValueError:
            continue
    return None


class Event:
    # one event record with its system fields and payload flattened
    __slots__ = (
        "record_id",
        "record_written",
        "timestamp",
        "timestamp_source",
        "provider",
        "provider_guid",
        "provider_source",
        "event_id",
        "qualifiers",
        "version",
        "level",
        "task",
        "opcode",
        "keywords",
        "channel",
        "computer",
        "user_id",
        "process_id",
        "thread_id",
        "activity_id",
        "payload",
        "payload_kind",
        "record_size",
        "chunk_index",
        "source_file",
        "damaged",
        "problem",
        "nodes",
    )

    def __init__(self):
        self.record_id = None
        self.record_written = None
        self.timestamp = None
        self.timestamp_source = "record"
        self.provider = ""
        self.provider_guid = ""
        self.provider_source = ""
        self.event_id = None
        self.qualifiers = None
        self.version = None
        self.level = None
        self.task = None
        self.opcode = None
        self.keywords = None
        self.channel = ""
        self.computer = ""
        self.user_id = ""
        self.process_id = None
        self.thread_id = None
        self.activity_id = ""
        self.payload = {}
        self.payload_kind = "none"
        self.record_size = 0
        self.chunk_index = 0
        self.source_file = ""
        self.damaged = False
        self.problem = None
        self.nodes = []

    def __repr__(self):
        return "Event(id=%s, channel=%s, provider=%s, time=%s)" % (
            self.event_id,
            self.channel or "?",
            self.provider or "?",
            isoformat(self.timestamp) or "?",
        )

    def event_id_int(self):
        try:
            return int(str(self.event_id).strip(), 0)
        except (TypeError, ValueError):
            return None

    def get(self, key, default=""):
        # payload lookup that also accepts system field names
        if key in self.payload:
            return self.payload[key]
        return default

    def get_int(self, key, default=None):
        value = self.payload.get(key)
        if value is None:
            return default
        try:
            return int(str(value).strip(), 0)
        except ValueError:
            return default

    def lower_payload(self):
        # lowercased payload keys, so rules can look fields up without caring
        # about the exact casing a provider used
        return dict((str(key).lower(), value) for key, value in self.payload.items())

    def first_of(self, *keys):
        # first non empty payload value among the given key names
        lowered = self.lower_payload()
        for key in keys:
            value = lowered.get(key.lower())
            if value not in (None, ""):
                return value
        return ""

    def searchable_text(self):
        # single string used by the pattern rules and the grep filter
        parts = [self.provider, self.channel, self.computer, str(self.event_id or "")]
        for key in sorted(self.payload):
            parts.append("%s=%s" % (key, self.payload[key]))
        return " ".join(parts)

    def channel_matches(self, name):
        # a rule may name either the full channel path or its short name
        channel = (self.channel or "").lower()
        wanted = (name or "").lower()
        return channel == wanted or channel.endswith("/" + wanted)

    def primary_account(self):
        # the account most likely responsible for the event
        return self.first_of("TargetUserName", "SubjectUserName", "AccountName", "param1") or self.user_id or ""

    def as_dict(self, include_payload=True, include_nodes=False):
        data = {
            "record_id": self.record_id,
            "timestamp": isoformat(self.timestamp),
            "record_written": isoformat(self.record_written),
            "timestamp_source": self.timestamp_source,
            "provider": self.provider,
            "provider_guid": self.provider_guid,
            "event_id": self.event_id,
            "qualifiers": self.qualifiers,
            "version": self.version,
            "level": self.level,
            "task": self.task,
            "opcode": self.opcode,
            "keywords": self.keywords,
            "channel": self.channel,
            "computer": self.computer,
            "user_id": self.user_id,
            "process_id": self.process_id,
            "thread_id": self.thread_id,
            "activity_id": self.activity_id,
            "chunk_index": self.chunk_index,
            "record_size": self.record_size,
            "source_file": self.source_file,
            "damaged": self.damaged,
            "problem": self.problem,
            "payload_kind": self.payload_kind,
        }
        if include_payload:
            data["payload"] = dict(self.payload)
        if include_nodes:
            data["nodes"] = self.nodes
        return data


def build_event(nodes, record=None, parser=None, source_file="", chunk_index=0, damaged=False, problem=None):
    # Turn a bound node tree into an Event. The tree normally starts with Event,
    # but a damaged or unusual record may start anywhere, so the first element is
    # used as the root whatever its tag.
    event = Event()
    event.nodes = nodes
    event.source_file = source_file
    event.chunk_index = chunk_index
    event.damaged = damaged
    event.problem = problem
    if record is not None:
        event.record_id = record.record_id
        event.record_written = record.written_datetime
        event.record_size = record.size
        event.timestamp = record.written_datetime
    root = None
    for node in nodes:
        if isinstance(node, Element):
            root = node
            break
    if root is None:
        return event
    system = root.child("System")
    if system is not None:
        _read_system(event, system)
    if event.timestamp is None and event.record_written is not None:
        event.timestamp = event.record_written
        event.timestamp_source = "record"
    event_data = root.child("EventData")
    if event_data is not None:
        _read_event_data(event, event_data)
    else:
        user_data = root.child("UserData")
        if user_data is not None:
            _read_user_data(event, user_data)
    return event


def _read_system(event, system):
    # system fields are attributes on a handful of well known child elements
    provider = system.child("Provider")
    if provider is not None:
        event.provider = provider.attribute_text("Name")
        event.provider_guid = provider.attribute_text("Guid")
        event.provider_source = provider.attribute_text("EventSourceName")
    event_id = system.child("EventID")
    if event_id is not None:
        event.event_id = event_id.text_content().strip()
        qualifiers = event_id.attribute_text("Qualifiers")
        event.qualifiers = qualifiers or None
    for tag, attribute in (("Version", "version"), ("Level", "level"), ("Task", "task"), ("Opcode", "opcode")):
        element = system.child(tag)
        if element is None:
            continue
        text = element.text_content().strip()
        setattr(event, attribute, int(text) if text.lstrip("-").isdigit() else (text or None))
    keywords = system.child("Keywords")
    if keywords is not None:
        event.keywords = keywords.text_content().strip() or None
    created = system.child("TimeCreated")
    if created is not None:
        stamp = parse_timestamp(created.attribute_text("SystemTime"))
        if stamp is not None:
            event.timestamp = stamp
            event.timestamp_source = "event"
    channel = system.child("Channel")
    if channel is not None:
        event.channel = channel.text_content().strip()
    computer = system.child("Computer")
    if computer is not None:
        event.computer = computer.text_content().strip()
    execution = system.child("Execution")
    if execution is not None:
        event.process_id = _maybe_int(execution.attribute_text("ProcessID"))
        event.thread_id = _maybe_int(execution.attribute_text("ThreadID"))
    correlation = system.child("Correlation")
    if correlation is not None:
        event.activity_id = correlation.attribute_text("ActivityID")
    security = system.child("Security")
    if security is not None:
        event.user_id = security.attribute_text("UserID")


def _maybe_int(text):
    if text in (None, ""):
        return None
    try:
        return int(text, 0)
    except ValueError:
        return text


def _read_event_data(event, event_data):
    # EventData holds Data elements, named through the Name attribute or
    # positional when the provider omitted it
    event.payload_kind = "EventData"
    index = 0
    for node in event_data.content:
        if not isinstance(node, Element):
            continue
        if node.tag == "Data":
            name = node.attribute_text("Name")
            if not name:
                name = "Data_%d" % index
            event.payload[name] = node.text_content()
            index += 1
        elif node.tag == "Binary":
            event.payload["Binary"] = node.text_content()
        else:
            event.payload[node.tag] = node.text_content()


def _read_user_data(event, user_data):
    # UserData wraps a provider specific structure, flattened into dotted paths
    event.payload_kind = "UserData"
    children = [child for child in user_data.content if isinstance(child, Element)]
    if children and all(child.tag in ("Data", "Binary") for child in children) and any(child.attribute_text("Name") for child in children):
        # a UserData block built from named Data elements reads like EventData
        index = 0
        for child in children:
            name = child.attribute_text("Name") or "Data_%d" % index
            event.payload[name] = child.text_content()
            index += 1
        return
    for path, text, attributes in flatten(children):
        # the leading wrapper element repeats the provider name, so it is dropped
        trimmed = path.split(".", 1)[-1] if "." in path else path
        if text or not attributes:
            event.payload[trimmed] = text
        for name, value in attributes.items():
            event.payload["%s@%s" % (trimmed, name)] = value
