# evtx-triage: read Windows event logs straight from their binary form, verify
# their structure, and turn them into findings and a timeline. Pure standard
# library, no dependencies.

__version__ = "1.0.0"

from .errors import BinXmlError, ChecksumError, EvtxError, FormatError, RecordError, TruncatedError, UnsupportedVersionError, ValueDecodeError
from .event import Event, build_event
from .evtxfile import EvtxFile, collect_files, open_evtx
from .rules import Finding, Rule, evaluate
from .rules_data import RULES, RULE_INDEX
from .triage import analyze, collect_paths, summarize

__all__ = [
    "BinXmlError",
    "ChecksumError",
    "Event",
    "EvtxError",
    "EvtxFile",
    "Finding",
    "FormatError",
    "RULE_INDEX",
    "RULES",
    "RecordError",
    "Rule",
    "TruncatedError",
    "UnsupportedVersionError",
    "ValueDecodeError",
    "analyze",
    "build_event",
    "collect_files",
    "collect_paths",
    "evaluate",
    "open_evtx",
    "summarize",
    "__version__",
]
