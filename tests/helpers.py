# shared helpers: build a small log and read it back
import os
import sys
import tempfile
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.fixtures.evtx_builder import EvtxBuilder

from evtx_triage.evtxfile import EvtxFile
from evtx_triage.triage import analyze

BASE_TIME = datetime(2024, 5, 4, 12, 0, 0)


def temp_path(name="sample.evtx"):
    handle, path = tempfile.mkstemp(prefix="evtx-triage-", suffix="-" + name)
    os.close(handle)
    return path


def simple_builder(chunks=1):
    # three events, one templated, one plain, one with a payload spread of types
    builder = EvtxBuilder(chunks=chunks)
    builder.add_event(
        4624,
        payload={"TargetUserName": ("wstring", "alice"), "LogonType": ("uint32", 3), "IpAddress": ("wstring", "10.0.0.9")},
        timestamp=BASE_TIME,
    )
    builder.add_event(
        1102,
        payload={},
        provider="Microsoft-Windows-Eventlog",
        timestamp=BASE_TIME + timedelta(minutes=1),
    )
    return builder


def write_builder(builder, name="sample.evtx"):
    path = temp_path(name)
    builder.write(path)
    return path


def read_events(path, **options):
    events = []
    with EvtxFile(path, recover=options.get("recover", True)) as log:
        for event in log.events():
            events.append(event)
    return events


def analyze_path(path, **options):
    return analyze([path], options or None)
