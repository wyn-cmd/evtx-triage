# Compare this parser with python-evtx on a real log and report every difference.
#
# This is the tool the parser was developed against. python-evtx is not a
# dependency of the package, so install it anywhere and put it on PYTHONPATH:
#
#     python3 -m venv /tmp/ref && /tmp/ref/bin/pip install python-evtx
#     PYTHONPATH=/tmp/ref/lib/python3.12/site-packages python3 scripts/crosscheck_reference.py Security.evtx
#
# Three differences are expected and understood, see the README:
#   timestamps   this parser truncates the 100ns FILETIME to microseconds, python-evtx rounds
#   control      characters XML 1.0 cannot hold are shown as a dot in the rendered XML
#   arrays       empty entries in a string array are kept here and dropped there
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evtx_triage.evtxfile import EvtxFile

try:
    import Evtx.Evtx as reference_evtx
except ImportError:
    reference_evtx = None

EVENT_ID = re.compile(r"<EventID[^>]*>(-?\d+)</EventID>")
CHANNEL = re.compile(r"<Channel>([^<]*)</Channel>")
COMPUTER = re.compile(r"<Computer>([^<]*)</Computer>")
PROVIDER = re.compile(r'<Provider\b[^>]*?\sName="([^"]*)"')
DATA_VALUE = re.compile(r'<Data Name="([^"]+)">([^<]*)</Data>')
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
ENTITY = re.compile(r"&(lt|gt|amp|quot|#\d+|#x[0-9a-fA-F]+);")


def unescape(text):
    # the reference escapes text twice in places, so its reader hands back
    # literal entity text such as &lt;Opaque&gt; where the log holds <Opaque>
    def replace(match):
        body = match.group(1)
        if body.startswith("#x"):
            return chr(int(body[2:], 16))
        if body.startswith("#"):
            return chr(int(body[1:]))
        return {"lt": "<", "gt": ">", "amp": "&", "quot": '"'}[body]

    return ENTITY.sub(replace, text)


def normalise(text):
    # control characters, entity text and a timestamp fraction are the things
    # the two readers are allowed to disagree about
    text = CONTROL.sub(".", text or "")
    text = unescape(text)
    if len(text) >= 19 and text[4] == "-" and text[7] == "-" and text[10] == " ":
        return text[:19]
    return text


def reference_fields(xml_text):
    # the System block comes first, and later providers can appear inside the
    # payload, so only the text before the payload is searched
    head = xml_text.split("<EventData")[0].split("<UserData")[0]
    event_id = EVENT_ID.search(head)
    channel = CHANNEL.search(head)
    computer = COMPUTER.search(head)
    provider = PROVIDER.search(head)
    return {
        "event_id": event_id.group(1) if event_id else "",
        "channel": channel.group(1) if channel else "",
        "computer": computer.group(1) if computer else "",
        "provider": provider.group(1) if provider else "",
        "payload": dict(DATA_VALUE.findall(xml_text)),
    }


def compare(path, limit):
    with EvtxFile(path) as log:
        mine = []
        for index, event in enumerate(log.events()):
            if limit and index >= limit:
                break
            mine.append(event)
    with reference_evtx.Evtx(path) as log:
        theirs = []
        for index, record in enumerate(log.records()):
            if limit and index >= limit:
                break
            theirs.append(reference_fields(record.xml()))
    return mine, theirs


def differences(mine, theirs):
    problems = []
    if len(mine) != len(theirs):
        problems.append("record count: %d here, %d there" % (len(mine), len(theirs)))
    for event, reference in zip(mine, theirs):
        label = "record %s" % event.record_id
        if normalise(str(event.event_id)) != normalise(reference["event_id"]):
            problems.append("%s event id %r vs %r" % (label, event.event_id, reference["event_id"]))
        if normalise(event.channel) != normalise(reference["channel"]):
            problems.append("%s channel %r vs %r" % (label, event.channel, reference["channel"]))
        if normalise(event.computer) != normalise(reference["computer"]):
            problems.append("%s computer %r vs %r" % (label, event.computer, reference["computer"]))
        if normalise(event.provider) != normalise(reference["provider"]):
            problems.append("%s provider %r vs %r" % (label, event.provider, reference["provider"]))
        for key, value in reference["payload"].items():
            if "<string>" in value:
                # array rendering is the one place the two disagree by design
                left = [item for item in normalise(event.payload.get(key, "")).split("\n") if item.strip("<string>/")]
                right = [item for item in normalise(value).split("\n") if item.strip("<string>/")]
                if left != right:
                    problems.append("%s payload %s array differs" % (label, key))
                continue
            if normalise(event.payload.get(key, "")) != normalise(value):
                problems.append("%s payload %s: %r vs %r" % (label, key, event.payload.get(key, ""), value))
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(prog="crosscheck_reference", description="Compare this parser with python-evtx on a real event log.")
    parser.add_argument("target", help="an evtx file")
    parser.add_argument("--limit", type=int, default=500, help="how many records to compare, 0 for all of them")
    parser.add_argument("--show", type=int, default=10, help="how many differences to print")
    args = parser.parse_args(argv)

    if reference_evtx is None:
        print("python-evtx is not importable, install it and put it on PYTHONPATH first")
        return 2
    if not os.path.exists(args.target):
        print("no such file: %s" % args.target)
        return 2

    mine, theirs = compare(args.target, args.limit)
    problems = differences(mine, theirs)
    print("compared %d records from %s" % (len(mine), args.target))
    for problem in problems[: args.show]:
        print("  %s" % problem)
    if len(problems) > args.show:
        print("  ... and %d more" % (len(problems) - args.show))
    if problems:
        print("%d differences" % len(problems))
        return 1
    print("no differences")
    return 0


if __name__ == "__main__":
    sys.exit(main())
