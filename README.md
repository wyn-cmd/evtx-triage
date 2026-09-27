# evtx-triage

Read Windows event logs straight out of their binary form, check whether the file is intact, pull every record apart into named fields, run detection rules over the result, and print a report. It uses nothing but the Python standard library, so there is nothing to install and nothing to break on an evidence machine.

Windows event logs are the most useful artefact in a Windows intrusion, and they are also the most annoying to read. Most tools want a library, a framework or a working Windows host. This one wants a file path.

## What it needs

Python 3.8 or newer. No dependencies at runtime, no compilation, no service to talk to.

python-evtx is optional and is only used by the cross check tests to compare this parser against another implementation. If it is not installed those tests skip themselves.

## Running it

Every subcommand takes one or more files, or directories that contain them.

    python3 -m evtx_triage info Security.evtx
    python3 -m evtx_triage verify Security.evtx
    python3 -m evtx_triage dump Security.evtx --event-id 4624 --format xml-pretty
    python3 -m evtx_triage triage Security.evtx --min-severity medium
    python3 -m evtx_triage triage /evidence/*.evtx --format json --output report.json
    python3 -m evtx_triage timeline Security.evtx --gap 20
    python3 -m evtx_triage entities Security.evtx
    python3 -m evtx_triage stats Security.evtx
    python3 -m evtx_triage rules
    python3 -m evtx_triage rules EVT-KERBEROAST

Installing the package adds the same commands under one name.

    pip install .
    evtx-triage triage Security.evtx

Useful switches on `triage` are `--format text|json|markdown|csv|findings-csv`, `--min-severity info|low|medium|high|critical`, `--rule <id>` to run a single rule, `--gap <minutes>` for how quiet a stretch has to be before it splits the timeline into episodes, and `--no-correlate` to leave out the rules that look at patterns across many events. The exit code is 1 when anything at medium severity or worse was found, which makes it usable as a gate in a script.

## What the output looks like

Trimmed from a real run over a public 26 chunk Security log of 2261 records.

    EVTX TRIAGE REPORT
    ========================================================================
    generated      : 2026-09-27 19:47:10
    files          : 1
    events parsed  : 2261
    damaged records: 0
    window         : 2016-07-08 18:12:51.681640 -> 2017-04-14 01:21:10.906949
    findings       : 42

    - /tmp/samples/ca628536.evtx
        3.1, 2166784 bytes, 26 chunks, 2261 records, 0 damaged
        flags: dirty, wrapped: False, checksum ok: True

    SEVERITY
      critical     0
      high        42  ########################
      medium       0
      low          0
      info         0

    MITRE ATT&CK TECHNIQUES
      T1562.002        36
      T1136.001         6

    CHANNEL COVERAGE
      Security                                       2261  2016-07-08 18:12:51 -> 2017-04-14 01:21:10  quiet 232d6h

    FINDINGS
      [HIGH] EVT-LOG-SERVICE-STOP  Event log service stopped
          2016-07-08 18:14:59.617465  event 1100  channel Security  host 37L4247F27-25
          technique T1562.002, score 40
      [HIGH] EVT-ACCOUNT-CREATED  Account created or enabled
          2016-07-08 18:15:23.398026  event 4720  channel Security  host WIN-03DLIIOFRRA
          technique T1136.001, score 40
          account fsir  source -
          TargetUserName=fsir; SubjectUserName=WIN-03DLIIOFRRA$; TargetDomainName=WIN-03DLIIOFRRA

That pair of findings is the whole point of the tool: the audit log service was stopped and accounts were created minutes later, which is what an operator cleaning up after themselves and leaving a way back in looks like.

## What it detects

Static rules run per event. Correlation rules look at the stream as a whole.

    antiforensics   event log cleared (1102, 104), audit policy changed (4719), log service stopped (1100)
    accounts        created, enabled, disabled or deleted (4720, 4722, 4723, 4724, 4725, 4726), lockouts (4740),
                    privileged group membership (4728, 4732, 4756), domain trust added (4706)
    logons          explicit credentials (4648), sensitive privileges assigned (4672), privilege use (4673, 4674)
    persistence     service installed (7045, 4697), scheduled task created or changed (4698 to 4702, 106, 140, 141),
                    registry run keys touched (4657)
    execution       process creation with a suspicious command line (4688), PowerShell script blocks (4104)
    credential      service tickets with weak RC4 encryption (4769), pre authentication disabled (4768),
                    registry access to hives that hold secrets (4656, 4663)
    lateral         administrative share access (5140, 5145), remote interactive logons, WMI activity (5857 to 5861)
    evasion         firewall rules changed or disabled (4946 to 4948), Defender detections and tampering
                    (1116, 1117, 5001, 5010, 5012)

Command line and script block rules match base64 encoded payloads, remote download idioms, shadow copy deletion, ntds extraction, credential dumping tooling, run key and scheduled task persistence, discovery commands and defence evasion switches.

Correlation rules cover repeated authentication failures from one address or against one account, password spraying across accounts, account lockout storms, a successful logon following a run of failures, and quiet stretches in a channel that had been busy.

Each finding carries the technique it maps to and the records it came from, so nothing is asserted without evidence in the event stream.

## How it reads a log

An EVTX file is a 4096 byte header followed by 64 KB chunks. Each chunk holds a 512 byte header, a string table, a template table and the event records. Each record has its own header and then a stream of binary XML tokens: elements, attributes, values, and template instances that fill a shared template with an array of substitution values.

This implementation walks that structure directly, decodes every variant value type, keeps one template cache per chunk, and checks the CRC32 in the file header, the chunk header and the chunk data. When a record header is damaged it scans forward for the next intact record and keeps going, reporting how many bytes were unreadable rather than giving up on the file.

Programmatic use is the same code path the command line takes.

    from evtx_triage import EvtxFile
    with EvtxFile("Security.evtx") as log:
        for event in log.events():
            print(event.record_id, event.event_id, event.channel, event.computer)

## Testing

    python3 -m unittest discover -s tests -t .

97 tests. The fixtures are built on the fly by a small EVTX writer in `tests/fixtures/evtx_builder.py`, which emits real headers, real checksums, real templates and real substitution arrays, so no event logs are committed to this repository and the tests can generate any edge case they need, including damaged records.

To also compare this parser against python-evtx, point it at a directory of real logs.

    PYTHONPATH=/path/to/python-evtx \
    EVTX_TRIAGE_SAMPLES=/path/to/real/evtx/files \
    python3 -m unittest discover -s tests -t .

That test checks record counts and the fields of the first two hundred records of each file, which is how the parser was developed in the first place.

## Where this parser differs from python-evtx

Three deliberate differences, all checked by tests rather than assumed.

    timestamps   FILETIME counts 100 nanosecond ticks and this parser truncates to microseconds while python-evtx rounds, so a value can differ by one microsecond
    control      characters that XML 1.0 cannot represent are shown as a dot in the XML rendering, while the parsed payload keeps the original byte
    string       arrays keep empty entries, python-evtx drops leading ones and can repeat a fragment

## Layout

    evtx_triage/
        reader.py         bounds checked little endian reader
        header.py         file header and its checksum
        chunk.py          chunk header, string table, template table, records, damage recovery
        values.py         every variant value type
        nodes.py          node model and template binding
        binxml.py         the binary XML token grammar and template instances
        render.py         XML rendering
        event.py          one record turned into named fields
        entities.py       accounts, hosts, addresses, objects seen in the logs
        rules.py          the rule engine
        rules_data.py     the rule catalogue
        correlations.py   rules that look at patterns across events
        timeline.py       episodes, coverage, logon sessions
        triage.py         the pipeline
        report.py         text, json, csv and markdown renderers
        cli.py            the command line
    docs/
        evtx-format-notes.md      what the binary format actually looks like
    scripts/
        crosscheck_reference.py   compare this parser with python-evtx on a real log
    tests/
