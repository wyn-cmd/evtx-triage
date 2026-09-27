# The file level API. An EvtxFile maps the log, validates the header, and walks
# chunks and records, reusing one binary XML parser per chunk so the template
# cache is shared by every record in it.

import mmap
import os

from .binxml import BxmlParser
from .chunk import CHUNK_SIZE, Chunk
from .errors import TruncatedError
from .event import build_event
from .header import FILE_HEADER_SIZE, FileHeader


class EvtxFile:
    # an open event log; use as a context manager or call close()
    def __init__(self, path, recover=True, source=None):
        self.path = path
        self.recover = recover
        self.source = source or os.path.basename(str(path))
        self.size = os.path.getsize(path)
        self._file = open(path, "rb")
        self._mmap = None
        self.data = None
        try:
            # mapping keeps a multi gigabyte log out of memory, and the slice
            # interface is identical to bytes so the reader needs no changes
            self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
            self.data = self._mmap
        except (ValueError, OSError):
            self.data = self._file.read()
        if self.size < FILE_HEADER_SIZE:
            self.close()
            raise TruncatedError("file is %d bytes, too small to hold an EVTX header" % self.size, offset=0, source=self.source)
        self.header = FileHeader(bytes(self.data[:FILE_HEADER_SIZE]), source=self.source)
        self.header.validate()
        self._chunk_reports = None

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.close()
        return False

    def close(self):
        if self._mmap is not None:
            self._mmap.close()
            self._mmap = None
        if self._file is not None:
            self._file.close()
            self._file = None

    def __repr__(self):
        return "EvtxFile(%r, chunks=%d)" % (self.path, self.header.chunk_count)

    def declared_chunk_count(self):
        return self.header.chunk_count

    def available_chunk_count(self):
        # the header can claim more chunks than the file holds, which happens
        # when a log is copied while it is still being written
        declared = self.header.chunk_count
        fits = max(0, (self.size - FILE_HEADER_SIZE) // CHUNK_SIZE)
        return min(declared, fits)

    def chunk_count(self):
        return self.available_chunk_count()

    def chunk_at(self, index):
        # build one Chunk, or None when the file is short of that chunk
        offset = FILE_HEADER_SIZE + index * CHUNK_SIZE
        if offset + CHUNK_SIZE > self.size:
            return None
        return Chunk(bytes(self.data[offset:offset + CHUNK_SIZE]), index=index, file_offset=offset, source=self.source)

    def chunks(self):
        # every chunk the file actually contains, in file order
        for index in range(self.available_chunk_count()):
            chunk = self.chunk_at(index)
            if chunk is not None:
                yield chunk

    def events(self, chunk_indexes=None, skip_damaged=False):
        # every readable event, in chunk order then record order. Events are not
        # sorted by time here, the timeline module does that.
        wanted = set(chunk_indexes) if chunk_indexes is not None else None
        for chunk in self.chunks():
            if wanted is not None and chunk.index not in wanted:
                continue
            chunk.damage = []
            parser = BxmlParser(chunk, source="%s chunk %d" % (self.source, chunk.index), recover=self.recover)
            for record in chunk.records(recover=self.recover):
                nodes, problem = parser.parse_record(record)
                if problem is not None and skip_damaged:
                    continue
                event = build_event(
                    nodes,
                    record=record,
                    parser=parser,
                    source_file=self.source,
                    chunk_index=chunk.index,
                    damaged=problem is not None,
                    problem=problem,
                )
                yield event

    def chunk_reports(self):
        # verification details for every chunk, cached because it is not cheap
        if self._chunk_reports is not None:
            return self._chunk_reports
        reports = []
        for chunk in self.chunks():
            report = chunk.verify()
            report["source_file"] = self.source
            reports.append(report)
        self._chunk_reports = reports
        return reports

    def damage_report(self):
        # every damaged region found so far: chunk, record header, record payload
        entries = []
        for chunk in self.chunks():
            chunk.damage = []
            parser = BxmlParser(chunk, source="%s chunk %d" % (self.source, chunk.index), recover=self.recover)
            records_readable = 0
            records_damaged = 0
            for record in chunk.records(recover=self.recover):
                nodes, problem = parser.parse_record(record)
                if problem is None:
                    records_readable += 1
                else:
                    records_damaged += 1
                    if self.recover:
                        entries.append({"kind": "record", "chunk": chunk.index, "offset": record.absolute_offset, "reason": problem})
            for item in chunk.damage:
                entries.append({"kind": "record-header", "chunk": chunk.index, "offset": chunk.offset_of(item["offset"]), "reason": item["reason"]})
            for item in parser.template_errors:
                entries.append({"kind": "template", "chunk": chunk.index, "offset": chunk.offset_of(item["offset"]), "reason": item["reason"]})
            if records_damaged or chunk.damage or chunk.recovered_bytes:
                entries.append(
                    {
                        "kind": "chunk",
                        "chunk": chunk.index,
                        "records_readable": records_readable,
                        "records_damaged": records_damaged,
                        "recovered_bytes": chunk.recovered_bytes,
                        "slack_bytes": chunk.slack_bytes(),
                    }
                )
        return entries

    def stats(self):
        # counts used by info and verify, one pass over the whole file
        totals = {
            "events": 0,
            "damaged_events": 0,
            "chunks": 0,
            "empty_chunks": 0,
            "records_readable": 0,
            "chunks_with_bad_header_checksum": 0,
            "chunks_with_bad_data_checksum": 0,
            "slack_bytes": 0,
            "recovered_bytes": 0,
        }
        for chunk in self.chunks():
            totals["chunks"] += 1
            chunk.damage = []
            verification = chunk.verify()
            totals["slack_bytes"] += chunk.slack_bytes()
            if verification["empty"]:
                totals["empty_chunks"] += 1
                continue
            if not verification["header_checksum_ok"]:
                totals["chunks_with_bad_header_checksum"] += 1
            if not verification["data_checksum_ok"]:
                totals["chunks_with_bad_data_checksum"] += 1
            parser = BxmlParser(chunk, source="%s chunk %d" % (self.source, chunk.index), recover=self.recover)
            for record in chunk.records(recover=self.recover):
                nodes, problem = parser.parse_record(record)
                totals["records_readable"] += 1
                if problem is None:
                    totals["events"] += 1
                else:
                    totals["damaged_events"] += 1
            totals["recovered_bytes"] += chunk.recovered_bytes
        return totals

    def info(self):
        # everything needed to describe the log without reading every payload
        header = self.header.describe()
        header["source_file"] = self.source
        header["file_size"] = self.size
        header["chunks_available"] = self.available_chunk_count()
        header["chunks_claimed"] = self.declared_chunk_count()
        return header

    def verify(self):
        # header, chunk and record verification in one structure
        header_ok, header_computed = self.header.verify_checksum()
        chunks = self.chunk_reports()
        report = {
            "source_file": self.source,
            "file_size": self.size,
            "header": self.header.describe(),
            "header_checksum_ok": header_ok,
            "header_checksum_computed": header_computed,
            "chunks": chunks,
            "damage": self.damage_report(),
            "stats": self.stats(),
        }
        report["ok"] = bool(header_ok) and all(
            chunk["header_checksum_ok"] and chunk["data_checksum_ok"] for chunk in chunks if not chunk["empty"]
        )
        return report


def open_evtx(path, recover=True):
    # convenience wrapper that also normalises the path
    return EvtxFile(os.fspath(path), recover=recover)


def collect_files(targets):
    # expand the command line arguments into a list of paths: files as given,
    # directories scanned for event logs by extension
    found = []
    for target in targets:
        path = os.fspath(target)
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                lower = name.lower()
                if lower.endswith(".evtx") or lower.endswith(".evtx.old"):
                    found.append(os.path.join(path, name))
            continue
        found.append(path)
    unique = []
    seen = set()
    for path in found:
        real = os.path.abspath(path)
        if real in seen:
            continue
        seen.add(real)
        unique.append(path)
    return unique
