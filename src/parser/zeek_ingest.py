
import json
import time
import math
from pathlib import Path
from threading import Event
from typing import Any, Iterator
from src.storage.sqlite_store import SQLiteStore

from src.common.zeek_models import ZeekEvent


class ZeekLogParser:
    """Parse and normalize Zeek JSON and TSV log records."""

    def __init__(self, log_type: str | None = None) -> None:
        self.log_type = log_type
        self.fields: list[str] = []
        self.separator = "\t"
        self.path = log_type
        self.errors: list[str] = []

    @staticmethod
    def _get(data: dict[str, Any], *keys: str) -> Any:
        """Return the first available non-empty field."""
        for key in keys:
            value = data.get(key)
            if value not in (None, "", "-", "(empty)"):
                return value
        return None

    @staticmethod
    def _to_port(value: Any) -> int | None:
        if value in (None, "", "-", "(empty)"):
            return None
        try:
            port = int(value)
            return port if 0 <= port <= 65535 else None
        except (TypeError, ValueError):
            return None

    def _normalize(
        self, data: dict[str, Any], log_type: str | None = None
    ) -> ZeekEvent:
        """Convert a Zeek record into a normalized event."""
        timestamp = self._get(data, "ts", "timestamp")
        if timestamp is None:
            raise ValueError("Missing timestamp")

        timestamp = float(timestamp)
        if not math.isfinite(timestamp) or timestamp < 0:
            raise ValueError("Invalid timestamp")

        event_type = (
            log_type
            or self._get(data, "_path", "path", "log_type")
            or self.path
            or "unknown"
        )

        src_ip = self._get(data, "id.orig_h", "id_orig_h", "src_ip")
        dst_ip = self._get(data, "id.resp_h", "id_resp_h", "dst_ip")

        src_port = self._get(data, "id.orig_p", "id_orig_p", "src_port")
        dst_port = self._get(data, "id.resp_p", "id_resp_p", "dst_port")

        excluded = {
            "ts", "timestamp", "_path", "path", "log_type",
            "uid", "id.orig_h", "id_orig_h", "src_ip",
            "id.resp_h", "id_resp_h", "dst_ip",
            "id.orig_p", "id_orig_p", "src_port",
            "id.resp_p", "id_resp_p", "dst_port", "proto",
            "protocol",
        }

        metadata = {
            key: value
            for key, value in data.items()
            if key not in excluded
        }

        return ZeekEvent(
            timestamp=timestamp,
            log_type=str(event_type),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=self._to_port(src_port),
            dst_port=self._to_port(dst_port),
            protocol=self._get(data, "proto", "protocol"),
            uid=self._get(data, "uid"),
            metadata=metadata,
        )

    def parse_line(self, line: str) -> ZeekEvent | None:
        """
        Parse one JSON or TSV line.

        Returns None for headers, blank lines and malformed records.
        """
        line = line.rstrip("\r\n")

        if not line:
            return None

        if line.startswith("#"):
            self._parse_header(line)
            return None

        try:
            if line.lstrip().startswith("{"):
                data = json.loads(line)
                if not isinstance(data, dict):
                    raise ValueError("JSON record must be an object")
                return self._normalize(data)

            if not self.fields:
                raise ValueError("TSV fields header not found")

            values = line.split(self.separator)

            if len(values) > len(self.fields):
                raise ValueError("Too many TSV fields")

            values.extend(["-"] * (len(self.fields) - len(values)))
            data = dict(zip(self.fields, values))

            return self._normalize(data)

        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.errors.append(str(exc))
            return None

    def _parse_header(self, line: str) -> None:
        """Read Zeek TSV metadata headers."""
        if line.startswith("#separator"):
            value = line[len("#separator"):].strip()
            if value:
                try:
                    self.separator = value.encode().decode("unicode_escape")
                except UnicodeDecodeError:
                    self.separator = "\t"

        elif line.startswith("#path"):
            parts = line.split(None, 1)
            if len(parts) == 2:
                self.path = parts[1].strip()

        elif line.startswith("#fields"):
            parts = line.split(self.separator)
            self.fields = parts[1:]

    def read_file(self, file_path: str | Path) -> Iterator[ZeekEvent]:
        """Read a completed Zeek log file."""
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                event = self.parse_line(line)
                if event is not None:
                    yield event

    def follow_file(
        self,
        file_path: str | Path,
        stop_event: Event | None = None,
        poll_interval: float = 0.2,
    ) -> Iterator[ZeekEvent]:
        """
        Follow a growing Zeek log file and yield new events.

        Stop by setting the supplied threading.Event.
        """
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")

        with open(file_path, "r", encoding="utf-8") as file:
            while True:
                line = file.readline()

                if line:
                    event = self.parse_line(line)
                    if event is not None:
                        yield event
                elif stop_event is not None and stop_event.is_set():
                    break
                else:
                    time.sleep(poll_interval)


def ingest_file(
    file_path: str | Path,
    store: SQLiteStore,
    log_type: str | None = None,
) -> int:
    """Read a recorded Zeek log file and save valid events to SQLite."""
    parser = ZeekLogParser(log_type=log_type)
    saved_count = 0

    for event in parser.read_file(file_path):
        store.save_zeek_event(event)
        saved_count += 1

    return saved_count


def follow_and_store(
    file_path: str | Path,
    store: SQLiteStore,
    stop_event: Event,
    log_type: str | None = None,
    poll_interval: float = 0.2,
) -> int:
    """Follow a growing Zeek log file and save incoming events to SQLite."""
    parser = ZeekLogParser(log_type=log_type)
    saved_count = 0

    for event in parser.follow_file(
        file_path,
        stop_event=stop_event,
        poll_interval=poll_interval,
    ):
        store.save_zeek_event(event)
        saved_count += 1

    return saved_count
