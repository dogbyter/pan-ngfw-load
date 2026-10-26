"""Split the techsupport_*.txt CLI dump into commands and parse simple sections."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

CMD_RE = re.compile(r"^> (.*\S)?\s*$")


class CliDump:
    """Ordered list of (command, output). The same command can appear several times."""

    def __init__(self, path: Path):
        self.path = path
        self.sections: list[tuple[str, str]] = []
        cmd, buf = None, []
        with open(path, errors="replace") as fh:
            for line in fh:
                m = CMD_RE.match(line)
                if m:
                    if cmd is not None:
                        self.sections.append((cmd, "".join(buf)))
                    cmd, buf = (m.group(1) or "").strip(), []
                else:
                    buf.append(line)
        if cmd is not None:
            self.sections.append((cmd, "".join(buf)))

    def get(self, command: str, which: int = 0) -> str | None:
        """Output of the n-th occurrence of an exact command (whitespace-insensitive)."""
        want = " ".join(command.split())
        hits = [out for c, out in self.sections if " ".join(c.split()) == want]
        if not hits:
            return None
        return hits[which] if -len(hits) <= which < len(hits) else None

    def commands(self) -> list[str]:
        return [c for c, _ in self.sections]


def parse_kv(text: str) -> dict[str, str]:
    """'key: value' lines -> dict (first occurrence wins)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            if k and k not in out:
                out[k] = v.strip()
    return out


def parse_clock(text: str) -> datetime | None:
    """'Thu Oct 15 13:26:43 CEST 2026' -> naive local datetime."""
    for line in text.splitlines():
        m = re.match(r"\s*\w{3} (\w{3})\s+(\d+) (\d\d:\d\d:\d\d) (\S+) (\d{4})", line)
        if m:
            mon, day, hms, _tz, year = m.groups()
            return datetime.strptime(f"{year} {mon} {day} {hms}", "%Y %b %d %H:%M:%S")
    return None


def parse_uptime(value: str) -> float | None:
    """'30 days, 23:36:45' -> seconds."""
    m = re.match(r"(?:(\d+) days?, )?(\d+):(\d+):(\d+)", value or "")
    if not m:
        return None
    d, h, mi, s = (int(x or 0) for x in m.groups())
    return ((d * 24 + h) * 60 + mi) * 60 + s
