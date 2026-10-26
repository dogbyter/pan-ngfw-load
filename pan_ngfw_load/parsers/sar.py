"""Parse sysstat text reports (var/log/sa/sarDD, 'sar -A' style).

Each report starts with 'Linux <kernel> (<host>) <date> ...' followed by blocks
whose header row names the columns. We return one DataFrame per header type,
keyed by the first column name (CPU, IFACE, DEV, ...).
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

import pandas as pd

TIME_RE = re.compile(r"^(\d\d:\d\d:\d\d)(?:\s+(AM|PM))?\s+(.*)$")


def parse_file(path: Path) -> dict[str, pd.DataFrame]:
    tables: dict[tuple, list] = {}
    day, header = None, None
    with open(path, errors="replace") as fh:
        for line in fh:
            if line.startswith("Linux "):
                m = re.search(r"(\d{4}-\d\d-\d\d|\d\d/\d\d/\d{2,4})", line)
                if m:
                    d = m.group(1)
                    day = datetime.strptime(d, "%Y-%m-%d").date() if "-" in d else datetime.strptime(d, "%m/%d/%y").date()
                continue
            if not line.strip():
                header = None
                continue
            if line.startswith("Average:") or day is None:
                continue
            m = TIME_RE.match(line.rstrip())
            if not m:
                continue
            hms, ampm, rest = m.groups()
            toks = rest.split()
            if header is None or (toks and not _is_num(toks[-1])):
                header = tuple(toks)
                continue
            if len(toks) != len(header):
                continue
            t = datetime.strptime(hms, "%H:%M:%S")
            if ampm == "PM" and t.hour < 12:
                t = t.replace(hour=t.hour + 12)
            elif ampm == "AM" and t.hour == 12:
                t = t.replace(hour=0)
            ts = datetime.combine(day, t.time())
            tables.setdefault(header, []).append([ts, *(_conv(x) for x in toks)])
    out: dict[str, pd.DataFrame] = {}
    for header, rows in tables.items():
        key = "_".join(header[:2])
        out[key] = pd.DataFrame(rows, columns=["ts", *header])
    return out


def parse_all(files: list[Path]) -> dict[str, pd.DataFrame]:
    merged: dict[str, list[pd.DataFrame]] = {}
    for f in files:
        for k, df in parse_file(f).items():
            merged.setdefault(k, []).append(df)
    return {k: pd.concat(v).sort_values("ts").reset_index(drop=True) for k, v in merged.items()}


def _is_num(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False


def _conv(s: str):
    try:
        return float(s)
    except ValueError:
        return s
