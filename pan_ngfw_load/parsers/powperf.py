"""Parse 'debug dataplane pow performance' tables.

Columns: name max-us avg-us count total-us | ac-max-us ac-avg-us ac-count ac-total-us
The first four describe the interval since the previous call; the 'ac-' columns
are accumulated since the dataplane started. 'group' rows are top-level work
groups (they add up to the busy time of the worker cores); 'func' rows are
functions nested inside groups (they overlap with groups and with each other).
"""

from __future__ import annotations

import re

import pandas as pd

COLS = ["max_us", "avg_us", "count", "total_us", "ac_max_us", "ac_avg_us", "ac_count", "ac_total_us"]
HDR_RE = re.compile(r"^(group|func)\s+max-us\s+avg-us")
CORE_RE = re.compile(r"^Core (\d+):")


def parse(text: str) -> pd.DataFrame:
    """-> DataFrame[core, kind, name, *COLS]. core is -1 for the all-core summary."""
    rows = []
    kind, core = None, -1
    for raw in text.splitlines():
        line = raw[1:] if raw.startswith(":") else raw
        s = line.strip()
        m = CORE_RE.match(s)
        if m:
            core, kind = int(m.group(1)), None
            continue
        m = HDR_RE.match(s)
        if m:
            kind = m.group(1)
            continue
        if kind is None:
            continue
        toks = s.split()
        if len(toks) != 9:
            kind = None  # end of table
            continue
        try:
            vals = [float(t) for t in toks[1:]]
        except ValueError:
            kind = None
            continue
        rows.append([core, kind, toks[0], *vals])
    return pd.DataFrame(rows, columns=["core", "kind", "name", *COLS])
