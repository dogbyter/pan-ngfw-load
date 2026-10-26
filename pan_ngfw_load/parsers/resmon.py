"""Parse 'show running resource-monitor' output (CLI dump and dp-monitor 'panio' blocks).

Both formats share one layout: per-window sections with a per-core CPU table
followed by utilization lists. Within every table/list the FIRST value is the
MOST RECENT sample. '*' means "no data" (core is not a DP worker, or the window
predates the last reboot).
"""

from __future__ import annotations

import re

import numpy as np

WINDOW_RE = re.compile(r"CPU load \(%\) during last (\d+) (seconds|minutes|hours|days|weeks)")
UTIL_RE = re.compile(r"Resource utilization \(%\) during last (\d+) (seconds|minutes|hours|days|weeks)")
GROUP_RE = re.compile(r"^(\w+)\s+:\s+(\d+)%\s*$")
UNIT_SECONDS = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400, "weeks": 604800}


def _num(tok: str) -> float:
    return np.nan if tok == "*" else float(tok)


def parse(text: str) -> dict:
    """Return {'groups': {name: pct}, 'windows': {step_s: {'cpu': {...}, 'util': {...}}}}.

    cpu  = {'cores': [0,1,..], 'avg': [[core values per row]], 'max': [[...]]} (rows newest first;
           per-second windows only have 'avg')
    util = {'session (average)': [values newest first], ...}
    """
    lines = [l[1:] if l.startswith(":") else l for l in text.splitlines()]
    out: dict = {"groups": {}, "windows": {}}
    i, n = 0, len(lines)
    in_groups = False
    while i < n:
        line = lines[i]
        if "CPU load sampling by group" in line:
            in_groups = True
            i += 1
            continue
        if in_groups:
            m = GROUP_RE.match(line.strip())
            if m:
                out["groups"][m.group(1)] = float(m.group(2))
                i += 1
                continue
            if line.strip():
                in_groups = False
        m = WINDOW_RE.search(line)
        if m:
            step = UNIT_SECONDS[m.group(2)]
            w = out["windows"].setdefault(step, {"cpu": {}, "util": {}})
            i += 1
            # header 'core 0 1 2 3'. With more than 8 cores PAN-OS wraps the table: a second
            # 'core 8 9 10 11' block with the same number of rows follows the first one.
            cores, avg, mx = [], [], []
            while True:
                while i < n and not lines[i].strip().startswith("core"):
                    i += 1
                if i >= n:
                    break
                i, blk_cores, blk_avg, blk_mx = _cpu_block(lines, i)
                if cores:  # continuation block: append its columns row by row
                    avg = [a + b for a, b in zip(avg, blk_avg)]
                    mx = [a + b for a, b in zip(mx, blk_mx)]
                else:
                    avg, mx = blk_avg, blk_mx
                cores += blk_cores
                j = i
                while j < n and not lines[j].strip():
                    j += 1
                if not (j < n and lines[j].strip().startswith("core")):
                    break
                i = j
            w["cpu"] = {"cores": cores, "avg": avg, "max": mx}
            continue
        m = UTIL_RE.search(line)
        if m:
            step = UNIT_SECONDS[m.group(2)]
            w = out["windows"].setdefault(step, {"cpu": {}, "util": {}})
            i += 1
            name = None
            while i < n:
                s = lines[i].strip()
                if WINDOW_RE.search(lines[i]) or UTIL_RE.search(lines[i]) or s.startswith("Resource monitoring"):
                    break
                if s.endswith(":") and not s[0].isdigit():
                    name = s[:-1]
                    w["util"][name] = []
                elif s and name and all(t == "*" or t.isdigit() for t in s.split()):
                    w["util"][name].extend(_num(t) for t in s.split())
                elif s and not s.endswith(":"):
                    break  # left the resource-monitor output
                i += 1
            continue
        i += 1
    return out


def _cpu_block(lines: list[str], i: int) -> tuple[int, list[int], list, list]:
    """One 'core ...' header plus its rows, starting at the header line; returns the next line index."""
    n = len(lines)
    cores = [int(x) for x in lines[i].split()[1:]]
    i += 1
    has_pairs = i < n and "avg" in lines[i]
    if has_pairs:
        i += 1
    avg, mx = [], []
    while i < n:
        toks = lines[i].split()
        if not toks or not all(t == "*" or t.isdigit() for t in toks):
            break
        vals = [_num(t) for t in toks]
        if has_pairs and len(vals) == 2 * len(cores):
            avg.append(vals[0::2])
            mx.append(vals[1::2])
        elif len(vals) == len(cores):
            avg.append(vals)
        i += 1
    return i, cores, avg, mx


def dp_cores(parsed: dict) -> list[int]:
    """Worker cores = cores that are not '*' in the per-minute (or any) avg table."""
    for step in (60, 3600, 1):
        cpu = parsed["windows"].get(step, {}).get("cpu")
        if cpu and cpu.get("avg"):
            arr = np.array(cpu["avg"], dtype=float)
            return [c for j, c in enumerate(cpu["cores"]) if not np.all(np.isnan(arr[:, j]))]
    return []
