"""Parse the rolling dp-monitor.log* / mp-monitor.log* files.

Both are sequences of blocks introduced by
    'YYYY-MM-DD HH:MM:SS.mmm +ZZZZ  --- <section>'
dp-monitor 'panio' blocks (every ~10 min) contain resource-monitor (15 s / 15 min),
session info, global counters and pow performance. mp-monitor contains top/top_summary.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd

from . import powperf, resmon, simple

HDR_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\.\d+ ([+-]\d{4})\s+--- (\S+)\s*$")


def iter_blocks(files: list[Path], sections: set[str]) -> Iterator[tuple[datetime, str, str]]:
    """Yield (timestamp, section, text) for wanted sections, files given oldest first."""
    for path in files:
        ts, sec, buf = None, None, []
        with open(path, errors="replace") as fh:
            for line in fh:
                m = HDR_RE.match(line)
                if m:
                    if sec in sections:
                        yield ts, sec, "".join(buf)
                    ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
                    sec, buf = m.group(3), []
                elif sec in sections:
                    buf.append(line)
        if sec in sections:
            yield ts, sec, "".join(buf)


def dp_monitor(files: list[Path]) -> dict[str, pd.DataFrame]:
    """-> tables:
    dpm_session   [ts, pps, kbps, cps, sessions_allocated, ...]
    dpm_minute    [ts, core, avg, max]      per-minute DP core load (deduplicated)
    dpm_util      [ts, metric, value]       per-minute resource utilization
    dpm_groups15s [ts, group, pct]          'CPU load sampling by group' (15 s snapshot)
    dpm_counters  [ts, name, value]         cumulative global counters
    dpm_pow       [ts, kind, name, ac_total_us, ac_count]  cumulative pow performance
    """
    sess, minute, util, groups, counters, pow_rows = [], [], [], [], [], []
    for ts, _sec, text in iter_blocks(files, {"panio"}):
        si = simple.session_info(text)
        if si:
            sess.append({"ts": ts, **si})
        rm = resmon.parse(text)
        for g, pct in rm["groups"].items():
            groups.append((ts, g, pct))
        w = rm["windows"].get(60)
        if w and w["cpu"].get("avg"):
            base = pd.Timestamp(ts).floor("min")
            for i, (a_row, m_row) in enumerate(zip(w["cpu"]["avg"], w["cpu"]["max"])):
                t = base - pd.Timedelta(minutes=i)
                for c, a, mx in zip(w["cpu"]["cores"], a_row, m_row):
                    minute.append((t, c, a, mx, ts))
            for metric, vals in w["util"].items():
                for i, v in enumerate(vals):
                    util.append((base - pd.Timedelta(minutes=i), metric, v, ts))
        _el, gc = simple.global_counters(text, 0)
        for name, value in zip(gc["name"], gc["value"]):
            counters.append((ts, name, value))
        pp = powperf.parse(text)
        for r in pp.itertuples():
            pow_rows.append((ts, r.kind, r.name, r.ac_total_us, r.ac_count))

    out = {
        "dpm_session": pd.DataFrame(sess),
        "dpm_groups15s": pd.DataFrame(groups, columns=["ts", "group", "pct"]),
        "dpm_counters": pd.DataFrame(counters, columns=["ts", "name", "value"]),
        "dpm_pow": pd.DataFrame(pow_rows, columns=["ts", "kind", "name", "ac_total_us", "ac_count"]),
    }
    # Overlapping 15-min windows every 10 min: keep the value from the newest snapshot per minute.
    m = pd.DataFrame(minute, columns=["ts", "core", "avg", "max", "snap"])
    if not m.empty:
        m = m.sort_values("snap").drop_duplicates(["ts", "core"], keep="last").drop(columns="snap")
    out["dpm_minute"] = m.sort_values(["ts", "core"]).reset_index(drop=True)
    u = pd.DataFrame(util, columns=["ts", "metric", "value", "snap"])
    if not u.empty:
        u = u.sort_values("snap").drop_duplicates(["ts", "metric"], keep="last").drop(columns="snap")
    out["dpm_util"] = u.sort_values(["ts", "metric"]).reset_index(drop=True)
    return out


TOP_HDR_RE = re.compile(r"load average: ([\d.]+), ([\d.]+), ([\d.]+)")
CPU_RE = re.compile(r"%Cpu\(s\):\s+([\d.]+) us,\s+([\d.]+) sy,\s+([\d.]+) ni,\s+([\d.]+) id,\s+([\d.]+) wa")
MEM_RE = re.compile(r"MiB Mem :\s+([\d.]+) total,\s+([\d.]+) free,\s+([\d.]+) used,\s+([\d.]+) buff")


def parse_top(ts, text: str, with_procs: bool = True) -> tuple[dict, list[tuple]]:
    """One 'top' output -> (summary row, process rows)."""
    row = {"ts": ts}
    m = TOP_HDR_RE.search(text)
    if m:
        row.update(load1=float(m.group(1)), load5=float(m.group(2)), load15=float(m.group(3)))
    m = CPU_RE.search(text)
    if m:
        row.update(dict(zip(["us", "sy", "ni", "id", "wa"], map(float, m.groups()))))
    m = MEM_RE.search(text)
    if m:
        row.update(dict(zip(["mem_total_mib", "mem_free_mib", "mem_used_mib", "mem_cache_mib"], map(float, m.groups()))))
    procs = []
    if with_procs:
        in_tbl = False
        for line in text.splitlines():
            if line.strip().startswith("PID"):
                in_tbl = True
                continue
            if in_tbl:
                t = line.split()
                if len(t) >= 12 and t[0].isdigit():
                    procs.append((ts, int(t[0]), " ".join(t[11:]), float(t[8]), float(t[9]), _kb(t[5])))
    return row, procs


PROC_COLS = ["ts", "pid", "cmd", "cpu", "mem", "res_kb"]


def mp_monitor(files: list[Path]) -> dict[str, pd.DataFrame]:
    """-> mpm_summary [ts, load1, load5, load15, us, sy, ni, id, wa, mem_*], mpm_procs [ts, pid, cmd, cpu, mem, res_kb]."""
    summ, procs = [], []
    for ts, sec, text in iter_blocks(files, {"top", "top_summary"}):
        row, pr = parse_top(ts, text, with_procs=(sec == "top"))
        summ.append(row)
        procs.extend(pr)
    s = pd.DataFrame(summ).drop_duplicates("ts") if summ else pd.DataFrame()
    return {"mpm_summary": s, "mpm_procs": pd.DataFrame(procs, columns=PROC_COLS)}


def _kb(tok: str) -> float:
    mult = {"m": 1024, "g": 1024 ** 2, "t": 1024 ** 3}
    try:
        return float(tok[:-1]) * mult[tok[-1]] if tok[-1] in mult else float(tok)
    except ValueError:
        return np.nan
