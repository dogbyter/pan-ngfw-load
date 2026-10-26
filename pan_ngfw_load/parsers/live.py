"""Parse collector output (collections/<host>/) into the same tables a TSF produces.

Samples map onto the dp-monitor tables (dpm_session, dpm_minute, dpm_util, dpm_groups15s,
dpm_counters) and the mp-monitor tables (mpm_summary, mpm_procs), so every existing
report section works unchanged. Logs become logs_traffic / logs_threat.
"""

from __future__ import annotations

import gzip
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from . import powperf, simple
from .cli import parse_clock, parse_uptime
from .monitor import PROC_COLS, parse_top

STEPS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400, "week": 604800}


def _xml(path: Path) -> ET.Element | None:
    """Read <name>.xml or <name>.xml.gz (samples are stored compressed)."""
    try:
        if path.exists():
            return ET.parse(path).getroot()
        gz = path.with_name(path.name + ".gz")
        if gz.exists():
            with gzip.open(gz) as fh:
                return ET.parse(fh).getroot()
    except (OSError, ET.ParseError):
        pass
    return None


def _vals(s: str | None) -> list[float]:
    out = []
    for t in (s or "").split(","):
        t = t.strip()
        out.append(np.nan if t in ("", "*") else float(t))
    return out


def resmon_xml(root: ET.Element) -> dict:
    """API 'show running resource-monitor' -> same dict layout as parsers.resmon.parse()."""
    out = {"groups": {}, "windows": {}}
    dp = root.find(".//data-processors")
    dp = dp[0] if dp is not None and len(dp) else None  # first DP (dp0)
    if dp is None:
        return out
    for wname, step in STEPS.items():
        w = dp.find(wname)
        if w is None:
            continue
        if wname == "second":
            for g in w.find("task") if w.find("task") is not None else []:
                out["groups"][g.tag] = float((g.text or "0").rstrip("%") or 0)
        avg = {int(e.findtext("coreid")): _vals(e.findtext("value")) for e in w.findall("cpu-load-average/entry")}
        mx = {int(e.findtext("coreid")): _vals(e.findtext("value")) for e in w.findall("cpu-load-maximum/entry")}
        cores = sorted(avg)
        n = max((len(v) for v in avg.values()), default=0)
        cpu = {"cores": cores,
               "avg": [[avg[c][i] if i < len(avg[c]) else np.nan for c in cores] for i in range(n)],
               "max": [[mx.get(c, [])[i] if i < len(mx.get(c, [])) else np.nan for c in cores] for i in range(n)]
               if mx else []}
        util = {e.findtext("name"): _vals(e.findtext("value")) for e in w.findall("resource-utilization/entry")}
        out["windows"][step] = {"cpu": cpu, "util": util}
    return out


def detect_dp_cores(rm: dict) -> list[int]:
    """Cores that ever show load in the hour/day/week windows. The API reports the
    management core as 0 instead of '*', so an all-zero core is treated as non-DP."""
    seen: dict[int, float] = {}
    for step in (3600, 86400, 604800, 60):
        cpu = rm["windows"].get(step, {}).get("cpu")
        if not cpu or not cpu.get("max"):
            continue
        arr = np.array(cpu["max"], dtype=float)
        for j, c in enumerate(cpu["cores"]):
            seen[c] = max(seen.get(c, 0), np.nanmax(arr[:, j]) if arr.size else 0)
    active = [c for c, v in seen.items() if v > 0]
    return sorted(active) if active else sorted(seen)


def session_info_xml(root: ET.Element) -> dict[str, float]:
    m = {"num-max": "sessions_supported", "num-active": "sessions_allocated", "num-tcp": "sessions_tcp",
         "num-udp": "sessions_udp", "num-icmp": "sessions_icmp", "num-installed": "sessions_created_total",
         "pps": "pps", "kbps": "kbps", "cps": "cps"}
    out = {}
    for tag, key in m.items():
        v = root.findtext(tag)
        if v is not None and v.strip().lstrip("-").isdigit():
            out[key] = float(v)
    if "sessions_allocated" in out and out.get("sessions_supported"):
        out["session_util_pct"] = out["sessions_allocated"] / out["sessions_supported"] * 100
    return out


def counters_xml(root: ET.Element) -> list[tuple[str, float]]:
    return [(e.findtext("name"), float(e.findtext("value") or 0)) for e in root.findall(".//global/counters/entry")]


def counters_full_xml(root: ET.Element) -> pd.DataFrame:
    """Latest 'show counter global' -> same columns as the TSF table counters_boot (values since boot)."""
    rows = [(e.findtext("name"), float(e.findtext("value") or 0), float(e.findtext("rate") or 0),
             e.findtext("severity") or "", e.findtext("category") or "", e.findtext("aspect") or "",
             e.findtext("desc") or "") for e in root.findall(".//global/counters/entry")]
    return pd.DataFrame(rows, columns=simple.COUNTER_COLS)


def _dir_time(name: str) -> datetime | None:
    try:
        return datetime.strptime(name[:15], "%Y%m%d_%H%M%S")
    except ValueError:
        return None


def load(coll: Path, since: datetime | None = None) -> dict:
    """Device data directory -> {'meta': {...}, 'tables': {...}, 'rm_latest': dict|None}.

    since: only samples/logs from this time on (None = everything)."""
    meta: dict = {}
    si = _xml(coll / "system_info.xml")
    if si is not None and si.find("system") is not None:
        s = si.find("system")
        meta.update(hostname=s.findtext("hostname"), model=s.findtext("model"), serial=s.findtext("serial"),
                    sw_version=s.findtext("sw-version"), app_version=s.findtext("app-version"),
                    threat_version=s.findtext("threat-version"), ip=s.findtext("ip-address"))

    sess, minute, util, groups, counters, summ, procs, pow_rows = [], [], [], [], [], [], [], []
    pow_latest = None
    rm_latest, rm_latest_ts, apps_latest, counters_latest = None, None, None, None
    for d in sorted((coll / "samples").glob("*")):
        if since is not None and (dt := _dir_time(d.name)) is not None and dt < since:
            continue
        clock = _xml(d / "clock.xml")
        ts = parse_clock(clock.text or "") if clock is not None else None
        ts = ts or datetime.strptime(d.name, "%Y%m%d_%H%M%S")
        if (r := _xml(d / "session_info.xml")) is not None:
            sess.append({"ts": ts, **session_info_xml(r)})
        if (r := _xml(d / "resource_monitor.xml")) is not None:
            rm = resmon_xml(r)
            rm_latest, rm_latest_ts = rm, ts
            for g, pct in rm["groups"].items():
                groups.append((ts, g, pct))
            w = rm["windows"].get(60)
            if w:
                base = pd.Timestamp(ts).floor("min")
                for i, (a_row, m_row) in enumerate(zip(w["cpu"]["avg"], w["cpu"]["max"])):
                    for c, a, mx in zip(w["cpu"]["cores"], a_row, m_row):
                        minute.append((base - pd.Timedelta(minutes=i), c, a, mx, ts))
                for metric, vals in w["util"].items():
                    for i, v in enumerate(vals):
                        util.append((base - pd.Timedelta(minutes=i), metric, v, ts))
        if (r := _xml(d / "counter_global.xml")) is not None:
            counters.extend((ts, n, v) for n, v in counters_xml(r))
            counters_latest = r
        if (r := _xml(d / "system_resources.xml")) is not None:
            row, pr = parse_top(ts, r.text or "")
            summ.append(row)
            procs.extend(pr)
        if (r := _xml(d / "pow_performance.xml")) is not None:
            pp = powperf.parse("".join(r.itertext()))
            pp = pp[pp.core == -1]
            if not pp.empty:
                pow_latest = pp.drop(columns="core")
                pow_rows.extend((ts, x.kind, x.name, x.ac_total_us, x.ac_count) for x in pp.itertuples())
        if (r := _xml(d / "app_statistics.xml")) is not None:
            apps_latest = simple.app_statistics(r.text or "")

    t: dict[str, pd.DataFrame] = {}
    t["dpm_session"] = pd.DataFrame(sess)
    t["dpm_groups15s"] = pd.DataFrame(groups, columns=["ts", "group", "pct"])
    t["dpm_counters"] = pd.DataFrame(counters, columns=["ts", "name", "value"])
    m = pd.DataFrame(minute, columns=["ts", "core", "avg", "max", "snap"])
    if not m.empty:
        m = m.sort_values("snap").drop_duplicates(["ts", "core"], keep="last").drop(columns="snap")
    t["dpm_minute"] = m.sort_values(["ts", "core"]).reset_index(drop=True) if not m.empty else m
    u = pd.DataFrame(util, columns=["ts", "metric", "value", "snap"])
    if not u.empty:
        u = u.sort_values("snap").drop_duplicates(["ts", "metric"], keep="last").drop(columns="snap")
    t["dpm_util"] = u
    t["dpm_pow"] = pd.DataFrame(pow_rows, columns=["ts", "kind", "name", "ac_total_us", "ac_count"])
    if pow_latest is not None:
        t["_pow_latest"] = pow_latest
    t["mpm_summary"] = pd.DataFrame(summ)
    t["mpm_procs"] = pd.DataFrame(procs, columns=PROC_COLS)
    if apps_latest is not None:
        t["apps"] = apps_latest
    if counters_latest is not None:
        t["counters_boot"] = counters_full_xml(counters_latest)

    for kind in ("traffic", "threat"):
        files = sorted((coll / "logs").glob(f"{kind}_*.csv.gz")) + sorted((coll / "logs").glob(f"{kind}_*.csv"))
        if since is not None:  # file name: <kind>_<from>_<to>.csv.gz - skip files that end before 'since'
            files = [f for f in files if (e := _dir_time(f.name.split("_", 3)[-1])) is None or e >= since]
        if files:
            df = pd.concat([pd.read_csv(f, low_memory=False) for f in files], ignore_index=True)
            if "seqno" in df.columns:
                df = df.drop_duplicates("seqno")
            for c in ("receive_time", "time_generated", "start"):
                if c in df.columns:
                    df[c] = pd.to_datetime(df[c], format="%Y/%m/%d %H:%M:%S", errors="coerce")
            if since is not None:
                df = df[df.receive_time >= since]
            t[f"logs_{kind}"] = df.sort_values("receive_time").reset_index(drop=True)

    if si is not None and si.find("system") is not None:
        up = parse_uptime(si.find("system").findtext("uptime") or "")
        info_ts = datetime.fromtimestamp((coll / "system_info.xml").stat().st_mtime)
        if up:
            meta["boot_time"] = info_ts - pd.Timedelta(seconds=up)
    if rm_latest is not None:
        meta["dp_cores"] = detect_dp_cores(rm_latest)
        meta["tsf_time"] = rm_latest_ts
    return {"meta": meta, "tables": t, "rm_latest": rm_latest}
