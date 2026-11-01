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


INVENTORY = ("decrypt_setting", "decrypt_memory", "decrypt_exclude", "decryption_policy", "jobs", "ssl_stats",
             "interface_all", "counter_interface", "lacp", "vpn_flow", "vpn_ipsec_sa", "security_policy", "nat_policy",
             "pbf_policy", "arp", "neighbor", "mac", "fib", "userid_count", "registered_ip", "gp_stats", "ha",
             "environmentals", "disk_space", "software_status")


def _text(elem: ET.Element) -> str:
    """CLI text an op command returns inside <result> (often in one <member>)."""
    return "".join(elem.itertext())


def commits_xml(r: ET.Element) -> pd.DataFrame:
    """'show jobs all' -> ts, job, kind ('configuration' for commits started by an admin, otherwise the job type).
    User names are not kept."""
    rows = []
    for j in r.iter("job"):
        typ, user = j.findtext("type") or "", j.findtext("user") or ""
        try:
            ts = datetime.strptime(j.findtext("tenq") or "", "%Y/%m/%d %H:%M:%S")
        except ValueError:
            continue
        conf = typ.lower().startswith("commit") and user not in ("", "Auto update agent")
        rows.append((pd.Timestamp(ts), int(j.findtext("id") or 0), "configuration" if conf else typ or "other"))
    return pd.DataFrame(rows, columns=["ts", "job", "kind"]).sort_values("ts").reset_index(drop=True)


# --- XML forms of the TSF tables (the API returns these commands as structured XML, not as CLI text) ---------
def _int(x) -> float:
    try:
        return float(str(x).strip())
    except (TypeError, ValueError):
        return np.nan


def interfaces_xml(r: ET.Element) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    """'show interface all' -> (if_hw, if_logical, device IP addresses) like simple.interface_hw / interface_logical
    and anonymize.interface_ips."""
    hw = []
    for e in r.findall("hw/entry"):
        parts = (e.findtext("st") or "").split("/")  # speed/duplex/state(...)
        if len(parts) >= 3:
            hw.append(dict(interface=e.findtext("name"), speed=_int(parts[0]), duplex=parts[1],
                           state=parts[2].split("(")[0]))
    lg, ips = [], []
    for e in r.findall("ifnet/entry"):
        addrs = [a.text.strip() for a in e.iter("member") if a.text and a.text.strip()]
        ip = (e.findtext("ip") or "").strip()
        if ip and ip != "N/A":
            addrs.insert(0, ip)
        lg.append(dict(interface=e.findtext("name"), zone=e.findtext("zone") or "", router=e.findtext("fwd") or "",
                       tag=e.findtext("tag") or "0", address=", ".join(dict.fromkeys(addrs))))
        ips += [a.split("/")[0] for a in addrs if "/" in a or ":" in a]
    return (pd.DataFrame(hw, columns=["interface", "speed", "duplex", "state"]),
            pd.DataFrame(lg, columns=["interface", "zone", "router", "tag", "address"]), list(dict.fromkeys(ips)))


HW_CNT = {"ibytes": "rx_bytes", "obytes": "tx_bytes", "ipackets": "rx_pkts", "opackets": "tx_pkts",
          "ierrors": "rx_errors", "idrops": "rx_discards"}
LG_CNT = {"ibytes": "rx_bytes", "obytes": "tx_bytes", "ipackets": "rx_pkts", "opackets": "tx_pkts",
          "ierrors": "rx_errors", "idrops": "drops", "flowstate": "flow_state_drops", "ifwderrors": "fwd_errors",
          "noroute": "no_route", "noarp": "arp_not_found", "noneigh": "neighbor_not_found", "nomac": "mac_not_found"}


def interface_counters_xml(r: ET.Element) -> pd.DataFrame:
    """'show counter interface all' -> like simple.interface_counters: hardware counters first (physical ports),
    the logical counters fill the rest and cover sub-interfaces, tunnels, VLANs."""
    rows = {}
    for path, mp in (("hw/entry", HW_CNT), ("ifnet/ifnet/entry", LG_CNT), ("ifnet/entry", LG_CNT)):
        for e in r.findall(path):
            row = rows.setdefault(e.findtext("name"), {"interface": e.findtext("name")})
            for tag, col in mp.items():
                if col not in row and e.findtext(tag) is not None:
                    row[col] = _int(e.findtext(tag))
    return pd.DataFrame(list(rows.values()), columns=["interface", *simple.IF_COUNTERS.values()])


def _first(e: ET.Element, *tags) -> str:
    for t in tags:
        v = e.findtext(t)
        if v:
            return v.strip()
    return ""


def vpn_flow_xml(r: ET.Element) -> pd.DataFrame:
    """'show vpn flow' -> tunnel_id, name, state, local, peer (field names as PAN-OS commonly uses them)."""
    rows = [dict(tunnel_id=int(_int(_first(e, "id", "tunnel-id")) or 0), name=_first(e, "name"),
                 state=_first(e, "state"), local=_first(e, "localip", "local-ip", "local"),
                 peer=_first(e, "peerip", "peer-ip", "peer"))
            for e in r.findall("IPSec/entry")]
    return pd.DataFrame(rows, columns=["tunnel_id", "name", "state", "local", "peer"])


def ipsec_sa_xml(r: ET.Element) -> pd.DataFrame:
    """'show vpn ipsec-sa' -> tunnel_id, algorithm (e.g. ESP/G256)."""
    rows = []
    for e in r.findall("entries/entry"):
        alg = "/".join(x for x in (_first(e, "proto", "protocol"), _first(e, "enc", "encryption"),
                                   _first(e, "hash", "authentication")) if x)
        rows.append(dict(tunnel_id=int(_int(_first(e, "tid", "tunnel-id", "id")) or 0), algorithm=alg))
    return pd.DataFrame(rows, columns=["tunnel_id", "algorithm"])


def ha_xml(r: ET.Element) -> pd.DataFrame:
    """'show high-availability all' -> key/value rows like simple.ha_status."""
    if (r.findtext("enabled") or "").strip() != "yes":
        return pd.DataFrame([("enabled", "no")], columns=["key", "value"])
    g = r.find("group")
    rows = [("enabled", "yes")]
    if g is not None:
        for key, paths in (("mode", ("mode",)), ("local state", ("local-info/state",)),
                           ("peer state", ("peer-info/state",)),
                           ("running configuration", ("running-sync",)),
                           ("state synchronization", ("local-info/state-sync", "state-sync"))):
            v = _first(g, *paths)
            if v:
                rows.append((key, v))
    return pd.DataFrame(rows, columns=["key", "value"])


def environmentals_xml(r: ET.Element) -> pd.DataFrame:
    """'show system environmentals' -> kind, description, alarm, value, min, max like simple.environmentals."""
    rows = []
    for kind in r:
        for e in kind.iter("entry"):
            v = next((_int(e.findtext(t)) for t in ("DegreesC", "RPMs", "Volts", "value") if e.findtext(t)), np.nan)
            rows.append(dict(kind=kind.tag.lower(), description=e.findtext("description") or "",
                             alarm=(e.findtext("alarm") or "").strip() == "True", value=v,
                             min=_int(e.findtext("min")), max=_int(e.findtext("max"))))
    return pd.DataFrame(rows, columns=["kind", "description", "alarm", "value", "min", "max"])


def scale_xml(get) -> pd.DataFrame:
    """Rule counts and table sizes with the limits the firewall reports - like dataset._scale, without the object
    counts that need the configuration."""
    rows = []
    for metric, stem in (("security_rules", "security_policy"), ("nat_rules", "nat_policy"),
                         ("decryption_rules", "decryption_policy"), ("pbf_rules", "pbf_policy")):
        if (r := get(stem)) is not None:
            rows.append((metric, simple.running_rules(_text(r)), None, "rules in effect"))
    for metric, stem in (("arp_entries", "arp"), ("ndp_entries", "neighbor"), ("mac_entries", "mac")):
        if (r := get(stem)) is not None and r.findtext("total") is not None:
            rows.append((metric, _int(r.findtext("total")), _int(r.findtext("max")), "table"))
    if (r := get("fib")) is not None and r.findtext("total") is not None:
        mx = [_int(x.text) for x in r.findall("fibs/entry/max")]
        rows.append(("fib_total", _int(r.findtext("total")), max(mx) if mx else None, "table"))
    for metric, stem, path in (("userid_mappings_mp", "userid_count", ".//count"),
                               ("dag_ips", "registered_ip", ".//count"), ("gp_users", "gp_stats", "TotalCurrentUsers")):
        if (r := get(stem)) is not None and r.findtext(path) is not None:
            rows.append((metric, _int(r.findtext(path)), None, "runtime"))
    return pd.DataFrame(rows, columns=["metric", "used", "device_limit", "source"])


def inventory(files: dict[str, Path]) -> tuple[dict, dict]:
    """Newest hourly files -> (meta, tables): SSL proxy, decryption rules, commits, TLS stats, interfaces, VPN,
    rules and tables against the model limits, health."""
    meta, t = {}, {}
    get = lambda stem: _xml(files[stem] / f"{stem}.xml") if stem in files else None
    if (r := get("decrypt_setting")) is not None:
        meta["decrypt"] = simple.decrypt_setting(_text(r))
        if (m := get("decrypt_memory")) is not None:
            meta["decrypt"]["cert_cache_entries"] = simple.cert_cache_entries(_text(m))
    if (r := get("decrypt_exclude")) is not None:
        t["decrypt_exclude"] = simple.decrypt_exclude(_text(r))
    su = scale_xml(get)
    if not su.empty:
        t["scale_used"] = su
    if (r := get("jobs")) is not None:
        t["commits"] = commits_xml(r)
    if (r := get("ssl_stats")) is not None:
        t["tls_stats"] = simple.tls_stats(_text(r))
    if (r := get("interface_all")) is not None:
        t["if_hw"], t["if_logical"], meta["device_ips"] = interfaces_xml(r)
    if (r := get("counter_interface")) is not None:
        t["if_counters"] = interface_counters_xml(r)
    for key, stem, fn in (("vpn_tunnels", "vpn_flow", vpn_flow_xml), ("vpn_sa", "vpn_ipsec_sa", ipsec_sa_xml),
                          ("ha", "ha", ha_xml), ("environment", "environmentals", environmentals_xml)):
        if (r := get(stem)) is not None:
            t[key] = fn(r)
    for key, stem, fn in (("disk", "disk_space", simple.disk_space), ("software", "software_status",
                                                                      simple.software_status)):
        if (r := get(stem)) is not None:
            t[key] = fn(_text(r))
    return meta, t


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
    inv_files: dict[str, Path] = {}  # newest sample directory holding each hourly file
    for d in sorted((coll / "samples").glob("*")):
        if since is not None and (dt := _dir_time(d.name)) is not None and dt < since:
            continue
        for stem in INVENTORY:
            if (d / f"{stem}.xml.gz").exists() or (d / f"{stem}.xml").exists():
                inv_files[stem] = d
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

    inv_meta, inv_t = inventory(inv_files)
    meta.update(inv_meta)
    t.update(inv_t)

    for kind in ("traffic", "threat", "decryption"):
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
