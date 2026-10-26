"""Collector operations (used by the pan-ngfw-load CLI): samples, log export, device info, permission test.

Directory layout per device (<data_dir>/devices/<name>/):
    device.json                    host + last 'show system info' summary
    system_info.xml                last 'show system info'
    state.json                     last sample time, last exported log time per type
    samples/YYYYMMDD_HHMMSS/*.xml   raw API answers, one directory per sample
    logs/<type>_<from>_<to>.csv.gz exported logs (deduplicated by seqno when loaded)
"""

from __future__ import annotations

import csv
import gzip
import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path

from ..config import Config, Device
from .api import POW_XML, Api, ApiError

log = logging.getLogger("pan-ngfw-load")

# op commands per sample: file stem -> CLI command (all read-only 'show')
SAMPLE_CMDS = {
    "clock": "show clock",
    "resource_monitor": "show running resource-monitor",
    "session_info": "show session info",
    "counter_global": "show counter global",
    "app_statistics": "show running application statistics",
    "system_resources": "show system resources",
}

TRAFFIC_FIELDS = [
    "receive_time", "time_generated", "start", "elapsed", "subtype", "action", "session_end_reason",
    "rule", "from", "to", "inbound_if", "outbound_if", "src", "sport", "dst", "dport", "natsrc", "natdst", "proto",
    "app", "category_of_app", "subcategory_of_app", "technology_of_app", "risk_of_app", "category",
    "bytes", "bytes_sent", "bytes_received", "packets", "pkts_sent", "pkts_received", "repeatcnt",
    "flag-decrypt-forwarded", "s_decrypted", "flag-proxy", "flag-tunnel-inspected", "flag-l7-skipped", "offloaded",
    "tunnel", "tunneled_app", "flags", "sessionid", "seqno",
]
THREAT_FIELDS = [
    "receive_time", "time_generated", "subtype", "action", "severity", "threatid", "thr_category", "direction",
    "rule", "from", "to", "src", "dst", "dport", "proto", "app", "category", "filetype", "sessionid", "seqno",
]
TS_FMT = "%Y/%m/%d %H:%M:%S"  # PAN-OS log time format


# --- helpers ---------------------------------------------------------------
def apis(dev: Device) -> tuple[Api, Api | None]:
    main = Api(dev.host, dev.key_file, dev.fingerprint_file)
    diag = None
    if dev.diag_key_file is not None and dev.diag_key_file.exists():
        diag = Api(dev.host, dev.diag_key_file, dev.fingerprint_file)
    return main, diag


def save_xml(path: Path, elem: ET.Element, compress: bool = False) -> None:
    data = ET.tostring(elem, encoding="unicode")
    if compress:
        with gzip.open(path.with_name(path.name + ".gz"), "wt") as fh:
            fh.write(data)
    else:
        path.write_text(data)


def load_state(ddir: Path) -> dict:
    f = ddir / "state.json"
    try:
        return json.loads(f.read_text())
    except (OSError, ValueError):
        return {}


def save_state(ddir: Path, state: dict) -> None:
    tmp = ddir / "state.json.tmp"
    tmp.write_text(json.dumps(state, indent=2) + "\n")
    tmp.replace(ddir / "state.json")


# --- operations ------------------------------------------------------------
def device_info(cfg: Config, dev: Device, api: Api) -> dict:
    ddir = cfg.device_dir(dev.name)
    r = api.op_cli("show system info")
    save_xml(ddir / "system_info.xml", r)
    s = r.find("system")
    info = {k: s.findtext(k) for k in ("hostname", "model", "serial", "sw-version", "uptime", "app-version",
                                        "threat-version", "ip-address")}
    (ddir / "device.json").write_text(json.dumps({"name": dev.name, "host": dev.host, **info}, indent=2) + "\n")
    return info


def log_range(api: Api, log_type: str) -> tuple[str | None, str | None]:
    newest = api.logs(log_type, nlogs=1, poll=1.0)
    oldest = api.logs(log_type, nlogs=1, poll=1.0, direction="forward")
    f = lambda e: e.findtext("logs/entry/receive_time") if e is not None else None
    return f(oldest), f(newest)


def take_sample(cfg: Config, dev: Device, api: Api, diag: Api | None) -> tuple[Path, list[str]]:
    ddir = cfg.device_dir(dev.name)
    if not (ddir / "system_info.xml").exists():
        device_info(cfg, dev, api)
    ts = datetime.now()
    d = ddir / "samples" / ts.strftime("%Y%m%d_%H%M%S")
    d.mkdir(parents=True, exist_ok=True)
    errors = []
    for stem, cli in SAMPLE_CMDS.items():
        try:
            save_xml(d / f"{stem}.xml", api.op_cli(cli), compress=True)
        except ApiError as e:
            errors.append(f"{stem}: {e}")
    if diag is not None:
        try:
            save_xml(d / "pow_performance.xml", diag.op(POW_XML), compress=True)
        except ApiError as e:
            errors.append(f"pow_performance: {e}")
    if errors:
        (d / "errors.txt").write_text("\n".join(errors) + "\n")
        for e in errors:
            log.warning("%s sample %s: %s", dev.name, d.name, e)
    st = load_state(ddir)
    st["last_sample"] = ts.isoformat(timespec="seconds")
    save_state(ddir, st)
    # refresh system info once a day (uptime -> boot time for the reports)
    if datetime.now().timestamp() - (ddir / "system_info.xml").stat().st_mtime > 86400:
        device_info(cfg, dev, api)
    return d, errors


def export_logs(cfg: Config, dev: Device, api: Api, log_type: str, since: datetime, until: datetime,
                query_filter: str | None = None, max_logs: int = 2_000_000, stop=lambda: False) -> tuple[int, str | None]:
    """Export logs in [since, until] to a new CSV.gz. Pages backwards in time (newest first),
    moving the upper bound down; duplicates in the same second are skipped by seqno.
    Returns (count, newest receive_time seen)."""
    fields = list(dict.fromkeys(TRAFFIC_FIELDS if log_type == "traffic" else THREAT_FIELDS))
    out_dir = cfg.device_dir(dev.name) / "logs"
    out_dir.mkdir(exist_ok=True)
    s_since, s_until = since.strftime(TS_FMT), until.strftime(TS_FMT)
    out = out_dir / f"{log_type}_{since:%Y%m%d_%H%M%S}_{until:%Y%m%d_%H%M%S}.csv.gz"
    tmp = out.with_suffix(".tmp")
    seen, total, upper, newest = set(), 0, s_until, None
    with gzip.open(tmp, "wt", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        while not stop() and total < max_logs:
            q = f"(receive_time geq '{s_since}') and (receive_time leq '{upper}')"
            if query_filter:
                q += f" and ({query_filter})"
            res = api.logs(log_type, query=q, nlogs=5000)
            entries = res.findall("logs/entry") if res is not None else []
            new, oldest = 0, upper
            for e in entries:
                sq, rt = e.findtext("seqno"), e.findtext("receive_time") or ""
                if rt and rt < oldest:
                    oldest = rt
                if rt and (newest is None or rt > newest):
                    newest = rt
                if sq in seen:
                    continue
                seen.add(sq)
                w.writerow({f: e.findtext(f, "") for f in fields})
                new += 1
            total += new
            log.info("%s %s logs: +%d (total %d), reached %s", dev.name, log_type, new, total, oldest)
            if len(entries) < 5000 or new == 0:
                if new == 0 and len(entries) == 5000:
                    log.warning("%s: more than 5000 %s logs in one second - some may be missing", dev.name, log_type)
                break
            upper = oldest
    if total:
        tmp.replace(out)
    else:
        tmp.unlink()
    return total, newest


def incremental_logs(cfg: Config, dev: Device, api: Api, stop=lambda: False) -> dict[str, int]:
    """Export everything since the last run (first run: cfg.log_initial back). 5 min overlap, dedupe on load."""
    ddir = cfg.device_dir(dev.name)
    st = load_state(ddir)
    last = st.setdefault("last_log_time", {})
    now = datetime.now()
    result = {}
    for lt in cfg.log_types:
        if lt in last:
            since = datetime.strptime(last[lt], TS_FMT) - timedelta(minutes=5)
        else:
            since = now - timedelta(seconds=cfg.log_initial)
        n, newest = export_logs(cfg, dev, api, lt, since, now, stop=stop)
        if newest:
            last[lt] = newest
        result[lt] = n
        save_state(ddir, st)
    return result


def permission_test(dev: Device) -> list[tuple[str, str, bool | None, str]]:
    """(key, check, expected_allowed, outcome). Only read operations; config probes bypass the
    local allow-list on purpose to verify the role on the device side (content is discarded)."""
    rows = []
    keys = [("main", dev.key_file)] + ([("diag", dev.diag_key_file)] if dev.diag_key_file else [])
    for label, kf in keys:
        if kf is None or not kf.exists():
            rows.append((label, "key file", True, f"missing: {kf}"))
            continue
        a = Api(dev.host, kf, dev.fingerprint_file)
        # layout A: main key is also the diag key (custom role) -> config must be denied.
        # layout B: main key is a read-only superreader, which may read the config by design.
        layout_a = dev.diag_key == dev.key or label == "diag"
        checks = [
            ("op show system info", True, lambda: a.op_cli("show system info")),
            ("log query (traffic)", True, lambda: a.logs("traffic", nlogs=1, poll=1.0)),
            ("op debug pow performance", True if (label == "diag" or dev.diag_key == dev.key) else None,
             lambda: a.op(POW_XML)),
            ("config read (running)", False if layout_a else None,
             lambda: a._request({"type": "config", "action": "show", "xpath": "/config/devices"}, unchecked=True)),
            ("config read (candidate)", False if layout_a else None,
             lambda: a._request({"type": "config", "action": "get", "xpath": "/config/mgt-config"}, unchecked=True)),
        ]
        for name, expected, fn in checks:
            try:
                fn()
                rows.append((label, name, expected, "allowed"))
            except ApiError as e:
                rows.append((label, name, expected, "denied" if "403" in str(e) or "rror" in str(e) else str(e)[:60]))
    return rows
