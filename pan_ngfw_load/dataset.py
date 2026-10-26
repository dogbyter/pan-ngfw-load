"""Build every table from a bundle and keep them in one Dataset object.

All tables are pandas DataFrames, saved as CSV under <out>/data/ so they can
be re-used (Excel, ad-hoc pandas, later comparisons between bundles).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

from . import knowledge as K
from .bundle import Bundle
from .parsers import monitor, powperf, resmon, sar, simple
from .parsers.cli import CliDump, parse_clock, parse_kv, parse_uptime

WINDOW_NAMES = {1: "second", 60: "minute", 3600: "hour", 86400: "day", 604800: "week"}


@dataclass
class Dataset:
    bundle: Bundle | None
    source: str = "tsf"  # "tsf" or "live"
    meta: dict = field(default_factory=dict)
    t: dict[str, pd.DataFrame] = field(default_factory=dict)  # all tables
    notes: list[str] = field(default_factory=list)  # parser caveats for the report

    def __getitem__(self, k: str) -> pd.DataFrame:
        return self.t.get(k, pd.DataFrame())

    def has(self, k: str) -> bool:
        return k in self.t and not self.t[k].empty

    def save(self, outdir: Path) -> None:
        d = outdir / "data"
        d.mkdir(parents=True, exist_ok=True)
        for k, df in self.t.items():
            if not df.empty:
                df.to_csv(d / f"{k}.csv", index=False)
        pd.Series(self.meta, dtype=object).to_csv(d / "_meta.csv", header=["value"])


def build(bundle: Bundle) -> Dataset:
    ds = Dataset(bundle=bundle)
    _from_cli(ds)
    _from_dp_monitor(ds)
    _from_mp_monitor(ds)
    _from_sar(ds)
    _coverage(ds)
    return ds


def build_live(coll: Path, since: datetime | None = None) -> Dataset:
    """Dataset from a collector device directory; since limits the time window."""
    from .parsers import live

    ds = Dataset(bundle=None, source="live")
    res = live.load(coll, since)
    ds.meta.update(res["meta"])
    ds.meta.setdefault("hostname", coll.name)
    ds.meta["bundle"] = f"live {coll.name}"
    ds.meta["uptime"] = "?"
    if res["rm_latest"] is not None:
        _rm_tables(ds, res["rm_latest"], ds.meta["tsf_time"])
    ds.t.update({k: v for k, v in res["tables"].items()})
    boot = ds.meta.get("boot_time")
    if boot is not None:  # per-minute history reaches back 60 min, possibly before the reboot
        for k in ("dpm_minute", "dpm_util"):
            if ds.has(k):
                ds.t[k] = ds[k][ds[k].ts > boot].reset_index(drop=True)
    ds.meta["dp_core_count"] = len(ds.meta.get("dp_cores") or []) or 1
    if "_pow_latest" in ds.t:  # accumulated since boot, from the newest sample
        ds.t["pow_boot"] = _enrich_pow(ds.t.pop("_pow_latest"))
    _derive_pow(ds)
    _derive_rates(ds)
    if not ds.has("dpm_session"):
        ds.notes.append("No samples yet - run 'pan-ngfw-load sample' (or wait for the cron job).")
    _coverage(ds)
    return ds


def _rm_tables(ds: Dataset, rm: dict, now: datetime) -> None:
    """resource-monitor dict (CLI or API) -> rm_cpu, rm_util, rm_groups.

    Samples whose period ended before the last boot are set to NaN: the CLI shows them as '*',
    but the XML API reports 0 for them.
    """
    boot = ds.meta.get("boot_time")
    cpu_rows, util_rows = [], []
    for step, w in rm["windows"].items():
        wname = WINDOW_NAMES.get(step, str(step))
        cpu = w["cpu"]
        for i, a_row in enumerate(cpu.get("avg", [])):
            m_row = cpu["max"][i] if cpu.get("max") else [np.nan] * len(a_row)
            end = now - timedelta(seconds=step * i)
            stale = boot is not None and end <= boot
            for c, a, mx in zip(cpu["cores"], a_row, m_row):
                cpu_rows.append((wname, step, i, end, c, np.nan if stale else a, np.nan if stale else mx))
        for metric, vals in w["util"].items():
            for i, v in enumerate(vals):
                end = now - timedelta(seconds=step * i)
                util_rows.append((wname, step, i, end, metric, np.nan if boot is not None and end <= boot else v))
    ds.t["rm_cpu"] = pd.DataFrame(cpu_rows, columns=["window", "step_s", "idx", "end", "core", "avg", "max"])
    ds.t["rm_util"] = pd.DataFrame(util_rows, columns=["window", "step_s", "idx", "end", "metric", "value"])
    ds.t["rm_groups"] = pd.DataFrame(list(rm["groups"].items()), columns=["group", "pct"])


# ---------------------------------------------------------------------------
def _from_cli(ds: Dataset) -> None:
    if not ds.bundle.cli_dump:
        ds.notes.append("No CLI dump (tmp/cli/techsupport_*.txt) found.")
        return
    d = CliDump(ds.bundle.cli_dump)
    si = parse_kv(d.get("show system info") or "")
    now = parse_clock(d.get("show clock") or "") or datetime.fromtimestamp(ds.bundle.cli_dump.stat().st_mtime)
    up = parse_uptime(si.get("uptime", ""))
    ds.meta.update(
        hostname=si.get("hostname", "?"), model=si.get("model", "?"), serial=si.get("serial", "?"),
        sw_version=si.get("sw-version", "?"), app_version=si.get("app-version", "?"),
        threat_version=si.get("threat-version", "?"), ip=si.get("ip-address", "?"),
        uptime=si.get("uptime", "?"), tsf_time=now,
        boot_time=(now - timedelta(seconds=up)) if up else None, bundle=ds.bundle.name,
    )

    from .anonymize import interface_ips
    ds.meta["device_ips"] = interface_ips(d.get("show interface all") or "")

    rm_text = d.get("show running resource-monitor")
    if rm_text:
        rm = resmon.parse(rm_text)
        ds.meta["dp_cores"] = resmon.dp_cores(rm)
        _rm_tables(ds, rm, now)

    pp = d.get("debug dataplane pow performance all")
    if pp:
        df = powperf.parse(pp)
        ds.t["pow_boot"] = _enrich_pow(df[df.core == -1].drop(columns="core"))
    for cmd, _ in d.sections:  # per-core tables (may be split over several commands)
        if cmd.startswith("debug dataplane pow performance all core"):
            df = powperf.parse(d.get(cmd))
            if not df.empty:
                ds.t["pow_core"] = pd.concat([ds["pow_core"], _enrich_pow(df)], ignore_index=True)

    if (txt := d.get("show running application statistics")):
        ds.t["apps"] = simple.app_statistics(txt)
    if (txt := d.get("show session all")):
        ds.t["sessions_now"] = simple.session_list(txt)
    if (txt := d.get("show session info")):
        ds.meta["session_info"] = simple.session_info(txt)
    if (txt := d.get("show counter global")):
        _el, gc = simple.global_counters(txt)
        ds.t["counters_boot"] = gc
    for key, cmd, fn in (("ha", "show high-availability all", simple.ha_status),
                         ("environment", "show system environmentals", simple.environmentals),
                         ("disk", "show system disk-space", simple.disk_space),
                         ("software", "show system software status", simple.software_status),
                         ("if_hw", "show interface all", simple.interface_hw),
                         ("vpn_tunnels", "show vpn flow", simple.vpn_flow),
                         ("vpn_sa", "show vpn ipsec-sa", simple.ipsec_sa)):
        if (txt := d.get(cmd)):
            ds.t[key] = fn(txt)
    if ds.bundle.crashinfo:
        ds.t["crashes"] = simple.crashinfo(ds.bundle.crashinfo)
    if (txt := d.get("debug dataplane pow status", -1)):  # repeated in a TSF; the last one is the newest
        ds.t["pow_status"] = simple.pow_status(txt)
    if (txt := d.get("show counter interface all")):
        ifc = simple.interface_counters(txt)
        cfg_xml = ds.bundle.root / "opt/pancfg/mgmt/saved-configs/running-config.xml"
        if cfg_xml.exists():
            ifc = ifc.merge(simple.ipsec_tunnels(cfg_xml), on="interface", how="left")
        ds.t["if_counters"] = ifc


def _enrich_pow(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["stage"] = np.where(df.kind == "group", df.name.map(K.group_stage), None)
    df["feature"] = np.where(df.kind == "func", df.name.map(lambda n: K.func_feature(n) or "(latency, not CPU)"), None)
    return df


def _from_dp_monitor(ds: Dataset) -> None:
    if not ds.bundle.dp_monitor:
        ds.notes.append("No dp-monitor.log* files found.")
        return
    t = monitor.dp_monitor(ds.bundle.dp_monitor)
    ds.t.update(t)
    ncores = len(ds.meta.get("dp_cores") or []) or max(1, t["dpm_minute"].core.nunique() - 1)
    ds.meta["dp_core_count"] = ncores

    _derive_pow(ds)
    _derive_rates(ds)


def _derive_pow(ds: Dataset) -> None:
    """pow performance: accumulated -> per-interval CPU share of total DP capacity."""
    pw = ds["dpm_pow"]
    ncores = ds.meta.get("dp_core_count") or 1
    if pw.empty:
        return
    pw = pw.sort_values("ts")
    wide = pw.pivot_table(index="ts", columns=["kind", "name"], values="ac_total_us", aggfunc="last")
    if len(wide) < 2:
        return
    dt = wide.index.to_series().diff().dt.total_seconds()
    delta = wide.diff()
    delta[delta < 0] = np.nan  # counter reset (dataplane restart)
    pct = delta.div(dt * ncores * 1e6, axis=0) * 100
    long = pct.stack(["kind", "name"], future_stack=True).rename("pct").reset_index()
    long["interval_s"] = long.ts.map(dt)
    long = long.dropna(subset=["pct"])
    long["stage"] = np.where(long.kind == "group", long.name.map(K.group_stage), None)
    long["feature"] = np.where(long.kind == "func", long.name.map(lambda n: K.func_feature(n) or "(latency, not CPU)"), None)
    ds.t["dp_pow_interval"] = long


def _derive_rates(ds: Dataset) -> None:
    """Global counters: cumulative -> per-second rate per sampling interval."""
    gc = ds["dpm_counters"]
    if not gc.empty:
        wide = gc.pivot_table(index="ts", columns="name", values="value", aggfunc="last").sort_index()
        dt = wide.index.to_series().diff().dt.total_seconds()
        rate = wide.diff().div(dt, axis=0)
        rate[rate < 0] = np.nan
        ds.t["dp_counter_rates"] = rate.stack(future_stack=True).dropna().rename("rate").reset_index()


def _from_mp_monitor(ds: Dataset) -> None:
    if ds.bundle.mp_monitor:
        ds.t.update(monitor.mp_monitor(ds.bundle.mp_monitor))


def _from_sar(ds: Dataset) -> None:
    if not ds.bundle.sar_text:
        return
    tabs = sar.parse_all(ds.bundle.sar_text)
    cpu = tabs.get("CPU_%usr")
    if cpu is not None:
        cpu = cpu[cpu.CPU != "all"].copy()
        cpu["core"] = cpu.CPU.astype(float).astype(int)
        cpu["busy"] = 100 - cpu["%idle"]
        dp = set(ds.meta.get("dp_cores") or [])
        cpu["role"] = np.where(cpu.core.isin(dp), "DP worker (busy-poll, ignore)", "MP")
        ds.t["sar_cpu"] = cpu.drop(columns="CPU")
    for key, name in (("runq-sz_plist-sz", "sar_load"), ("kbmemfree_kbavail", "sar_mem"), ("IFACE_rxpck/s", "sar_net")):
        if key in tabs:
            ds.t[name] = tabs[key]


def _coverage(ds: Dataset) -> None:
    """Which period does each source cover? Drives the 'data coverage' table."""
    rows = []
    now, boot = ds.meta.get("tsf_time"), ds.meta.get("boot_time")

    def add(source, what, start, end, res):
        rows.append((source, what, start, end, res))

    live = ds.source == "live"
    rm_src = "resource-monitor (API)" if live else "resource-monitor (CLI)"
    smp = "collector samples (API)" if live else "dp-monitor.log*"
    if ds.has("rm_cpu"):
        rc = ds["rm_cpu"]
        dp = ds.meta.get("dp_cores") or []
        for step, wname in WINDOW_NAMES.items():
            sub = rc[(rc.step_s == step) & rc.core.isin(dp)].dropna(subset=["avg"])
            if not sub.empty:
                start = sub.end.min() - timedelta(seconds=step)
                if boot is not None and start < boot:
                    start = boot
                add(rm_src, f"DP core load per {wname}", start, now, wname)
    if ds.has("pow_boot") and boot:
        add("pow performance (CLI)", "DP CPU time by group/function, accumulated", boot, now, "total since boot")
    if ds.has("apps") and boot:
        add("application statistics", "Sessions/packets/bytes per app, accumulated", boot, now, "total since boot")
    if ds.has("dpm_session"):
        s = ds["dpm_session"]
        res = f"~{s.ts.sort_values().diff().median().total_seconds() / 60:.0f} min" if len(s) > 1 else "1 sample"
        add(smp, "Session rates, counters" + ("" if live else ", pow perf"), s.ts.min(), s.ts.max(), res)
    if ds.has("dpm_minute"):
        m = ds["dpm_minute"]
        add(smp, "DP core load per minute (reconstructed)", m.ts.min(), m.ts.max(), "1 min")
    if ds.has("mpm_summary"):
        m = ds["mpm_summary"]
        add("collector samples (API)" if live else "mp-monitor.log*", "MP load average, CPU, memory, processes",
            m.ts.min(), m.ts.max(), "per sample" if live else "~3-10 min")
    if ds.has("sar_cpu"):
        m = ds["sar_cpu"]
        add("sar (var/log/sa)", "Linux CPU per core (MP meaningful only)", m.ts.min(), m.ts.max(), "10 min")
    for kind in ("traffic", "threat"):
        if ds.has(f"logs_{kind}"):
            lg = ds[f"logs_{kind}"]
            add(f"{kind} logs (API)", f"{len(lg):,} {kind} log entries", lg.receive_time.min(), lg.receive_time.max(), "per session")
    cov = pd.DataFrame(rows, columns=["source", "content", "start", "end", "resolution"])
    cov["days"] = (pd.to_datetime(cov.end) - pd.to_datetime(cov.start)).dt.total_seconds() / 86400
    ds.t["coverage"] = cov
