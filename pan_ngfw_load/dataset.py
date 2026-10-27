"""Build every table from a bundle and keep them in one Dataset object.

All tables are pandas DataFrames, saved as CSV under <out>/data/ so they can
be re-used (Excel, ad-hoc pandas, later comparisons between bundles).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

from . import knowledge as K
from .bundle import Bundle, _dp_key
from .parsers import monitor, powperf, resmon, sar, simple
from .parsers.cli import CliDump, parse_clock, parse_kv, parse_uptime, split_dp

WINDOW_NAMES = {1: "second", 60: "minute", 3600: "hour", 86400: "day", 604800: "week"}

# Tables and meta keys that belong to one dataplane. On chassis models (several DPs) they hold the DP
# chosen with select_dp(); everything else covers the whole firewall.
DP_TABLES = ("rm_cpu", "rm_util", "rm_groups", "pow_boot", "pow_core", "pow_status", "dpm_session", "dpm_groups15s",
             "dpm_counters", "dpm_pow", "dpm_minute", "dpm_util", "dp_pow_interval", "dp_counter_rates")
DP_META = ("dp_cores", "dp_core_count", "dp")


@dataclass
class Dataset:
    bundle: Bundle | None
    source: str = "tsf"  # "tsf" or "live"
    meta: dict = field(default_factory=dict)
    t: dict[str, pd.DataFrame] = field(default_factory=dict)  # all tables
    notes: list[str] = field(default_factory=list)  # parser caveats for the report
    dp_cli: dict = field(default_factory=dict)  # per DP (None = single-DP model): raw CLI texts of DP commands
    _dpm: dict = field(default_factory=dict)  # per DP: parsed dp-monitor tables (cache)
    nodes: dict = field(default_factory=dict)  # cluster report: node id -> that node's own Dataset

    @property
    def non_leader(self) -> bool:
        """TSF of an NGFW cluster node that is not the leader: management, routing (BGP ...) and LACP run on the
        leader, so this node's view of them is not the cluster's."""
        if self.nodes or not self.has("cluster"):
            return False
        me = self["cluster"][self["cluster"].this]
        return not me.empty and me.leader.iloc[0] != "yes"

    @property
    def dps(self) -> list[str]:
        """DP names on chassis models ('s3dp0', ...), [] on single-DP models."""
        names = {k for k in self.dp_cli if k} | set(self.bundle.dp_logs if self.bundle else ())
        return sorted(names, key=_dp_key)

    def __getitem__(self, k: str) -> pd.DataFrame:
        return self.t.get(k, pd.DataFrame())

    def has(self, k: str) -> bool:
        return k in self.t and not self.t[k].empty

    def save(self, outdir: Path, only: tuple | None = None, sub: str = "") -> None:
        d = outdir / "data" / sub
        d.mkdir(parents=True, exist_ok=True)
        for k, df in self.t.items():
            if only is not None and k not in only:
                continue
            if not df.empty:
                df.to_csv(d / f"{k}.csv", index=False)
        if only is None:
            pd.Series(self.meta, dtype=object).to_csv(d / "_meta.csv", header=["value"])


def build(bundle: Bundle, dp: str | None = None) -> Dataset:
    """dp: on chassis models the DP whose details the DP sections show (default: the busiest)."""
    ds = Dataset(bundle=bundle)
    _from_cli(ds)
    if ds.dps:
        if dp is not None and dp not in ds.dps:
            raise SystemExit(f"unknown DP '{dp}' - this firewall has: {', '.join(ds.dps)}")
        _dp_compare(ds)
        if dp is None and ds.has("dp_compare"):
            dp = ds["dp_compare"].sort_values("mean", ascending=False).dp.iloc[0]
        select_dp(ds, dp or ds.dps[0])
    else:
        if dp is not None:
            raise SystemExit("--dp: this firewall has a single dataplane")
        select_dp(ds, None)
    _from_mp_monitor(ds)
    _from_sar(ds)
    _coverage(ds)
    return ds


def build_cluster(bundles: list[Bundle]) -> Dataset:
    """NGFW cluster (PA-7500): one Dataset from the TSFs of both nodes.

    Each node counts only what its own dataplanes processed (inferred from the counters: received and sent bytes
    balance only over both nodes), so counters are added up. Management, configuration, routing and logs run on the
    leader - its Dataset is the base. The nodes' own Datasets stay in ds.nodes for the per-node parts."""
    dss = [build(b) for b in bundles]
    ids = []
    for d in dss:
        cl = d.meta.get("cluster") or {}
        if not d.has("cluster") or not cl.get("node_id"):
            raise SystemExit(f"{d.bundle.name}: not a node of an NGFW cluster - a cluster report needs the TSFs of "
                             "both nodes of one cluster")
        ids.append((cl.get("cluster_id"), cl["node_id"]))
    if len({c for c, _ in ids}) != 1 or len({n for _, n in ids}) != len(ids):
        raise SystemExit("the TSFs are not from the nodes of one cluster (cluster ID / node ID: "
                         + ", ".join(f"{c}/{n}" for c, n in ids) + ")")
    nodes = {n: d for (_c, n), d in zip(ids, dss)}
    leaders = [n for n, d in nodes.items() if (d["cluster"].this & (d["cluster"].leader == "yes")).any()]
    lead = leaders[0] if len(leaders) == 1 else min(nodes)
    ld = nodes[lead]  # the base is a copy: the nodes keep their own values for the per-node views
    base = Dataset(bundle=ld.bundle, source=ld.source, meta=dict(ld.meta), t=dict(ld.t), notes=list(ld.notes),
                   dp_cli=ld.dp_cli, _dpm=ld._dpm)
    base.nodes = dict(sorted(nodes.items()))
    if len(leaders) != 1:
        base.notes.append("The TSFs do not agree on the cluster leader - node %s is used as the base." % lead)
    times = [d.meta.get("tsf_time") for d in nodes.values()]
    if all(times) and max(times) - min(times) > timedelta(hours=2):
        base.notes.append(f"The TSFs of the nodes were taken {(max(times) - min(times)).total_seconds() / 3600:.0f} "
                          "hours apart - values 'now' are from different times.")
    for n, d in [*nodes.items(), (lead, base)]:
        d.meta["node"] = n
        d.meta["dp_label"] = f"node {n} {d.meta.get('dp')}"
    base.meta.update(cluster_nodes=sorted(nodes), cluster_leader=lead)

    # counters are each node's share - add them up
    def summed(key, by):
        parts = [d[key].assign(node=n) for n, d in nodes.items() if d.has(key)]
        if not parts:
            return None, None
        allp = pd.concat(parts, ignore_index=True)
        by = [c for c in by if c in allp.columns]
        num = [c for c in allp.columns if c not in by + ["node"] and pd.api.types.is_numeric_dtype(allp[c])]
        other = [c for c in allp.columns if c not in num + by + ["node"]]
        tot = allp.groupby(by, sort=False).agg({**{c: "sum" for c in num}, **{c: "first" for c in other}}).reset_index()
        return tot, allp
    for key, by in (("if_counters", ["interface"]), ("counters_boot", ["name"]), ("apps", ["vsys", "app"])):
        tot, allp = summed(key, by)
        if tot is not None:
            base.t[key] = tot[[c for c in allp.columns if c != "node"]]
            if key == "if_counters":
                base.t["if_counters_nodes"] = allp
    si = [d.meta.get("session_info") or {} for d in nodes.values()]
    if all(si):
        tot = {k: sum(x.get(k) or 0 for x in si) for k in si[0] if isinstance(si[0][k], (int, float)) and k != "session_util_pct"}
        tot["session_util_pct"] = tot["sessions_allocated"] / tot["sessions_supported"] * 100 if tot.get("sessions_supported") else 0
        base.meta["session_info"] = {**si[0], **tot}
    if all(d.has("sessions_now") for d in nodes.values()):
        base.t["sessions_now"] = pd.concat([d["sessions_now"] for d in nodes.values()], ignore_index=True)
    # all DPs of both nodes side by side, named like the interfaces ('n1:s7dp0')
    for key in ("dp_compare", "dp_compare_5min"):
        if all(d.has(key) for d in nodes.values()):
            base.t[key] = pd.concat([d[key].assign(dp=f"n{n}:" + d[key].dp) for n, d in nodes.items()], ignore_index=True)
    base.meta["dp_shown"] = [f"n{n}:{d.meta.get('dp')}" for n, d in nodes.items()]
    return base


def select_dp(ds: Dataset, name: str | None) -> None:
    """Load one DP's resource-monitor, pow performance/status and dp-monitor history into the DP tables."""
    for k in DP_TABLES:
        ds.t.pop(k, None)
    for k in DP_META:
        ds.meta.pop(k, None)
    ds.meta["dp"] = name
    texts = ds.dp_cli.get(name, {})
    now = ds.meta.get("tsf_time")
    if texts.get("rm"):
        rm = resmon.parse(texts["rm"])
        ds.meta["dp_cores"] = resmon.dp_cores(rm)
        _rm_tables(ds, rm, now)
    if texts.get("pp"):
        df = powperf.parse(texts["pp"])
        ds.t["pow_boot"] = _enrich_pow(df[df.core == -1].drop(columns="core"))
    for txt in texts.get("pp_core", []):  # per-core tables (may be split over several commands)
        df = powperf.parse(txt)
        if not df.empty:
            ds.t["pow_core"] = pd.concat([ds["pow_core"], _enrich_pow(df)], ignore_index=True)
    if texts.get("pow_status"):
        ds.t["pow_status"] = simple.pow_status(texts["pow_status"])
    t = _dp_monitor_tables(ds, name)
    if t is None:
        ds.meta["dp_core_count"] = len(ds.meta.get("dp_cores") or []) or 1
        return
    ds.t.update(t)
    ds.meta["dp_core_count"] = len(ds.meta.get("dp_cores") or []) or max(1, t["dpm_minute"].core.nunique() - 1)
    _derive_pow(ds)
    _derive_rates(ds)
    if ds.has("coverage"):  # coverage depends on the DP as well
        _coverage(ds)


def _dp_monitor_tables(ds: Dataset, name: str | None) -> dict | None:
    if name not in ds._dpm:
        files = ds.bundle.dp_logs.get(name, []) if name else ds.bundle.dp_monitor
        ds._dpm[name] = monitor.dp_monitor(files) if files else None
        if not files and name is None:
            ds.notes.append("No dp-monitor.log* files found.")
    return ds._dpm[name]


def _dp_compare(ds: Dataset) -> None:
    """Chassis: load of every DP side by side (dp_compare), from its dp-monitor history (per minute) or,
    without one, from the hourly resource-monitor window."""
    rows, minutes = [], []
    cards = ds.meta.get("slot_cards") or {}
    for name in ds.dps:
        texts = ds.dp_cli.get(name, {})
        card = cards.get(int(re.match(r"s(\d+)", name).group(1)), "")
        rm = resmon.parse(texts["rm"]) if texts.get("rm") else None
        cores = resmon.dp_cores(rm) if rm else []
        t = _dp_monitor_tables(ds, name)
        src, series, per_core = None, None, None
        if t is not None and not t["dpm_minute"].empty:
            m = t["dpm_minute"]
            m = m[m.core.isin(cores)] if cores else m
            wide = m.pivot_table(index="ts", columns="core", values="avg")
            series, per_core, src = wide.mean(axis=1), wide.mean(), "dp-monitor (per minute)"
            peak = m["max"].max()
            five = series.resample("5min").mean().dropna()
            minutes += [(ts, name, v) for ts, v in five.items()]
        elif rm and rm["windows"].get(3600, {}).get("cpu", {}).get("avg"):
            w = rm["windows"][3600]["cpu"]
            wide = pd.DataFrame(w["avg"], columns=w["cores"])[cores or w["cores"]]
            series, per_core, src = wide.mean(axis=1), wide.mean(), "resource-monitor (per hour)"
            peak = pd.DataFrame(w["max"], columns=w["cores"])[cores or w["cores"]].max().max() if w.get("max") else np.nan
        if series is None or series.dropna().empty:
            rows.append(dict(dp=name, card=card, cores=len(cores) or np.nan, mean=np.nan, p95=np.nan, max=np.nan,
                             core_peak=np.nan, busiest_core="", hours=np.nan, source="no data"))
            continue
        series = series.dropna()
        hours = ((series.index.max() - series.index.min()).total_seconds() / 3600
                 if isinstance(series.index, pd.DatetimeIndex) else len(series))
        rows.append(dict(dp=name, card=card, cores=len(cores) or len(per_core), mean=series.mean(), p95=series.quantile(0.95),
                         max=series.max(), core_peak=peak, busiest_core=f"{per_core.idxmax()} ({per_core.max():.0f}%)",
                         hours=hours, source=src))
    ds.t["dp_compare"] = pd.DataFrame(rows)
    ds.t["dp_compare_5min"] = pd.DataFrame(minutes, columns=["ts", "dp", "avg"])  # mean of the DP's cores


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

    cards = {}  # chassis: card model per slot
    for line in (d.get("show chassis inventory") or "").splitlines():
        if (m := re.match(r"^(\d+)\s+(PA-\S+)", line)):
            cards[int(m.group(1))] = m.group(2)
    if cards:
        ds.meta["slot_cards"] = cards
    # dataplane commands: chassis models print one block per DP - kept per DP, loaded by select_dp()
    for dp, txt in split_dp(d.get("show running resource-monitor")).items():
        ds.dp_cli.setdefault(dp, {})["rm"] = txt
    for dp, txt in split_dp(d.get("debug dataplane pow performance all")).items():
        ds.dp_cli.setdefault(dp, {})["pp"] = txt
    for cmd, out in d.sections:  # per-core tables (may be split over several commands)
        if " ".join(cmd.split()).startswith("debug dataplane pow performance all core"):
            for dp, txt in split_dp(out).items():
                ds.dp_cli.setdefault(dp, {}).setdefault("pp_core", []).append(txt)
    # repeated in a TSF; the last one is the newest
    for dp, txt in split_dp(d.get("debug dataplane pow status", -1)).items():
        ds.dp_cli.setdefault(dp, {})["pow_status"] = txt

    if (txt := d.get("show running application statistics")):
        ds.t["apps"] = simple.app_statistics(txt)
    if (txt := d.get("show session all")):
        ds.t["sessions_now"] = simple.session_list(txt)
    if (txt := d.get("show session info")):
        ds.meta["session_info"] = simple.session_info(txt)
    if (txt := d.get("show cluster all")) and "not enabled" not in txt:
        ds.meta["cluster"] = simple.cluster_settings(txt)
    if (txt := d.get("show counter global")):
        _el, gc = simple.global_counters(txt)
        ds.t["counters_boot"] = gc
    for key, cmd, fn in (("ha", "show high-availability all", simple.ha_status),
                         ("environment", "show system environmentals", simple.environmentals),
                         ("cluster", "show cluster all", simple.cluster_status),
                         ("chassis", "show chassis status", simple.chassis_status),
                         ("disk", "show system disk-space", simple.disk_space),
                         ("software", "show system software status", simple.software_status),
                         ("if_hw", "show interface all", simple.interface_hw),
                         ("vpn_tunnels", "show vpn flow", simple.vpn_flow),
                         ("vpn_sa", "show vpn ipsec-sa", simple.ipsec_sa)):
        if (txt := d.get(cmd)):
            ds.t[key] = fn(txt)
    if ds.bundle.crashinfo:
        ds.t["crashes"] = simple.crashinfo(ds.bundle.crashinfo)
    _scale(ds, d)
    if (txt := d.get("show counter interface all")):
        ifc = simple.interface_counters(txt)
        cfg_xml = simple.config_file(ds.bundle.root)
        if cfg_xml is not None:
            ifc = ifc.merge(simple.ipsec_tunnels(cfg_xml), on="interface", how="left")
        ds.t["if_counters"] = ifc
    if (txt := d.get("show interface all")):
        lg = simple.interface_logical(txt)
        cfg_xml = simple.config_file(ds.bundle.root)
        zones = simple.interface_zones(cfg_xml) if cfg_xml is not None else {}
        if zones:
            lg["zone"] = lg.interface.map(zones).fillna(lg.zone)
        ds.t["if_logical"] = lg
    members = {}
    cfg_xml = simple.config_file(ds.bundle.root)
    if cfg_xml is not None:
        members = simple.ae_members(cfg_xml)
    lc = simple.lacp(d.get("show lacp aggregate-ethernet all") or "")
    for r in lc.itertuples():  # LACP output also knows members a template-pushed config may not show
        members.setdefault(r.interface, r.ae)
    if members:
        ae = pd.DataFrame(sorted(members.items(), key=lambda kv: (kv[1], kv[0])), columns=["interface", "ae"])
        ds.t["ae_members"] = ae.merge(lc.drop(columns=["ae"]), on="interface", how="left")


def _scale(ds: Dataset, d) -> None:
    """Configuration and table sizes in use, with the limits the firewall reports itself (scale_used)."""
    rows = []  # metric, used, device limit, source
    cfg_xml = simple.config_file(ds.bundle.root)
    cfg = simple.config_scale(cfg_xml) if cfg_xml is not None else {}
    ds.meta["config_source"] = ("" if cfg_xml is None else "configuration incl. what Panorama pushed"
                                if cfg.get("panorama_managed") else "configuration")
    for metric, cmd in (("security_rules", "show running security-policy"), ("nat_rules", "show running nat-policy"),
                        ("decryption_rules", "show running decryption-policy"), ("pbf_rules", "show running pbf-policy")):
        txt = d.get(cmd)
        n = simple.running_rules(txt) if txt is not None else None
        # output cut short in the TSF (seen on a PA-7500: only rule 1 per DP) - disabled rules may legitimately
        # make the running count lower than the configuration, so only an almost empty output counts as cut short
        if n is not None and metric in cfg and n <= 1 and cfg[metric] >= 10:
            rows.append((metric, cfg[metric], None, "configuration (running output incomplete)"))
        elif n is not None:
            rows.append((metric, n, None, "rules in effect"))
        elif metric in cfg:
            rows.append((metric, cfg[metric], None, "configuration"))
    for metric in ("app_override_rules", "dos_rules", "qos_rules", "address_objects", "address_groups",
                   "service_objects", "service_groups", "edl_lists", "url_custom_categories", "zones", "virtual_routers"):
        if metric in cfg:
            rows.append((metric, cfg[metric], None, "configuration"))
    for metric, cmd, kind in (("arp_entries", "show arp all", "ARP"), ("ndp_entries", "show neighbor interface all", "neighbor"),
                              ("mac_entries", "show mac all", "MAC")):
        if (txt := d.get(cmd)):
            used, mx = simple.table_usage(txt, kind)
            if used is not None:
                rows.append((metric, used, mx, "table"))
    for cmd in ("show routing fib", "show advanced-routing fib"):
        if (txt := d.get(cmd)):
            used, mx = simple.fib_usage(txt)
            if used is not None:
                rows.append(("fib_total", used, mx, "table"))
                break
    for metric, cmd in (("userid_mappings_mp", "show user ip-user-mapping-mp all option count"),
                        ("dag_ips", "show object registered-ip all option count"),
                        ("gp_users", "show global-protect-gateway statistics")):
        n = simple.total_count(d.get(cmd) or "")
        if n is not None:
            rows.append((metric, n, None, "runtime"))
    ds.t["scale_used"] = pd.DataFrame(rows, columns=["metric", "used", "device_limit", "source"]).drop_duplicates("metric")
    ds.meta["panorama_managed"] = bool(cfg.get("panorama_managed"))


def _enrich_pow(df: pd.DataFrame) -> pd.DataFrame:
    df = df[~((df.kind == "group") & df.name.isin(K.NOT_CPU_GROUPS))].copy()  # waiting time, not CPU
    df["stage"] = np.where(df.kind == "group", df.name.map(K.group_stage), None)
    df["feature"] = np.where(df.kind == "func", df.name.map(lambda n: K.func_feature(n) or "(latency, not CPU)"), None)
    return df


def _derive_pow(ds: Dataset) -> None:
    """pow performance: accumulated -> per-interval CPU share of total DP capacity."""
    pw = ds["dpm_pow"]
    if not pw.empty:
        pw = pw[~((pw.kind == "group") & pw.name.isin(K.NOT_CPU_GROUPS))]
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
        dp = set() if ds.dps else set(ds.meta.get("dp_cores") or [])  # chassis: the MP is a card of its own
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
