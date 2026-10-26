"""Extended: configuration and table sizes against the model's limits - rules, objects, zones, routers,
interfaces, ARP/neighbor/MAC/route tables, tunnels, User-ID. Limits the firewall reports itself come first;
datasheet values come from the optional capacity files (pan_ngfw_load/capacity.py)."""

import pandas as pd

from .. import capacity as CAP

TITLE = "Configuration against model limits"

NOTICE, WARN = 70, 90  # % of the limit


def _derived(ds) -> list[tuple]:
    """Sizes computed from tables other sections use as well."""
    rows = []
    if ds.has("if_logical"):
        lg = ds["if_logical"]
        rows.append(("interfaces", len(lg), None, "interface list"))
        tags = pd.to_numeric(lg.tag, errors="coerce")
        rows.append(("vlan_tags", int((tags > 0).sum()), None, "interface list"))
        rows.append(("aggregates", int(lg.interface.str.match(r"^ae\d+$").sum()), None, "interface list"))
    if ds.has("vpn_tunnels"):
        rows.append(("ipsec_tunnels", len(ds["vpn_tunnels"]), None, "runtime"))
    si = ds.meta.get("session_info") or {}
    if si.get("sessions_supported"):
        peak = ds["dpm_session"].sessions_allocated.max() if ds.has("dpm_session") else si.get("sessions_allocated", 0)
        rows.append(("sessions", peak, si["sessions_supported"], "runtime (peak)"))
    return rows


def build(ctx):
    ds = ctx.ds
    used = ds["scale_used"] if ds.has("scale_used") else pd.DataFrame(columns=["metric", "used", "device_limit", "source"])
    used = pd.concat([used, pd.DataFrame(_derived(ds), columns=used.columns)], ignore_index=True).drop_duplicates("metric")
    if used.empty:
        return []
    model, sw = ds.meta.get("model", "?"), ds.meta.get("sw_version", "")
    sheet, notes, ver = CAP.limits(ctx.settings, model, sw)

    rows = []
    for metric, (label, _unit) in CAP.METRICS.items():
        if metric.endswith("_gbps") or metric == "cps":
            continue
        u = used[used.metric == metric]
        if u.empty:
            continue
        r = u.iloc[0]
        dev = r.device_limit if pd.notna(r.device_limit) else None
        ds_val = sheet.get(metric)
        limit = dev or ds_val
        if dev and ds_val and abs(dev - ds_val) > 0.5:
            lim_txt = f"{dev:,.0f} (firewall; datasheet {ds_val:,.0f})"
        elif dev:
            lim_txt = f"{dev:,.0f} (firewall)"
        elif ds_val:
            lim_txt = f"{ds_val:,.0f}"
        else:
            lim_txt = "-"
        if metric in notes and "(PAN-" in notes[metric]:
            lim_txt += " *"
        pct = r.used / limit * 100 if limit else None
        rows.append(dict(item=label, used=r.used, limit=lim_txt, pct=pct, source=r.source))
    if not rows:
        return []
    tab = pd.DataFrame(rows)

    intro = (f"How much of this {model}'s configuration and table capacity is in use. <b>in use</b> comes from the "
             "tech support file: rules in effect (including rules pushed by Panorama), the configuration"
             + (f" ({ds.meta['config_source']})" if ds.meta.get("config_source") else "")
             + ", and the live tables (ARP, neighbors, MAC, routes). Where the firewall reports its own limit, that "
             "one is used; otherwise the datasheet value.")
    if sheet:
        intro += f" Datasheet values: PAN-OS {ver}" + (
            f" - this firewall runs {sw}; limits can differ between versions." if ver and sw and
            not sw.startswith(".".join(ver.split(".")[:2])) else ".")
    else:
        intro += (" No datasheet values are configured, so only the limits the firewall reports itself are shown. "
                  "Set <i>capacity_files</i> in the config file to compare all items (see docs/SETUP.md).")
    out = [ctx.h1(TITLE), ctx.p(intro)]

    def status(p):
        if p is None or pd.isna(p):
            return "-"
        col = "#d03b3b" if p >= WARN else "#eda100" if p >= NOTICE else None
        txt = f"{p:.0f}%" if p >= 1 else "<1%"
        return f"<font color='{col}'><b>{txt}</b></font>" if col else txt

    out.append(ctx.table(tab.rename(columns={"used": "in use", "pct": "used"}), [5.2, 2.0, 5.2, 1.6, 3.0],
                         fmt={"in use": lambda v: f"{v:,.0f}", "used": status}, max_rows=60))
    if any("*" in x for x in tab.limit):
        out.append(ctx.small("* The datasheet value carries a reference to a known defect for this item."))
    out.append(ctx.small("Limits are per firewall. Some datasheet values count differently than the firewall does "
                         "(e.g. interfaces include physical ports, rules are counted over all vsys) - treat small "
                         "differences near the limit with care."))

    for r in tab.itertuples():
        if r.pct is not None and pd.notna(r.pct) and r.pct >= NOTICE:
            ctx.find("warning" if r.pct >= WARN else "notice", "Scale",
                     f"{r.item}: {r.used:,.0f} in use, {r.pct:.0f}% of the limit ({r.limit}).")
    top = tab.dropna(subset=["pct"]).sort_values("pct", ascending=False).head(1)
    if not top.empty and top.pct.iloc[0] < NOTICE:
        ctx.find("info", "Scale", f"All configuration and table sizes are below {NOTICE}% of their limits "
                                  f"(highest: {top.item.iloc[0]} {top.pct.iloc[0]:.0f}%).")
    return out
