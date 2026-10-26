"""Extended: capacity - measured peaks against the model's limits, and how much more traffic the dataplane
could take at the current traffic mix (from how DP load grows with the packet rate).

Session maximum comes from the firewall itself. Datasheet values (throughput, connections per second) are not
shipped with the tool - published figures differ between sources and PAN-OS versions. Enter the ones from the
official datasheet in the config file to compare against them:

    [capacity PA-3410]
    firewall_gbps = ...     # firewall throughput (App-ID, appmix)
    threat_gbps = ...       # threat prevention throughput
    ipsec_gbps = ...        # IPsec VPN throughput
    cps = ...               # new sessions per second
"""

import numpy as np
import pandas as pd

TITLE = "Capacity - how much headroom is left"

CEILING = 80  # % DP load treated as the practical limit (latency and drops rise above)


def _dp_load_vs_pps(ds) -> pd.DataFrame:
    """10-minute intervals: mean DP load (resource monitor, all DP cores) and packets/s."""
    if not (ds.has("dpm_minute") and ds.has("dp_counter_rates")):
        return pd.DataFrame()
    cores = ds.meta.get("dp_cores") or []
    m = ds["dpm_minute"]
    load = m[m.core.isin(cores)].groupby("ts")["avg"].mean().sort_index()
    r = ds["dp_counter_rates"]
    pps = r[r.name == "pkt_recv"].set_index("ts").rate.sort_index()
    if load.empty or len(pps) < 10:
        return pd.DataFrame()
    step = pd.Series(pps.index).diff().median()
    vals = [load[(load.index > t - step) & (load.index <= t)].mean() for t in pps.index]
    return pd.DataFrame({"load": vals, "pps": pps.values}, index=pps.index).dropna()


def build(ctx):
    ds = ctx.ds
    si = ds.meta.get("session_info") or {}
    sess = ds["dpm_session"] if ds.has("dpm_session") else pd.DataFrame()
    if not si and sess.empty:
        return []
    model = ds.meta.get("model", "?")
    sheet = (ctx.settings.get("capacity") or {}).get(model, {})
    out = [ctx.h1(TITLE), ctx.p(
        f"How close this {model} gets to its limits. Measured peaks are the highest of the 'show session info' "
        "snapshots the dp-monitor logs take every 10 minutes (about the last two days); bursts between two "
        "snapshots are not seen. The session maximum is "
        "reported by the firewall itself."
        + ("" if sheet else f" No datasheet values are configured for the {model}; add a <i>[capacity {model}]</i> "
           "block to the config file (firewall_gbps, threat_gbps, ipsec_gbps, cps) to compare against them."))]

    rows = []
    if not sess.empty:
        def peak(col, scale=1.0):
            return float(sess[col].max()) * scale if col in sess.columns and sess[col].notna().any() else np.nan
        gbps = peak("kbps", 1e-6)
        rows.append(("Throughput", f"{gbps:,.2f} Gbit/s", sheet.get("threat_gbps") or sheet.get("firewall_gbps"),
                     gbps, "Gbit/s",
                     "threat prevention" if sheet.get("threat_gbps") else "firewall" if sheet.get("firewall_gbps") else ""))
        rows.append(("Packets per second", f"{peak('pps'):,.0f}", None, None, "", ""))
        c = peak("cps")
        rows.append(("New sessions per second", f"{c:,.0f}", sheet.get("cps"), c, "/s", ""))
    alloc = sess.sessions_allocated.max() if "sessions_allocated" in sess.columns and not sess.empty else si.get("sessions_allocated")
    if si.get("sessions_supported"):
        rows.append(("Sessions in the table", f"{alloc:,.0f}", si["sessions_supported"], alloc, "", "firewall"))
    tab = []
    for name, measured, limit, val, unit, src in rows:
        lim = "-" if not limit else (f"{limit:,.2f} {unit}".strip() if unit == "Gbit/s" else f"{limit:,.0f}")
        use = "-" if not limit or val is None or pd.isna(val) else f"{val / float(limit) * 100:.0f}%"
        tab.append((name, measured, lim + (f" ({src})" if limit and src else ""), use))
    out.append(ctx.h2("Peaks against the limits"))
    out.append(ctx.table(pd.DataFrame(tab, columns=["metric", "measured peak", "limit", "used"]), [5.0, 3.6, 5.0, 2.0]))
    out.append(ctx.small("Datasheet figures are measured under ideal lab conditions with a fixed traffic mix; real "
                         "traffic usually reaches the limit earlier. Treat 'used' as a rough indication."))

    # --- headroom from load vs packet rate ------------------------------------------------
    df = _dp_load_vs_pps(ds)
    if len(df) >= 10 and df.pps.std() > 0:
        r = df.load.corr(df.pps)
        k, d = np.polyfit(df.pps, df.load, 1)
        peak_pps, peak_load = df.pps.max(), df.load.max()
        out.append(ctx.h2("Headroom of the dataplane"))
        if peak_load < 10:
            out.append(ctx.p(
                f"The dataplane was at most {peak_load:.1f}% busy ({peak_pps:,.0f} packets/s in the busiest 10-minute "
                "interval). That is too little load to extrapolate from - there is plenty of headroom."))
        elif r >= 0.8 and k > 0:
            pps_limit = (CEILING - d) / k
            factor = pps_limit / peak_pps
            out.append(ctx.p(
                f"DP load rises in step with the packet rate (r = {r:.2f}): about {k * 1e5:.2f} points per 100,000 "
                f"packets/s on top of a base load of {max(d, 0):.0f}%. Extending that line, the dataplane reaches "
                f"{CEILING}% at about <b>{pps_limit:,.0f} packets/s</b> - {factor:.1f}x the busiest 10-minute "
                f"interval measured ({peak_pps:,.0f} packets/s at {peak_load:.0f}% load)."))
            out.append(ctx.small(f"Assumes the same traffic mix (applications, packet sizes, features). New "
                                 f"inspection features, more decryption or smaller packets shrink the headroom. "
                                 f"{CEILING}% is used as the practical ceiling because latency and drops grow above it."))
            lvl = "warning" if factor < 1.25 else "notice" if factor < 2 else "info"
            ctx.find(lvl, "Capacity", f"At the current traffic mix the dataplane reaches {CEILING}% load at about "
                                      f"{factor:.1f}x the busiest measured packet rate ({peak_pps:,.0f} packets/s, "
                                      f"{peak_load:.0f}% load).")
        else:
            out.append(ctx.p(
                f"DP load doesn't follow the packet rate closely enough (r = {r:.2f}) to extrapolate. The busiest "
                f"10-minute interval had {peak_pps:,.0f} packets/s at {peak_load:.0f}% DP load."))
    return out
