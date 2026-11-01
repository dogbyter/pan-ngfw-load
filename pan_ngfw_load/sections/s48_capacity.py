"""Extended: capacity - measured peaks against the model's limits, and how much more traffic the dataplane
could take at the current traffic mix (from how DP load grows with the packet rate).

The session maximum comes from the firewall itself. Datasheet values (throughput, connections per second) come only
from the public product comparison (pan_ngfw_load/capacity.py); missing ones are named in the report.
"""

import numpy as np
import pandas as pd

from .. import capacity as CAP

TITLE = "Capacity - how much headroom is left"
DP_SCOPED = "partly"  # chassis: rates and load over time come from one DP (see dataset.select_dp)

CEILING = 80  # % DP load treated as the practical limit (latency and drops rise above)
TLS_NOTICE = 70  # % of a TLS/SSL limit


def _tls(ctx, sheet: dict) -> list:
    """TLS / SSL decryption: every value the firewall reports or the configuration holds against the model's
    public limits (decrypted sessions, certificate cache, inbound certificates, rules) plus rates without a limit."""
    ds = ctx.ds
    c = ds["counters_boot"].set_index("name").value if ds.has("counters_boot") else pd.Series(dtype=float)
    now = lambda n: float(c.get(n, 0) or 0)
    dc = ds["dpm_counters"] if ds.has("dpm_counters") else pd.DataFrame(columns=["ts", "name", "value"])
    gauge = dc[dc.name.isin(["proxy_sessions_forward", "proxy_sessions"])].pivot_table(
        index="ts", columns="name", values="value", aggfunc="last").fillna(0)  # missing sample = 0
    rates = ds["dp_counter_rates"] if ds.has("dp_counter_rates") else pd.DataFrame(columns=["ts", "name", "rate"])
    rate = lambda *names: rates[rates.name.isin(names)].groupby("ts").rate.sum()
    su = ds["scale_used"].set_index("metric").used if ds.has("scale_used") else pd.Series(dtype=float)
    st = ds.meta.get("decrypt") or {}
    if not (st or c.index.str.startswith(("proxy_", "ssl_")).any() or any(k in sheet for k in (
            "ssl_decrypt_sessions", "other:ssl_decryption_ssl_certificate_cache", "ssl_inbound_certs"))):
        return []

    def peak(col):
        w = gauge[col].max() if col in gauge else np.nan
        return np.nanmax([w, now(col)])

    new_dec, checked = rate("proxy_acc_convert_to_forward_proxy", "proxy_acc_convert_to_inbound_proxy"), \
        rate("proxy_process_accumulation")
    rows = [  # metric, measured, limit key, how measured
        ("Decrypted sessions at the same time", peak("proxy_sessions_forward"), "ssl_decrypt_sessions",
         "peak of the 10-minute samples and now"),
        ("All SSL proxy sessions at the same time", peak("proxy_sessions"), None,
         "incl. no-decrypt checks and firewall-terminated TLS"),
        ("SSL certificate cache", st.get("cert_cache_entries"), "other:ssl_decryption_ssl_certificate_cache",
         "entries now"),
        ("Inbound inspection certificates", su.get("ssl_inbound_certs"), "ssl_inbound_certs", "configuration"),
        ("Decryption rules", su.get("decryption_rules"), "decryption_rules", "rules in effect"),
        ("New decrypted sessions per second", new_dec.max() if len(new_dec) else np.nan, None,
         "busiest 10-minute interval"),
        ("TLS sessions checked per second", checked.max() if len(checked) else np.nan, None,
         "busiest 10-minute interval"),
        ("GlobalProtect clientless VPN SSL tunnels", np.nan, "other:globalprotect_clientless_vpn_max_ssl_tunnels",
         "not in the TSF"),
    ]
    tab = []
    for name, measured, key, how in rows:
        limit = sheet.get(key) if key else None
        whole = measured is not None and pd.notna(measured) and (measured >= 10 or float(measured).is_integer())
        m = "-" if measured is None or pd.isna(measured) else f"{measured:,.0f}" if whole else f"{measured:,.2f}"
        use = measured / limit * 100 if limit and measured is not None and pd.notna(measured) else None
        tab.append((name, m, "-" if not limit else f"{limit:,.0f}",
                    "-" if use is None else ("<1%" if 0 < use < 1 else f"{use:.0f}%"), how))
        # decrypted sessions and the certificate cache have their findings in 'TLS and Decryption'
        if use is not None and use >= TLS_NOTICE and key in ("ssl_inbound_certs", "decryption_rules"):
            ctx.find("warning" if use >= 90 else "notice", "Capacity", f"{name}: {m} of {limit:,.0f} ({use:.0f}%).",
                     whole=True)
    notes = CAP.limits(ctx.settings, ds.meta.get("model", ""))[1]
    feats = [f"{lab}: {notes.get(k, '-')}" for lab, k in (("HSM", "other:ssl_decryption_hsm_supported"),
             ("decryption port mirror", "other:ssl_decryption_decryption_port_mirror"),
             ("network packet broker", "other:ssl_decryption_network_packet_broker")) if notes.get(k)]
    out = [ctx.h2("TLS and decryption against the limits"),
           ctx.table(pd.DataFrame(tab, columns=["metric", "measured", "limit", "used", "measured how"]),
                     [5.4, 2.2, 2.0, 1.4, 6.0]),
           ctx.small("Limits from the public product comparison; '-' where it has none. Details on decryption: "
                     "section 'TLS and Decryption'."
                     + (f" Decryption features of the model - {', '.join(feats)}." if feats else "")
                     + (" On chassis models the per-second rates and peaks come from one DP." if ds.dps else ""))]
    return out


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
    sw = ds.meta.get("sw_version", "")
    sheet, _notes, src, status = CAP.limits(ctx.settings, model)
    gap = CAP.hint(model, status, CAP.missing(sheet, ["threat_appmix_gbps", "fw_appmix_gbps", "cps"]))
    out = [ctx.h1(TITLE), ctx.p(
        f"How close this {model} gets to its limits. Measured peaks are the highest of the 'show session info' "
        "snapshots the dp-monitor logs take every 10 minutes (about the last two days); bursts between two "
        "snapshots are not seen. The session maximum is "
        "reported by the firewall itself."
        + (f" Datasheet values: {src} (no PAN-OS version stated there)." if sheet else "")
        + (f" <b>Note:</b> {gap}" if gap else ""))]

    rows = []
    if not sess.empty:
        def peak(col, scale=1.0):
            return float(sess[col].max()) * scale if col in sess.columns and sess[col].notna().any() else np.nan
        gbps = peak("kbps", 1e-6)
        if sheet.get("threat_appmix_gbps"):
            rows.append(("Throughput", f"{gbps:,.2f} Gbit/s", sheet["threat_appmix_gbps"], gbps, "Gbit/s",
                         "threat prevention, appmix"))
        if sheet.get("fw_appmix_gbps"):
            rows.append(("Throughput", f"{gbps:,.2f} Gbit/s", sheet["fw_appmix_gbps"], gbps, "Gbit/s",
                         "firewall / App-ID, appmix"))
        if not (sheet.get("threat_appmix_gbps") or sheet.get("fw_appmix_gbps")):
            rows.append(("Throughput", f"{gbps:,.2f} Gbit/s", None, gbps, "Gbit/s", ""))
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
    out.append(ctx.table(pd.DataFrame(tab, columns=["metric", "measured peak", "limit", "used"]), [4.2, 3.2, 7.0, 2.0]))
    out.append(ctx.small("Datasheet figures are measured under ideal lab conditions with a fixed traffic mix; real "
                         "traffic usually reaches the limit earlier. Treat 'used' as a rough indication."))
    over = [t for t in tab if t[3].endswith("%") and t[3] != "-" and float(t[3][:-1]) > 100]
    if over:
        out.append(ctx.p(
            "<b>Above 100% of a datasheet value</b> is possible without an overload: the datasheet assumes every "
            "packet goes through that inspection with its test mix, while real traffic is partly not inspected (IPsec "
            "pass-through, application overrides, rules without security profiles) or uses larger packets. Whether "
            "the dataplane is really close to its limit shows in its load - see the headroom below."))

    out += _tls(ctx, sheet)

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
