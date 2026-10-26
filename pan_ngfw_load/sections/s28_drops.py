"""Extended: drops and errors - the global counters with severity drop/error/warn, grouped by what they usually
mean, with the rate when the data was taken and over time."""

import re

import pandas as pd

from .. import charts as C

TITLE = "Drops and errors"

# (theme, pattern, explanation) - first match wins
THEMES = [
    ("Cloud lookups skipped", r"^ctd_(wif|adns)\w*bypass|^ctd_adns_",
     "Inline cloud analysis that was skipped for single sessions - WildFire inline ML (quota, flags) or Advanced "
     "DNS (no cloud connection, cache). The session itself was still inspected locally; many entries here point to "
     "an unstable connection to the cloud services."),
    ("Inspection skipped", r"^ctd_err_bypass|^ctd_skip_offset|^ctd_\w*(overlimit|exceed)\w*bypass",
     "Packets that passed <b>without full content inspection</b> - e.g. because an inspection limit was hit. "
     "Security-relevant: threats in these packets are not seen."),
    ("Policy and expected", r"^flow_policy_deny|^flow_tcp_non_syn|^flow_fwd_l3_ttl_zero|^flow_host_service|"
                            r"^flow_ipv6_disabled|^tcp_new_syn|^flow_dos_(?!pbp)|^flow_.*_land",
     "Mostly normal: traffic denied by a rule, TCP packets without a session (after a timeout or with asymmetric "
     "routing), expired TTL, connections to the management services. Watch the trend rather than the total."),
    ("Network and configuration", r"^flow_rcv_dot1q|^flow_no_interface|^flow_fwd_l3_noarp|^flow_fwd_l3_mcast|"
                                  r"^flow_fwd_notopology|^flow_ingress_ifp|^flow_fwd_pbf|^flow_fwd_mtu|"
                                  r"^flow_fwd_.*route|^flow_rcv_.*err|^pkt_recv_err|^flow_ipfrag",
     "Traffic the firewall can't forward the way it arrives: VLAN tags without a matching subinterface, next hops "
     "that don't answer ARP, multicast without a route, packets larger than the MTU, invalid PBF next hops. "
     "Usually a configuration or neighbour issue, and each such packet still costs DP time."),
    ("TCP quality", r"^tcp_",
     "Problems in the TCP streams themselves: out-of-order segments beyond the reorder queue, packets outside the "
     "window, failed reassembly. Points to loss or reordering on the path; such packets can't be inspected in order."),
    ("Resources and protection", r"pbp|alloc_fail|_full|nobuf|^flow_dos_pbp|^pkt_(recv_)?skip",
     "A pool ran out or packet buffer protection dropped packets (see the resource section)."),
    ("Sessions and HA", r"^session_|^flow_predict|^flow_ager|^ha_",
     "Session-table bookkeeping: hash collisions, install races, HA sync messages for sessions that no longer "
     "exist. Small numbers are normal on a busy firewall."),
    ("Tunnels", r"^flow_tunnel|^flow_gre",
     "IPsec/GRE packets that didn't match a tunnel or session (e.g. after a rekey or with NAT-T)."),
]


# Counters PAN-OS rates only 'info' but that matter here (inspection bypass on errors, receive pressure)
ALSO = r"^ctd_err_bypass$|^ctd_\w*bypass\w*$|^pkt_recv_skip_inflight$|^pkt_skip_rx_burst$"


def _theme(name: str) -> str:
    for t, pat, _x in THEMES:
        if re.search(pat, name):
            return t
    return "Other"


def build(ctx):
    ds = ctx.ds
    if not ds.has("counters_boot") or "severity" not in ds["counters_boot"].columns:
        return []
    c = ds["counters_boot"]
    c = c[(c.severity.isin(["drop", "error", "warn"]) | c.name.str.match(ALSO)) & (c.value > 0)].copy()
    if c.empty:
        return []
    c["theme"] = c.name.map(_theme)
    out = [ctx.h1(TITLE), ctx.p(
        "PAN-OS counts every dropped packet and every error in global counters, each with a severity "
        "(<i>drop</i>, <i>error</i>, <i>warn</i>) and a short description. A few counters PAN-OS rates only "
        "<i>info</i> are included because they matter here (inspection bypassed on errors, receive pressure). The values below are totals since the "
        "last boot; <b>rate</b> is per second when the data was taken. Most drops are by design (policy); the "
        "interesting ones are drops that cost DP work without need, or that hide traffic from inspection.")]

    tot = c.groupby("theme").agg(counters=("name", "size"), total=("value", "sum")).reset_index()
    order = [t for t, _p, _x in THEMES] + ["Other"]
    tot["o"] = tot.theme.map(order.index)
    tot = tot.sort_values("o")
    out.append(ctx.h2("Overview"))
    out.append(ctx.table(tot[["theme", "counters", "total"]].rename(columns={"total": "packets / events since boot"}),
                         [6.0, 2.0, 5.0], fmt={"packets / events since boot": lambda v: f"{v:,.0f}"}))

    for theme, _pat, expl in THEMES + [("Other", "", "Counters without a theme above - see their descriptions.")]:
        g = c[c.theme == theme].sort_values("value", ascending=False)
        if g.empty:
            continue
        out.append(ctx.h2(theme))
        out.append(ctx.p(expl))
        out.append(ctx.table(g.head(8)[["name", "value", "rate", "severity", "description"]],
                             [5.4, 2.4, 1.4, 1.4, 6.4],
                             fmt={"value": lambda v: f"{v:,.0f}", "rate": lambda v: "-" if pd.isna(v) else f"{v:,.0f}"}))

    # --- over time ------------------------------------------------------------------------
    if ds.has("dp_counter_rates"):
        r = ds["dp_counter_rates"]
        top = c[c.theme != "Policy and expected"].sort_values("value", ascending=False).name.head(6).tolist()
        r = r[r.name.isin(top)]
        if not r.empty and r.ts.nunique() >= 3:
            w = r.pivot_table(index="ts", columns="name", values="rate").sort_index()
            span = (w.index.max() - w.index.min()).total_seconds() / 86400
            cmap = C.colors_for(list(w.columns))
            f, ax = C.fig(C.W, 2.5)
            for n in w.columns:
                ax.plot(w.index, w[n], color=cmap[n], lw=1, label=n)
            ax.set_ylabel("per second")
            ax.set_title("Largest drop/error counters over time (without policy drops)")
            C.time_axis(ax, span)
            C.legend_below(ax, 2)
            out.append(ctx.figure(f, "drops_time"))

    # --- findings -------------------------------------------------------------------------
    pol = c[c.name == "flow_policy_deny"]
    if not pol.empty:
        ctx.find("info", "Drops", f"{pol.value.iloc[0]:,.0f} sessions denied by policy since boot"
                                  + (f" ({pol.rate.iloc[0]:,.0f}/s now)." if pd.notna(pol.rate.iloc[0]) else "."))
    byp = c[c.theme == "Inspection skipped"]
    if not byp.empty and byp.value.sum() >= 1000:
        ctx.find("notice", "Drops", "Packets passed without full content inspection since boot: " + ", ".join(
            f"{n} {v:,.0f}" for n, v in zip(byp.name, byp.value)) + ".")
    net = c[c.theme.isin(["Network and configuration", "TCP quality"])].sort_values("value", ascending=False).head(3)
    if not net.empty:
        ctx.find("notice", "Drops", "Largest avoidable drops since boot: " + "; ".join(
            f"{r.description.lower() if r.description else r.name} ({r.value:,.0f})" for r in net.itertuples()) + ".")
    return out
