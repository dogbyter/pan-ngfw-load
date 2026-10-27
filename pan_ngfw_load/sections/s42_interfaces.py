"""Extended: physical interfaces - traffic since boot, average use of the link speed, errors and drops.
With --subinterfaces also every sub-interface and VLAN interface: zone, VLAN, router, traffic and drops."""

import pandas as pd

from .. import charts as C
from ..parsers.simple import NODE

TITLE = "Interfaces"

ERR_NOTICE = 1e-5  # receive errors per received packet (10 per million)


def build(ctx):
    ds = ctx.ds
    if not ds.has("if_counters"):
        return []
    allc = ds["if_counters"]
    ic = allc[allc.interface.str.match(rf"^{NODE}(ethernet\d+/\d+|ae\d+)$")].copy()
    ic = ic[(ic.rx_bytes > 0) | (ic.tx_bytes > 0)]
    want_sub = bool(ctx.settings.get("subinterfaces"))
    if ic.empty and not want_sub:
        return []
    boot, now = ds.meta.get("boot_time"), ds.meta.get("tsf_time")
    up = (now - boot).total_seconds() if boot is not None and now is not None else None
    if ds.has("if_hw"):
        ic = ic.merge(ds["if_hw"][["interface", "speed", "state"]], on="interface", how="left")
    else:
        ic["speed"], ic["state"] = float("nan"), ""
    for col in ("rx_errors", "rx_discards", "drops"):
        if col not in ic.columns:
            ic[col] = 0
    ic = ic.fillna({"rx_errors": 0, "rx_discards": 0, "drops": 0})
    if up:
        ic["rx_mbps"] = ic.rx_bytes * 8 / up / 1e6
        ic["tx_mbps"] = ic.tx_bytes * 8 / up / 1e6
        ic["use_pct"] = (ic[["rx_mbps", "tx_mbps"]].max(axis=1) / ic.speed * 100).where(ic.speed > 0)
    ic["err_ppm"] = ic.rx_errors / ic.rx_pkts.where(ic.rx_pkts > 0) * 1e6
    ic["pkt"] = ic.rx_bytes / ic.rx_pkts.where(ic.rx_pkts > 0)
    ic = ic.sort_values("rx_bytes", ascending=False)

    out = [ctx.h1(TITLE), ctx.p(
        "Traffic and errors per physical port and aggregate group since the last boot (dataplane counters, "
        "'show counter interface all'). The averages spread the whole period evenly, so they show which ports "
        "carry the bulk of the traffic, not how high the peaks were. An aggregate (ae) and its members both "
        "appear when both are counted."
        + (" <b>NGFW cluster:</b> each node counts only the traffic <i>its own</i> dataplanes processed, also for ports "
           "of the other chassis (packets can be processed across the HSCI links). The values here are <b>added up "
           "over all nodes</b>; the table at the end shows each node's share per port." if ds.nodes else
           " <b>NGFW cluster:</b> every node lists the ports of both chassis (<i>node1:</i>, <i>node2:</i>), and its "
           "counters hold only the traffic <i>this node's</i> dataplanes processed - packets of a port on one chassis "
           "can be processed by the other one across the HSCI links. A port's total is the sum over the TSFs of "
           "both nodes (run the report with the TSFs of all nodes for that); the values and averages here are this "
           "node's share." if ds.has("cluster") else "")
        + ("" if want_sub else " <b>Tip:</b> run the report with <b>--subinterfaces</b> for detailed statistics of "
           "every sub-interface and VLAN interface (zone, VLAN, router, traffic, drops)."))]

    show = ic[["interface", "speed", "rx_bytes", "tx_bytes"] + (["rx_mbps", "tx_mbps", "use_pct"] if up else [])
              + ["pkt", "rx_errors", "err_ppm"]].rename(columns={
                  "speed": "link", "rx_bytes": "received", "tx_bytes": "sent", "rx_mbps": "avg in",
                  "tx_mbps": "avg out", "use_pct": "avg use", "pkt": "avg pkt", "rx_errors": "rx errors",
                  "err_ppm": "errors / M pkts"})
    fmt = {"link": lambda v: "-" if pd.isna(v) else (f"{v / 1000:g}G" if v >= 1000 else f"{v:g}M"),
           "received": lambda v: C.human(v) + "B", "sent": lambda v: C.human(v) + "B",
           "avg in": lambda v: f"{v:,.0f} Mb/s", "avg out": lambda v: f"{v:,.0f} Mb/s",
           "avg use": lambda v: "-" if pd.isna(v) else f"{v:.1f}%", "avg pkt": lambda v: "-" if pd.isna(v) else f"{v:,.0f} B",
           "rx errors": lambda v: f"{v:,.0f}", "errors / M pkts": lambda v: "-" if pd.isna(v) else f"{v:.2f}"}
    widths = [2.4, 1.2, 1.8, 1.8] + ([1.9, 1.9, 1.5] if up else []) + [1.5, 1.6, 1.6]
    out.append(ctx.table(show, widths, fmt=fmt))

    phys = ic[~ic.interface.str.match(rf"^{NODE}ae")]  # an aggregate repeats its members' traffic
    out += _aggregates(ctx, allc)

    tot = phys.assign(total=phys.rx_bytes + phys.tx_bytes).set_index("interface").total
    tot = C.top_n(tot[tot > 0].astype(float), 9)
    f, ax = C.fig(C.W, 0.28 * len(tot) + 0.8)
    C.hbar(ax, tot, labeler=lambda v: C.human(v) + "B")
    ax.set_title("Traffic per physical port since boot (received + sent)")
    out.append(ctx.figure(f, "interfaces_traffic"))

    bad = ic[ic.err_ppm >= ERR_NOTICE * 1e6]
    if not bad.empty:
        out.append(ctx.p(
            "<b>Receive errors</b> are frames the port received damaged (CRC, alignment, runts). More than a few per "
            "million packets usually points to a cable, optic or the device on the other end - not to load."))
        ctx.find("notice", "Interfaces", "Receive errors above 10 per million packets: " + ", ".join(
            f"{r.interface} {r.rx_errors:,.0f} ({r.err_ppm:.1f}/M)" for r in bad.itertuples()) + ".")
    if up and ic.use_pct.notna().any() and ic.use_pct.max() >= 1:
        hi = ic.sort_values("use_pct", ascending=False).iloc[0]
        ctx.find("info", "Interfaces", f"Busiest port on average since boot: {hi.interface} "
                                       f"({hi.use_pct:.0f}% of {hi.speed / 1000:g} Gbit/s, larger direction"
                                       + (", this cluster node's share" if ds.has("cluster") and not ds.nodes else "")
                                       + ").")
    if want_sub:
        out += _subinterfaces(ctx, allc, up)
    if ds.has("if_counters_nodes"):
        out += _node_shares(ctx, phys.interface)
    return out


def _node_shares(ctx, ports) -> list:
    """Cluster report: which node's dataplanes processed how much of each port's traffic."""
    nd = ctx.ds["if_counters_nodes"]
    nd = nd[nd.interface.isin(set(ports))]
    if nd.empty:
        return []
    wide = nd.pivot_table(index="interface", columns="node", values=["rx_bytes", "tx_bytes"], aggfunc="sum")
    rows = []
    for port, r in wide.iterrows():
        row = {"port": port}
        for d, lab in (("rx_bytes", "in"), ("tx_bytes", "out")):
            tot = r[d].sum()
            row[f"{lab} total"] = tot
            for n in r[d].index:
                row[f"{lab} node {n}"] = r[d][n] / tot * 100 if tot else float("nan")
        rows.append(row)
    tab = pd.DataFrame(rows).sort_values("in total", ascending=False)
    pct = lambda v: "-" if pd.isna(v) else f"{v:.0f}%"
    fmt = {c: (lambda v: C.human_bytes(v) if pd.notna(v) else "-") if c.endswith("total") else pct
           for c in tab.columns if c != "port"}
    return [ctx.h2("Share per node"),
            ctx.small("Each port's traffic since boot, added up over the nodes, and the share each node's dataplanes "
                      "processed. A port whose traffic is processed mostly by one node shows how the cluster spreads "
                      "the sessions (by the routing and the switch in front of it), not a fault."),
            ctx.table(tab, [3.4] + [1.7] * (len(tab.columns) - 1), fmt=fmt, max_rows=60)]


def _aggregates(ctx, allc: pd.DataFrame) -> list:
    """Which physical ports belong to which aggregate group, their LACP state and their share of the traffic."""
    ds = ctx.ds
    if not ds.has("ae_members"):
        return []
    am = ds["ae_members"].merge(allc[["interface", "rx_bytes", "tx_bytes"]], on="interface", how="left")
    if ds.has("if_hw"):
        am = am.merge(ds["if_hw"][["interface", "speed", "state"]], on="interface", how="left")
    am["total"] = am.rx_bytes.fillna(0) + am.tx_bytes.fillna(0)
    am["share"] = am.total / am.groupby("ae").total.transform("sum").replace(0, float("nan")) * 100
    am = am.sort_values(["ae", "interface"], key=lambda c: c.str.replace(r"\d+", lambda m: m.group(0).zfill(4),
                                                                         regex=True) if c.dtype == object else c)
    has_lacp = am.bundled.notna().any() if "bundled" in am.columns else False
    lacp_elsewhere = has_lacp and ds.non_leader  # LACP runs on the cluster leader - this node's view is not valid
    has_lacp = has_lacp and not lacp_elsewhere
    tab = pd.DataFrame({
        "aggregate": am.ae, "member port": am.interface,
        "link": [("-" if pd.isna(sp) else (f"{sp / 1000:g}G" if sp >= 1000 else f"{sp:g}M")) + (f" {st}" if isinstance(st, str) else "")
                 for sp, st in zip(am.get("speed", pd.Series(float("nan"), index=am.index)),
                                   am.get("state", pd.Series(None, index=am.index)))],
        "traffic": am.total, "share of the group": am.share})
    widths = [2.0, 2.6, 2.0, 2.0, 2.4]
    if has_lacp:
        tab["LACP"] = [("-" if pd.isna(b) else ("in bundle" if b == "yes" else "NOT in bundle")
                        + (f", {s.lower()}" if isinstance(s, str) and s else ""))
                       for b, s in zip(am.bundled, am.selection)]
        tab["mode / rate"] = [f"{m} / {r}" if isinstance(m, str) and m else "static (no LACP)"
                              for m, r in zip(am["mode"], am["rate"])]
        widths += [3.0, 2.6]
    out = [ctx.h2("Aggregate groups (ae)"),
           ctx.small("Physical ports per aggregate group (saved config and 'show lacp aggregate-ethernet all'). "
                     "'share of the group' is each member's part of the group's traffic since boot - the firewall "
                     "spreads sessions over the members by a hash, so a very uneven split means a few large flows."
                     + (" Members on both nodes make this an MC-LAG." if am.interface.str.match(r"^node\d+:").any()
                        and am.groupby("ae").interface.apply(lambda s: s.str.extract(r"^(node\d+):")[0].nunique()).max() > 1
                        else "")
                     + (" <b>LACP state left out:</b> LACP runs on the cluster leader - this node shows its members "
                        "as not negotiated even when the bundle is up. The leader's TSF (or a cluster report from the "
                        "TSFs of all nodes) shows the real state." if lacp_elsewhere else "")),
           ctx.table(tab, widths, max_rows=200,
                     fmt={"traffic": lambda v: C.human(v) + "B" if v else "-",
                          "share of the group": lambda v: "-" if pd.isna(v) else f"{v:.0f}%"})]
    ae_tx = allc[allc.interface.isin(set(am.ae))].tx_bytes.sum()
    if am.tx_bytes.fillna(0).sum() == 0 and ae_tx > 0:  # seen on a PA-7500 cluster (MC-LAG)
        out.append(ctx.small("The member ports count only <i>received</i> traffic here; <i>sent</i> traffic is counted "
                             f"on the aggregate interface itself ({C.human(ae_tx)}B since boot), so the shares refer to "
                             "the received traffic."))
    down = am[(am.get("bundled") == "no")] if has_lacp else am.iloc[0:0]
    if not down.empty:
        ctx.find("warning", "Interfaces", "Aggregate member not in its bundle: " + ", ".join(
            f"{r.interface} ({r.ae})" for r in down.itertuples()) + ".")
    for g, grp in am.groupby("ae"):
        sh = grp.share.dropna()
        if len(sh) >= 2 and sh.max() - sh.min() >= 30:
            ctx.find("notice", "Interfaces", f"{g}: traffic is unevenly spread over its members ("
                     + ", ".join(f"{r.interface} {r.share:.0f}%" for r in grp.itertuples() if pd.notna(r.share)) + ").")
    return out


SUB_RE = rf"^({NODE}(ethernet\d+/\d+|ae\d+)\.\d+|vlan\.\d+)$"


def _subinterfaces(ctx, allc: pd.DataFrame, up: float | None) -> list:
    ds = ctx.ds
    sc = allc[allc.interface.str.match(SUB_RE)].copy()
    out = [ctx.h2("Sub-interfaces")]
    if sc.empty:
        out.append(ctx.p("This firewall has no sub-interfaces or VLAN interfaces with counters."))
        return out
    lg = ds["if_logical"] if ds.has("if_logical") else pd.DataFrame(columns=["interface", "zone", "router", "tag", "address"])
    sc = sc.merge(lg, on="interface", how="left").fillna({"zone": "", "router": "", "tag": "", "address": ""})
    for col in ("drops", "flow_state_drops", "arp_not_found", "no_route", "fwd_errors"):
        if col not in sc.columns:
            sc[col] = 0
    sc = sc.fillna({c: 0 for c in ("drops", "flow_state_drops", "arp_not_found", "no_route", "fwd_errors")})
    sc["kind"] = sc.interface.map(lambda i: "VLAN interface" if i.startswith("vlan.") else "sub-interface")
    sc["total"] = sc.rx_bytes + sc.tx_bytes
    sc["drop_ppm"] = sc.drops / sc.rx_pkts.where(sc.rx_pkts > 0) * 1e6
    if up:
        sc["rx_mbps"] = sc.rx_bytes * 8 / up / 1e6
        sc["tx_mbps"] = sc.tx_bytes * 8 / up / 1e6
    sc["pkt"] = sc.rx_bytes / sc.rx_pkts.where(sc.rx_pkts > 0)
    sc = sc.sort_values("total", ascending=False)
    n_sub, n_vlan = (sc.kind == "sub-interface").sum(), (sc.kind == "VLAN interface").sum()
    out.append(ctx.p(
        f"{n_sub} sub-interface{'s' if n_sub != 1 else ''}"
        + (f" and {n_vlan} VLAN interface{'s' if n_vlan != 1 else ''}" if n_vlan else "")
        + " with their own counters since the last boot ('show counter interface all'), with zone, VLAN tag and "
        "router from 'show interface all'. A sub-interface counts what enters and leaves through its VLAN; the "
        "physical port or aggregate above it counts the sum of all its VLANs."))

    # --- addressing -----------------------------------------------------------------------
    adr = sc[["interface", "kind", "zone", "tag", "router", "address"]].rename(columns={"tag": "VLAN"})
    adr["VLAN"] = adr.VLAN.replace({"0": ""})
    out.append(ctx.small("Where each one sits:"))
    out.append(ctx.table(adr, [2.6, 2.2, 3.0, 1.2, 3.0, 5.6], max_rows=200))

    # --- traffic and drops -----------------------------------------------------------------
    cols = ["interface", "rx_bytes", "tx_bytes"] + (["rx_mbps", "tx_mbps"] if up else []) + \
           ["pkt", "drops", "drop_ppm", "arp_not_found", "flow_state_drops"]
    tab = sc[cols].rename(columns={"rx_bytes": "received", "tx_bytes": "sent", "rx_mbps": "avg in Mb/s",
                                   "tx_mbps": "avg out Mb/s",
                                   "pkt": "avg pkt in", "drops": "dropped", "drop_ppm": "dropped / M pkts",
                                   "arp_not_found": "ARP not found", "flow_state_drops": "flow state drops"})
    num = lambda v: f"{v:,.0f}"
    fmt = {"received": lambda v: C.human(v) + "B", "sent": lambda v: C.human(v) + "B",
           "avg in Mb/s": lambda v: f"{v:,.1f}", "avg out Mb/s": lambda v: f"{v:,.1f}",
           "avg pkt in": lambda v: "-" if pd.isna(v) else f"{v:,.0f} B", "dropped": num,
           "dropped / M pkts": lambda v: "-" if pd.isna(v) else f"{v:,.0f}", "ARP not found": num,
           "flow state drops": num}
    widths = [2.6, 1.6, 1.6] + ([1.7, 1.7] if up else []) + [1.5, 1.7, 1.8, 1.7, 1.7]
    out.append(ctx.small("Traffic and drops since boot (averages spread over the whole uptime):"))
    out.append(ctx.table(tab, widths, fmt=fmt, max_rows=200))
    out.append(ctx.p(
        "<b>dropped</b> counts every packet discarded after entering through this interface, for any reason - "
        "including policy denies, so internet-facing interfaces always show many. <b>ARP not found</b>: packets to "
        "addresses in this subnet that never answered ARP - scans of unused addresses or hosts that are down. "
        "<b>flow state drops</b>: TCP packets that don't fit the state of their session (e.g. after a timeout or with "
        "asymmetric routing)."))

    # --- charts ----------------------------------------------------------------------------
    label = lambda r: f"{r.interface} ({r.zone})" if r.zone else r.interface
    top = sc[sc.total > 0].head(12)
    if len(top) >= 2:
        f, ax = C.fig(C.W, 0.3 * len(top) + 0.8)
        C.hbar(ax, pd.Series(top.total.values, index=[label(r) for r in top.itertuples()]),
               labeler=lambda v: C.human(v) + "B")
        ax.set_title("Traffic per sub-interface since boot (received + sent)")
        out.append(ctx.figure(f, "subinterfaces_traffic"))
    dr = sc[sc.drops > 0].sort_values("drops", ascending=False).head(10)
    if len(dr) >= 2:
        f, ax = C.fig(C.W, 0.3 * len(dr) + 0.8)
        C.hbar(ax, pd.Series(dr.drops.values, index=[label(r) for r in dr.itertuples()]), color=C.CAT[1],
               labeler=C.human)
        ax.set_title("Dropped packets per sub-interface since boot")
        out.append(ctx.figure(f, "subinterfaces_drops"))

    # --- findings ------------------------------------------------------------------------
    t1 = sc.iloc[0]
    ctx.find("info", "Interfaces", f"Busiest sub-interface since boot: {label(t1)} with {C.human(t1.total)}B "
                                   f"({t1.total / sc.total.sum() * 100:.0f}% of all sub-interface traffic).")
    arp = sc[sc.arp_not_found >= 1e6].sort_values("arp_not_found", ascending=False).head(3)
    if not arp.empty:
        ctx.find("notice", "Interfaces", "Many packets to addresses that never answered ARP: " + ", ".join(
            f"{label(r)} {C.human(r.arp_not_found)}" for r in arp.itertuples())
            + " - scans of unused addresses or hosts that are down; each one still costs dataplane work.")
    return out
