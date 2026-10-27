"""Cluster report (TSFs of both nodes of an NGFW cluster): how the work is shared between the nodes."""

import numpy as np
import pandas as pd

from .. import charts as C

TITLE = "Cluster nodes compared"

UNEVEN_SHARE = 65  # % of a measure on one node of two
UNEVEN_RATIO, UNEVEN_POINTS = 1.5, 10  # DP load: busier node vs. the other one

PORT_RE = r"^node\d+:ethernet\d+/\d+$"  # physical ports (no sub-interfaces, no aggregates - those repeat the traffic)


def _node_rows(ds) -> pd.DataFrame:
    lead = ds.meta.get("cluster_leader")
    rows = []
    for n, d in ds.nodes.items():
        si = d.meta.get("session_info") or {}
        cmp = d["dp_compare"] if d.has("dp_compare") else pd.DataFrame(columns=["dp", "mean", "p95"])
        top = cmp.dropna(subset=["mean"]).sort_values("mean", ascending=False).head(1)
        ports = d["if_counters"][d["if_counters"].interface.str.match(PORT_RE)] if d.has("if_counters") else pd.DataFrame()
        apps = d["apps"] if d.has("apps") else pd.DataFrame()
        rows.append(dict(
            node=n, role="leader" if n == lead else "member", host=d.meta.get("hostname", "?"),
            taken=d.meta.get("tsf_time"), uptime=d.meta.get("uptime", "?"), dps=len(cmp),
            dp_mean=cmp["mean"].mean() if len(cmp) else np.nan,
            busiest=f"{top.dp.iloc[0]} ({top['mean'].iloc[0]:.0f}%)" if len(top) else "-",
            sessions=si.get("sessions_allocated", np.nan), pps=si.get("pps", np.nan), kbps=si.get("kbps", np.nan),
            created=si.get("sessions_created_total", np.nan),
            port_rx=ports.rx_bytes.sum() if len(ports) else np.nan, port_tx=ports.tx_bytes.sum() if len(ports) else np.nan,
            app_bytes=apps.bytes.sum() if "bytes" in apps else np.nan))
    return pd.DataFrame(rows)


def build(ctx):
    ds = ctx.ds
    if not ds.nodes:
        return []
    nd = _node_rows(ds)
    lead = ds.meta.get("cluster_leader")
    out = [ctx.h1(TITLE), ctx.p(
        f"This report combines the tech support files of all {len(nd)} nodes of the NGFW cluster. Each node counts "
        "only the traffic <i>its own</i> dataplanes processed - also for ports of the other chassis, whose packets "
        "can be processed across the HSCI links. So counters, sessions, applications and interface traffic are "
        "<b>added up over the nodes</b>, and this section shows each node's share. That the shares add up is "
        "inferred from the counters (received and sent bytes balance only over all nodes together), not taken from "
        "vendor documentation. Management, configuration, routing and logs run on the leader (node "
        f"{lead}): the management plane, configuration and limits come from its TSF. Each node then gets a part of "
        "its own with the DP sections for its busiest DP and the health of its chassis.")]

    tab = nd.assign(node=nd.node.astype(str) + " (" + nd.role + ")")[
        ["node", "host", "taken", "uptime", "dps", "dp_mean", "busiest", "sessions", "pps", "kbps"]]
    num = lambda v: "-" if pd.isna(v) else f"{v:,.0f}"
    out.append(ctx.table(tab.rename(columns={"host": "hostname", "taken": "TSF taken", "dps": "DPs",
                                             "dp_mean": "DP load (mean)", "busiest": "busiest DP",
                                             "sessions": "sessions now", "pps": "packets/s now", "kbps": "kbit/s now"}),
                         [2.4, 3.2, 2.3, 2.0, 1.0, 1.6, 2.4, 1.8, 1.8, 1.8],
                         fmt={"DPs": num, "DP load (mean)": lambda v: "-" if pd.isna(v) else f"{v:.1f}%",
                              "sessions now": num, "packets/s now": num, "kbit/s now": num}))

    measures = [("bytes received on the ports", "port_rx"), ("bytes sent on the ports", "port_tx"),
                ("application bytes", "app_bytes"), ("sessions since boot", "created"), ("sessions now", "sessions"),
                ("packets/s now", "pps")]
    share = pd.DataFrame({lab: nd.set_index("node")[col] for lab, col in measures}).T.dropna(how="all")
    share = share.div(share.sum(axis=1), axis=0) * 100
    if not share.empty:
        f, ax = C.fig(C.W, 0.32 * len(share) + 0.9)
        cmap = C.colors_for([f"node {n}" for n in share.columns])
        left = np.zeros(len(share))
        for n in share.columns:
            v = share[n].fillna(0).values
            ax.barh(range(len(share)), v, left=left, color=cmap[f"node {n}"], height=0.55,
                    label=f"node {n}" + (" (leader)" if n == lead else ""), edgecolor=C.SURFACE, linewidth=0.8)
            for i, (x, w) in enumerate(zip(left, v)):
                if w >= 6:
                    ax.text(x + w / 2, i, f"{w:.0f}%", ha="center", va="center", fontsize=C.VALUE_FS, color="white")
            left += v
        ax.set_yticks(range(len(share)), share.index)
        ax.invert_yaxis()
        ax.set_xlim(0, 100)
        ax.set_xticks([0, 25, 50, 75, 100], ["0", "25", "50", "75", "100%"])
        ax.grid(axis="y", visible=False)
        ax.set_title("Share of the work per node")
        C.legend_below(ax, len(share.columns), y=-0.5 if len(share) < 5 else -0.3)
        out.append(ctx.figure(f, "cluster_share", "Ports: physical ports of both chassis, as each node counted them. "
                                                  "'now' values are from the moment each TSF was taken."))

    totals = pd.DataFrame([("bytes received on the ports", C.human_bytes(nd.port_rx.sum())),
                           ("bytes sent on the ports", C.human_bytes(nd.port_tx.sum())),
                           ("sessions since boot", num(nd.created.sum())), ("sessions now", num(nd.sessions.sum()))],
                          columns=["cluster total (all nodes)", "value"])
    out.append(ctx.table(totals, [7.0, 4.0]))

    # findings
    for lab, row in share.iterrows():
        if row.max() >= UNEVEN_SHARE and lab in ("bytes received on the ports", "sessions since boot"):
            ctx.find("notice", "Cluster", f"Uneven work: node {row.idxmax()} has {row.max():.0f}% of the {lab}.")
    dm = nd.set_index("node").dp_mean.dropna()
    if len(dm) == 2 and dm.max() >= dm.min() * UNEVEN_RATIO and dm.max() - dm.min() >= UNEVEN_POINTS:
        ctx.find("notice", "Cluster", f"Node {dm.idxmax()} runs its DPs at {dm.max():.0f}% on average, node "
                                      f"{dm.idxmin()} at {dm.min():.0f}%.")
    rx = share.loc["bytes received on the ports"] if "bytes received on the ports" in share.index else None
    ctx.find("info", "Cluster", f"{len(nd)} nodes, leader node {lead}; mean DP load "
             + ", ".join(f"node {n} {v:.1f}%" for n, v in dm.items())
             + ("; share of the received port traffic " + ", ".join(f"node {n} {v:.0f}%" for n, v in rx.items())
                if rx is not None else "") + ".")
    return out
