"""Chassis models (PA-7000/7500): the load of every dataplane side by side, and which DP the detail sections show."""

import numpy as np
import pandas as pd

from .. import charts as C

TITLE = "Dataplanes compared"

NOTICE, WARN = 60, 85  # % p95 of a DP's average core load
IMBALANCE_RATIO, IMBALANCE_POINTS = 1.5, 10  # busiest vs. median DP of the same card type


def build(ctx):
    ds = ctx.ds
    if not ds.has("dp_compare"):
        return []
    cmp = ds["dp_compare"]
    sel = ds.meta.get("dp")
    shown = ds.meta.get("dp_shown") or ([sel] if sel else [])  # cluster report: the busiest DP of each node
    n_cards = len(cmp.dp.str.extract(r"^(?:(n\d+):)?s(\d+)dp").drop_duplicates())  # (node,) slot
    one_doc = ctx.settings.get("all_dps_doc")  # this is the separate document with every DP
    what = (f"This cluster of {len(ds.nodes)} {ds.meta.get('model', '?')}" if ds.nodes else
            f"This {ds.meta.get('model', '?')}")
    intro = (f"{what} has <b>{len(cmp)} dataplanes</b> (DPs) on {n_cards} cards. "
             "Each DP has its own cores, session table and buffers, and the firewall spreads sessions across "
             "them. Load is the mean over a DP's worker cores, in % - <b>mean</b> and <b>p95</b> over the whole "
             "history of the DP (dp-monitor, per minute), <b>max</b> is the highest one-minute value. "
             "<b>core peak</b> is the highest load a single core reached.")
    if ds.nodes:
        intro += (f" The DPs of all {len(ds.nodes)} cluster nodes are compared here, named <i>n1:</i>, <i>n2:</i> "
                  "after their node. Each node's part shows the DP sections for its busiest DP: "
                  f"<b>{', '.join(shown)}</b>.")
    elif ds.has("cluster"):
        me = ds["cluster"][ds["cluster"].this]
        role = "" if me.empty else " (the leader)" if me.leader.iloc[0] == "yes" else " (not the leader)"
        intro += (f" This chassis is {'node ' + str(me.node.iloc[0]) if not me.empty else 'a node'}{role} of an "
                  "NGFW cluster: the DPs here are those of this chassis only - the other node's DPs are in its own "
                  "TSF (see Health and stability).")
    if ds.nodes:
        pass
    elif one_doc:
        intro += " The following parts show the DP sections for every DP, one part per DP."
    else:
        intro += (f" The DP sections of this report (CPU load, core spikes, resources, breakdown) cover "
                  f"<b>{sel}</b>" + (" - the DP with the highest mean load" if not ctx.settings.get("dp") else "")
                  + ". <b>Tip:</b> pick another DP with <b>--dp NAME</b>, or build a separate document with those "
                  "sections for every DP with <b>--all-dps</b> (large).")
    out = [ctx.h1(TITLE), ctx.p(intro)]

    ok = cmp.dropna(subset=["mean"])
    if not ok.empty:
        f, ax = C.fig(C.W, 2.6)
        x = np.arange(len(ok))
        ax.bar(x, ok.p95, width=0.7, color=C.SEQ[1], label="p95")
        ax.bar(x, ok["mean"], width=0.42, color=C.CAT[0], label="mean")
        ax.scatter(x, ok["max"], marker="_", s=60, color=C.INK2, linewidths=1.2, label="max (1 min)", zorder=3)
        ax.set_xticks(x, [f"{d}*" if d in shown else d for d in ok.dp], rotation=90, fontsize=6)
        ax.set_xlim(-0.6, len(ok) - 0.4)
        ax.set_ylabel("% (mean of the DP's cores)")
        ax.set_ylim(0, max(10, ok["max"].max() * 1.15))
        ax.set_title("Load per DP over its history" + ("" if one_doc else f" (* = {', '.join(shown)}, shown in detail)"))
        C.legend_below(ax, 3, y=-0.42)
        out.append(ctx.figure(f, "dp_compare"))

    m = ds["dp_compare_5min"]
    # over time: the DPs of the most common card type (other cards, e.g. network cards with a DP of their own,
    # do different work), from the time all of them have data
    cards = cmp.card.replace("", "?")
    main = cards.value_counts().index[0] if not cards.empty else "?"
    group = set(cmp[cards == main].dp)
    others = [d for d in cmp.dp if d not in group]
    m = m[m.dp.isin(group)]
    if not m.empty:
        start, end = m.groupby("dp").ts.min().max(), m.groupby("dp").ts.max().min()
        wide = m.pivot_table(index="ts", columns="dp", values="avg").sort_index()
        wide = wide[(wide.index >= start) & (wide.index <= end)] if start < end else wide
    if not m.empty and len(wide) > 1:
        hl = C.notable(wide)
        for d in shown if not one_doc else []:
            if d in wide.columns and d not in hl:
                hl = [d] + hl[:C.FIELD_MAX_HIGHLIGHT - 1]
        cmap = C.colors_for(hl)
        f, ax = C.fig(C.W, 2.6)
        C.field_plot(ax, wide, hl, cmap, what="DP")
        C.time_axis(ax, (wide.index.max() - wide.index.min()).total_seconds() / 86400)
        ax.set_ylabel("% (mean of the DP's cores)")
        ax.set_ylim(bottom=0)
        what = f"the {wide.shape[1]} DPs on {main.replace('PA-', '')} cards" if others else f"all {wide.shape[1]} DPs"
        ax.set_title(f"{what[0].upper() + what[1:]} over time (5-minute means) - median, range and notable DPs")
        C.legend_below(ax, 3)
        out.append(ctx.figure(f, "dp_compare_time",
                              "Coloured: the DPs that differ most from the others"
                              + ("" if one_doc or not set(shown) & group else
                                 f", and {', '.join(d for d in shown if d in group)} (shown in detail)") + "."
                              + (f" Not in this chart: {', '.join(others)} (other card type, see the table)."
                                 if others else "")
                              + (" The chart starts when all of these DPs have data." if start < end else "")))

    tab = cmp.assign(card=cmp.card.str.replace("PA-", "", regex=False))[
        ["dp", "card", "cores", "mean", "p95", "max", "core_peak", "busiest_core", "hours"]]
    pct = lambda v: "-" if pd.isna(v) else f"{v:.1f}%"
    out.append(ctx.table(tab.rename(columns={"core_peak": "core peak", "busiest_core": "busiest core (mean)",
                                             "hours": "history"}),
                         [1.6, 2.4, 1.2, 1.4, 1.4, 1.4, 1.5, 2.6, 1.5],
                         fmt={"cores": lambda v: "-" if pd.isna(v) else f"{v:.0f}", "mean": pct, "p95": pct,
                              "max": pct, "core peak": lambda v: "-" if pd.isna(v) else f"{v:.0f}%",
                              "history": lambda v: "-" if pd.isna(v) else f"{v:.0f} h"},
                         max_rows=80))
    if (cmp.source != "dp-monitor (per minute)").any():
        out.append(ctx.small("DPs without a dp-monitor history are rated from the hourly resource-monitor window "
                             "(last 24 hours) instead."))

    if ok.empty:
        return out
    for r in ok.itertuples():
        if r.p95 >= NOTICE:
            ctx.find("warning" if r.p95 >= WARN else "notice", TITLE,
                     f"{r.dp}: mean of its cores {r.mean:.0f}%, p95 {r.p95:.0f}% over {r.hours:.0f} h.")
    for card, grp in ok.groupby(ok.card.replace("", "?")):
        if len(grp) < 3:
            continue
        top, med = grp.loc[grp["mean"].idxmax()], grp["mean"].median()
        if top["mean"] >= med * IMBALANCE_RATIO and top["mean"] - med >= IMBALANCE_POINTS:
            ctx.find("notice", TITLE, f"Uneven DPs on the {card} cards: {top.dp} averages {top['mean']:.0f}%, "
                                      f"the median DP {med:.0f}% - sessions are not spread evenly.")
    top = ok.loc[ok["mean"].idxmax()]
    ctx.find("info", TITLE, f"{len(cmp)} dataplanes; highest mean load {top.dp} ({top['mean']:.0f}%, p95 "
                            f"{top.p95:.0f}%), lowest {ok.loc[ok['mean'].idxmin()].dp} ({ok['mean'].min():.0f}%)."
             + ("" if one_doc else f" DP sections show {', '.join(shown)}."))
    return out
