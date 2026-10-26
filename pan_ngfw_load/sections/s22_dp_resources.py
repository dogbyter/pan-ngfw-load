"""Dataplane resources besides CPU: packet buffers, packet descriptors, software tag descriptors and the
session table - what they are, how full they got, and whether anything ran out."""

import pandas as pd

from .. import charts as C
from .. import knowledge as K

TITLE = "Dataplane resources - buffers, descriptors, session table"

NOTICE_MAX, WARN_MAX = 70, 90   # % peak (max) within the last 7 days
NOTICE_AVG = 50                 # % weekly average

WINDOWS = [(60, "last 60 min"), (3600, "last 24 h"), (86400, "last 7 days"), (604800, "last 13 weeks")]


def _peak(u: pd.DataFrame, metric: str, step: int, kind: str = "maximum") -> float:
    x = u[(u.step_s == step) & (u.metric == f"{metric} ({kind})")].value.dropna()
    if x.empty:
        return float("nan")
    return float(x.max() if kind == "maximum" else x.mean())


def build(ctx):
    ds = ctx.ds
    if not ds.has("rm_util") and not ds.has("dpm_util"):
        return []
    u = ds["rm_util"] if ds.has("rm_util") else pd.DataFrame(columns=["step_s", "metric", "value"])
    metrics = [m for m in K.RESOURCES if (u.metric == f"{m} (maximum)").any()
               or (ds.has("dpm_util") and (ds["dpm_util"].metric == f"{m} (maximum)").any())]
    if not metrics:
        return []
    out = [ctx.h1(TITLE), ctx.p(
        "Besides CPU time the dataplane needs memory for the packets it is working on, bookkeeping entries for "
        "them, and room in the session table. These pools are fixed in size per model. CPU can be moderate while "
        "one of them runs full - and a full pool means drops. The resource monitor records how full each pool "
        "was, as an average and a peak (max) per minute, hour, day and week.")]

    # --- what the counters mean ---------------------------------------------------
    out.append(ctx.h2("What the values mean"))
    for m in metrics:
        name, what, high = K.RESOURCES[m]
        out.append(ctx.p(f"<b>{name}</b> - {what} <i>When high:</i> {high}"))

    # --- table: peaks per window ----------------------------------------------------
    rows = []
    for m in metrics:
        r = {"resource": K.RESOURCES[m][0]}
        for step, lab in WINDOWS:
            r[f"max {lab}"] = _peak(u, m, step)
        r["avg 13 weeks"] = _peak(u, m, 604800, "average")
        rows.append(r)
    tab = pd.DataFrame(rows)
    out.append(ctx.h2("How full the pools got"))
    out.append(ctx.small("Peak (max) per window and the average over the weekly samples, in % of the pool. "
                         "Nothing before the last reboot is included."))
    pct = lambda v: "-" if pd.isna(v) else f"{v:.0f}%"
    out.append(ctx.table(tab, [4.2, 2.4, 2.4, 2.4, 2.6, 2.4], fmt={c: pct for c in tab.columns if c != "resource"}))

    # findings
    for m, r in zip(metrics, rows):
        name = K.RESOURCES[m][0]
        pk7 = max(v for v in (r["max last 7 days"], r["max last 24 h"], r["max last 60 min"], 0) if not pd.isna(v))
        avg = r["avg 13 weeks"]
        if pk7 >= WARN_MAX:
            ctx.find("warning", "DP resources", f"{name} peaked at {pk7:.0f}% in the last 7 days - close to exhaustion "
                                                "(drops start at 100%).")
        elif pk7 >= NOTICE_MAX:
            ctx.find("notice", "DP resources", f"{name} peaked at {pk7:.0f}% in the last 7 days "
                                               f"(average {avg:.0f}% over the weekly samples).")
        elif not pd.isna(avg) and avg >= NOTICE_AVG:
            ctx.find("notice", "DP resources", f"{name} averaged {avg:.0f}% over the weekly samples.")
    if all(not pd.isna(r["max last 7 days"]) and r["max last 7 days"] < NOTICE_MAX for r in rows):
        ctx.find("info", "DP resources", "Buffers, descriptors and session table stayed below "
                                         f"{NOTICE_MAX}% in the last 7 days.")

    # --- chart: per minute (dp-monitor) ---------------------------------------------
    if ds.has("dpm_util"):
        du = ds["dpm_util"]
        du = du[du.metric.str.endswith("(maximum)")].copy()
        du["res"] = du.metric.str.replace(" (maximum)", "", regex=False)
        du = du[du.res.isin(metrics)]
        if not du.empty:
            w = du.pivot_table(index="ts", columns="res", values="value").sort_index()
            span = (w.index.max() - w.index.min()).total_seconds() / 86400
            names = [K.RESOURCES[m][0] for m in metrics if m in w.columns]
            cmap = C.colors_for(names)
            f, ax = C.fig(C.W, 2.6)
            for m in metrics:
                if m in w.columns:
                    ax.plot(w.index, w[m], color=cmap[K.RESOURCES[m][0]], lw=0.9, label=K.RESOURCES[m][0])
            ax.set_ylim(0, max(10, float(w.max().max()) * 1.15))
            ax.set_ylabel("% of pool (max per minute)")
            ax.set_title(f"Per minute, last {span:.1f} days: peak use of each pool")
            C.time_axis(ax, span)
            C.legend_below(ax, len(names))
            out.append(ctx.figure(f, "resources_minute"))

    # --- chart: weekly peaks --------------------------------------------------------
    wk = u[(u.step_s == 604800) & u.metric.str.endswith("(maximum)")].dropna(subset=["value"]).copy()
    if not wk.empty and wk["end"].nunique() >= 2:
        wk["res"] = wk.metric.str.replace(" (maximum)", "", regex=False)
        wk = wk[wk.res.isin(metrics)]
        w = wk.pivot_table(index="end", columns="res", values="value").sort_index()
        w = w[(w.fillna(0) > 0).any(axis=1)]  # the week of the reboot reports 0 for everything
        names = [K.RESOURCES[m][0] for m in metrics if m in w.columns]
        cmap = C.colors_for(names)
        f, ax = C.fig(C.W, 2.3)
        for m in metrics:
            if m in w.columns:
                ax.plot(w.index, w[m], color=cmap[K.RESOURCES[m][0]], marker="o", markersize=3, lw=1.2,
                        label=K.RESOURCES[m][0])
        ax.set_ylim(0, 105)
        ax.set_ylabel("% of pool (weekly max)")
        ax.set_title("Per week: peak use of each pool")
        C.time_axis(ax, (w.index.max() - w.index.min()).total_seconds() / 86400)
        C.legend_below(ax, len(names))
        out.append(ctx.figure(f, "resources_week"))

    # --- counters: did anything run out? ------------------------------------------
    if ds.has("counters_boot"):
        c = ds["counters_boot"]
        c = c[c.name.str.match(K.RESOURCE_COUNTERS) & (c.value > 0)]
        out.append(ctx.h2("Did a pool run out?"))
        if c.empty:
            out.append(ctx.p("No counter for failed buffer/descriptor allocations or packet-buffer-protection drops "
                             "is above zero since the last boot."))
        else:
            cols = ["name", "value", "severity", "description"] if "description" in c.columns else ["name", "value"]
            out.append(ctx.small("Global counters since the last boot that show a pool ran out or a protection "
                                 "kicked in:"))
            out.append(ctx.table(c[cols], [5.2, 2.4, 1.6, 8.0][:len(cols)], fmt={"value": lambda v: f"{v:,.0f}"}))
            pbp = c[c.name == "flow_dos_pbp_drop"]
            if not pbp.empty:
                out.append(ctx.p(
                    f"<b>Packet buffer protection</b> dropped {pbp.value.iloc[0]:,.0f} packets since boot. It protects "
                    "the buffer pool by dropping packets of sessions that use a large share of it when the pool fills "
                    "up. Some drops during bursts are by design; a steadily growing number points to sessions or "
                    "sources that flood the firewall (check the zone protection logs)."))
                ctx.find("notice", "DP resources", f"Packet buffer protection dropped {pbp.value.iloc[0]:,.0f} packets "
                                                   "since boot.")
            fail = c[c.name.str.contains("alloc_failure|alloc_fail")]
            if not fail.empty and fail.value.sum() >= 100:
                ctx.find("notice", "DP resources", "Allocation failures since boot: " + ", ".join(
                    f"{n} {v:,.0f}" for n, v in zip(fail.name, fail.value)) + ".")
    return out
