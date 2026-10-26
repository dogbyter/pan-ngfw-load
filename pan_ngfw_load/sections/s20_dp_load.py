"""DP core load across all resource-monitor windows plus the per-minute series from dp-monitor."""

import numpy as np
import pandas as pd

from .. import charts as C

TITLE = "Dataplane CPU load"

THRESH_NOTICE, THRESH_WARN = 60, 85  # % per-core max


def build(ctx):
    ds = ctx.ds
    if not ds.has("rm_cpu"):
        return []
    cores = ds.meta.get("dp_cores") or []
    cmap = C.colors_for([f"core {c}" for c in cores])
    rc = ds["rm_cpu"][ds["rm_cpu"].core.isin(cores)]
    out = [ctx.h1(TITLE), ctx.p(
        f"DP worker cores: {', '.join(map(str, cores))}. Each value is a core's utilisation in %. "
        "<b>avg</b> is the mean over the period, <b>max</b> is the highest load sampled within it. "
        "Short bursts show up only in <b>max</b>; the averages stay low.")]

    # --- weeks + days: grouped bars avg/max --------------------------------
    for step, label, unit in ((604800, "week", "Week"), (86400, "day", "Day")):
        sub = rc[rc.step_s == step].dropna(subset=["avg"])
        if sub.empty:
            continue
        idxs = sorted(sub.idx.unique(), reverse=True)
        f, ax = C.fig(C.W, 2.6)
        w = 0.8 / len(cores)
        for j, c in enumerate(cores):
            s = sub[sub.core == c].set_index("idx").reindex(idxs)
            x = np.arange(len(idxs)) + (j - (len(cores) - 1) / 2) * w
            ax.bar(x, s["max"], width=w * 0.92, color=cmap[f"core {c}"], alpha=0.35, edgecolor=C.SURFACE, label=None)
            ax.bar(x, s["avg"], width=w * 0.92, color=cmap[f"core {c}"], edgecolor=C.SURFACE, label=f"core {c}")
            for xi, v in zip(x, s["max"]):
                if v >= 20:
                    ax.text(xi, v + 1, f"{v:.0f}", ha="center", fontsize=C.VALUE_FS, color=C.INK2)
        ends = sub.drop_duplicates("idx").set_index("idx").end
        ax.set_xticks(range(len(idxs)))
        ax.set_xticklabels([(pd.Timestamp(ends[i]) - pd.Timedelta(seconds=step)).strftime("%d.%m.") +
                            ("-" + pd.Timestamp(ends[i]).strftime("%d.%m.") if step > 86400 else "") for i in idxs])
        ax.set_ylim(0, 105)
        ax.set_ylabel("load %")
        ax.set_title(f"Per {label}: average (solid) and max (light) per DP core")
        C.legend_below(ax, len(cores))
        cap = (f"Averages are {sub['avg'].min():.0f}-{sub['avg'].max():.0f}% in every {label}, so the solid bars "
               "may be too small to see.") if sub["avg"].max() < 3 else None
        out.append(ctx.figure(f, f"dp_load_{label}", cap))

    # --- last 24 h hourly max ------------------------------------------------
    sub = rc[rc.step_s == 3600].dropna(subset=["max"])
    if not sub.empty:
        f, ax = C.fig(C.W, 2.4)
        for c in cores:
            s = sub[sub.core == c].sort_values("end")
            ax.plot(s.end, s["max"], color=cmap[f"core {c}"], label=f"core {c}", marker="o", markersize=2.5)
        C.time_axis(ax, 1)
        ax.set_ylabel("max load %")
        ax.set_title("Last 24 hours: hourly max per DP core")
        C.legend_below(ax, len(cores))
        out.append(ctx.figure(f, "dp_load_24h"))

    # --- per-minute series from dp-monitor ----------------------------------
    if ds.has("dpm_minute"):
        m = ds["dpm_minute"][ds["dpm_minute"].core.isin(cores)]
        span = (m.ts.max() - m.ts.min()).total_seconds() / 86400
        f, (a1, a2) = C.plt.subplots(2, 1, figsize=(C.W, 4.4), dpi=150, sharex=True)
        for c in cores:
            s = m[m.core == c].set_index("ts").sort_index()
            a1.plot(s.index, s["max"], color=cmap[f"core {c}"], lw=0.8, label=f"core {c}")
            a2.plot(s.index, s["avg"].rolling(10, min_periods=1).mean(), color=cmap[f"core {c}"], lw=1.2, label=f"core {c}")
        a1.set_title(f"Per minute, last {span:.1f} days: max per core")
        a1.set_ylabel("max load %")
        a2.set_title("Per minute: average per core (10-minute rolling mean)")
        a2.set_ylabel("avg load %")
        C.time_axis(a2, span)
        C.legend_below(a2, len(cores))
        out.append(ctx.figure(f, "dp_load_minute"))

        # hour-of-day profile of the per-minute max
        prof = m.assign(h=m.ts.dt.hour).groupby(["h", "core"])["max"].quantile(0.95).unstack()
        f, ax = C.fig(C.W, 2.3)
        for c in cores:
            ax.plot(prof.index, prof[c], color=cmap[f"core {c}"], marker="o", markersize=2.5, label=f"core {c}")
        ax.set_xticks(range(0, 24, 2))
        ax.set_xlabel("hour of day")
        ax.set_ylabel("p95 of minute max %")
        ax.set_title("Daily profile: 95th percentile of the per-minute max, by hour")
        C.legend_below(ax, len(cores))
        out.append(ctx.figure(f, "dp_load_hour_profile"))

    # --- resource utilisation (buffers, sessions) ---------------------------
    ru = ds["rm_util"]
    if not ru.empty:
        rows = []
        for metric in sorted(ru.metric.unique()):
            if "average" in metric or metric in ("session", "packet buffer", "packet descriptor", "sw tags descriptor"):
                continue
            s = ru[(ru.metric == metric)]
            for wname in ("hour", "day", "week"):
                v = s[s.window == wname].value
                if not v.empty:
                    rows.append((metric.replace(" (maximum)", ""), wname, np.nanmax(v.values)))
        if rows:
            t = pd.DataFrame(rows, columns=["resource", "window", "max"]).pivot(index="resource", columns="window", values="max")
            t = t.reindex(columns=[c for c in ("hour", "day", "week") if c in t.columns]).reset_index()
            t.columns = ["resource"] + [f"max % ({c}ly samples)" for c in t.columns[1:]]
            out += [ctx.h2("Other DP resources (max utilisation %)"),
                    ctx.table(t, [4.5] + [3.5] * (len(t.columns) - 1), fmt={c: lambda v: f"{v:.0f}" for c in t.columns[1:]})]

    # --- findings ------------------------------------------------------------
    wk = rc[rc.step_s == 604800].dropna(subset=["max"])
    if not wk.empty:
        top = wk.sort_values("max").iloc[-1]
        level = "warning" if top["max"] >= THRESH_WARN else "notice" if top["max"] >= THRESH_NOTICE else "info"
        week_start = pd.Timestamp(top.end) - pd.Timedelta(days=7)
        ctx.find(level, "DP load",
                 f"Highest per-core peak since boot: {top['max']:.0f}% on core {top.core} in the week "
                 f"{week_start:%d.%m.}-{pd.Timestamp(top.end):%d.%m.} (weekly max). The highest weekly average is "
                 f"{wk['avg'].max():.0f}%.")
    if ds.has("dpm_minute"):
        m = ds["dpm_minute"][ds["dpm_minute"].core.isin(cores)]
        pk = m.sort_values("max").iloc[-1]
        ctx.find("info", "DP load",
                 f"Last {(m.ts.max() - m.ts.min()).total_seconds() / 86400:.1f} days: per-minute max peaked at "
                 f"{pk['max']:.0f}% (core {pk.core}, {pk.ts:%d.%m. %H:%M}); mean load {m['avg'].mean():.1f}%.")
    return out
