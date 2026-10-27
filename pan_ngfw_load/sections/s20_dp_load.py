"""DP core load across all resource-monitor windows plus the per-minute series from dp-monitor."""

import numpy as np
import pandas as pd

from .. import charts as C

TITLE = "Dataplane CPU load"
DP_SCOPED = True  # chassis models: covers one DP (see dataset.select_dp)

THRESH_NOTICE, THRESH_WARN = 60, 85  # % per-core max


def build(ctx):
    ds = ctx.ds
    if not ds.has("rm_cpu"):
        return []
    cores = ds.meta.get("dp_cores") or []
    rc = ds["rm_cpu"][ds["rm_cpu"].core.isin(cores)]
    many = len(cores) > len(C.CAT)
    field = many and ctx.settings.get("report_kind") == "extended"  # extended report: field + highlighted cores
    sty = C.series_styles([f"core {c}" for c in cores])
    hl = 2.4 if many else 1.2  # legend handles long enough to show dashes
    intro = (f"DP worker cores: {', '.join(map(str, cores))}. Each value is a core's utilisation in %. "
             "<b>avg</b> is the mean over the period, <b>max</b> is the highest load sampled within it. "
             "Short bursts show up only in <b>max</b>; the averages stay low.")
    if field:
        intro += (f" With {len(cores)} cores the charts show the field of all cores instead of each one: the "
                  "<b>median</b> (dark line or bar), the <b>range from the lowest to the highest core</b> (grey band or "
                  f"thin line), and in colour only the cores that differ most from the others (at most "
                  f"{C.FIELD_MAX_HIGHLIGHT}, and only if they differ by {C.FIELD_MIN_DEV:g} points or more on average).")
    elif many:
        rounds = (len(cores) - 1) // len(C.CAT) + 1
        intro += (f" This firewall has {len(cores)} DP cores - more than the {len(C.CAT)} colours that can be told "
                  "apart. The colours repeat: cores " + "; ".join(
                      f"{cores[i * len(C.CAT)]}-{cores[min(len(cores), (i + 1) * len(C.CAT)) - 1]} "
                      f"{C.ROUND_NAMES[i % len(C.ROUND_NAMES)]}" for i in range(rounds)) + ". "
                  "<b>Tip:</b> run the report with <b>-x / --extended</b> for charts that show the field of all "
                  "cores (median and range) and name only the cores that stand out - easier to read with many cores. The extended report also adds more analysis: drops and "
                  "errors, interfaces, IPsec VPN and capacity.")
    hl_cores, hl_cmap = [], {}
    if field:  # the notable cores are chosen once, from the averages, and shown the same way in every chart
        if ds.has("dpm_minute"):
            mm = ds["dpm_minute"][ds["dpm_minute"].core.isin(cores)]
            base = mm.pivot_table(index="ts", columns="core", values="avg").resample("10min").mean()
        else:
            base = rc[rc.step_s == 3600].pivot_table(index="end", columns="core", values="avg")
        hl_cores = C.notable(base.reindex(columns=cores))
        hl_cmap = dict(zip(hl_cores, C.colors_for([str(c) for c in hl_cores]).values()))
        intro += (" Highlighted here: " + (", ".join(f"core {c}" for c in hl_cores) if hl_cores else
                                           "none - all cores stay close to the median") + ".")
    out = [ctx.h1(TITLE), ctx.p(intro)]

    # --- weeks + days: grouped bars avg/max (field view for many cores in the extended report) ---------
    for step, label, unit in ((604800, "week", "Week"), (86400, "day", "Day")):
        sub = rc[rc.step_s == step].dropna(subset=["avg"])
        if sub.empty:
            continue
        idxs = sorted(sub.idx.unique(), reverse=True)
        ends = sub.drop_duplicates("idx").set_index("idx").end
        labels = [(pd.Timestamp(ends[i]) - pd.Timedelta(seconds=step)).strftime("%d.%m.") +
                  ("-" + pd.Timestamp(ends[i]).strftime("%d.%m.") if step > 86400 else "") for i in idxs]
        if field:
            avg = sub.pivot_table(index="idx", columns="core", values="avg").reindex(index=idxs, columns=cores)
            mx = sub.pivot_table(index="idx", columns="core", values="max").reindex(index=idxs, columns=cores)
            x = np.arange(len(idxs))
            f, ax = C.fig(C.W, 2.6)
            ax.bar(x, mx.median(axis=1), width=0.6, color=C.SEQ[1], edgecolor=C.SURFACE, label="max (median of cores)")
            ax.bar(x, avg.median(axis=1), width=0.6, color=C.SEQ[4], edgecolor=C.SURFACE, label="average (median of cores)")
            ax.vlines(x, avg.min(axis=1), avg.max(axis=1), color=C.INK, lw=1.2, label="average: lowest-highest core")
            for k, c in enumerate(hl_cores):
                off = (k - (len(hl_cores) - 1) / 2) * 0.09
                ax.scatter(x + off, avg[c], s=16, color=hl_cmap[c], zorder=5, edgecolors=C.SURFACE, linewidths=0.5,
                           label=f"core {c} (average)")
            ax.set_xticks(x)
            ax.set_xticklabels(labels)
            ax.set_ylim(0, 105)
            ax.set_ylabel("load %")
            ax.set_title(f"Per {label}: all {len(cores)} DP cores - median, range and notable cores")
            C.legend_below(ax, 3)
            out.append(ctx.figure(f, f"dp_load_{label}"))
            continue
        f, ax = C.fig(C.W, 2.6)
        w = 0.8 / len(cores)
        for j, c in enumerate(cores):
            st = sty[f"core {c}"]
            s = sub[sub.core == c].set_index("idx").reindex(idxs)
            x = np.arange(len(idxs)) + (j - (len(cores) - 1) / 2) * w
            ax.bar(x, s["max"], width=w * 0.92, color=st["color"], alpha=0.35, edgecolor=C.SURFACE, hatch=st["hatch"],
                   linewidth=0.3, label=None)
            ax.bar(x, s["avg"], width=w * 0.92, color=st["color"], edgecolor=C.SURFACE, hatch=st["hatch"],
                   linewidth=0.3, label=f"core {c}")
        ax.set_xticks(range(len(idxs)))
        ax.set_xticklabels(labels)
        ax.set_ylim(0, 105)
        ax.set_ylabel("load %")
        ax.set_title(f"Per {label}: average (solid) and max (light) per DP core")
        C.legend_below(ax, len(cores), handlelength=1.6 if many else 1.2)
        cap = (f"Averages are {sub['avg'].min():.0f}-{sub['avg'].max():.0f}% in every {label}, so the solid bars "
               "may be too small to see.") if sub["avg"].max() < 3 else None
        out.append(ctx.figure(f, f"dp_load_{label}", cap))

    # --- last 24 h hourly max ------------------------------------------------
    sub = rc[rc.step_s == 3600].dropna(subset=["max"])
    if not sub.empty:
        if field:
            wide = sub.pivot_table(index="end", columns="core", values="max").sort_index().reindex(columns=cores)
            f, ax = C.fig(C.W, 2.4)
            C.field_plot(ax, wide, hl_cores, hl_cmap, marker="o")
            C.time_axis(ax, 1)
            ax.set_ylabel("max load %")
            ax.set_title(f"Last 24 hours: hourly max of all {len(cores)} DP cores")
            C.legend_below(ax, 3)
        else:
            f, ax = C.fig(C.W, 2.4)
            for c in cores:
                st = sty[f"core {c}"]
                s = sub[sub.core == c].sort_values("end")
                ax.plot(s.end, s["max"], color=st["color"], ls=st["ls"], label=f"core {c}", marker="o", markersize=2.5)
            C.time_axis(ax, 1)
            ax.set_ylabel("max load %")
            ax.set_title("Last 24 hours: hourly max per DP core")
            C.legend_below(ax, len(cores), handlelength=hl)
        out.append(ctx.figure(f, "dp_load_24h"))

    # --- per-minute series from dp-monitor ----------------------------------
    if ds.has("dpm_minute"):
        m = ds["dpm_minute"][ds["dpm_minute"].core.isin(cores)]
        span = (m.ts.max() - m.ts.min()).total_seconds() / 86400
        if field:
            f, (a1, a2) = C.plt.subplots(2, 1, figsize=(C.W, 4.4), dpi=150, sharex=True)
            for ax, col, how, title, ylab in (
                    (a1, "max", "max", f"Per minute, last {span:.1f} days: max of all {len(cores)} cores "
                                       "(highest minute of each 10 minutes)", "max load %"),
                    (a2, "avg", "mean", "Per minute: average of all cores (10-minute mean)", "avg load %")):
                wide = (m.pivot_table(index="ts", columns="core", values=col).sort_index()
                        .resample("10min").agg(how).reindex(columns=cores))
                C.field_plot(ax, wide, hl_cores, hl_cmap)
                ax.set_ylabel(ylab)
                ax.set_title(title)
            C.time_axis(a2, span)
            C.legend_below(a2, 3)
        else:
            f, (a1, a2) = C.plt.subplots(2, 1, figsize=(C.W, 4.4), dpi=150, sharex=True)
            for c in cores:
                st = sty[f"core {c}"]
                s = m[m.core == c].set_index("ts").sort_index()
                a1.plot(s.index, s["max"], color=st["color"], ls=st["ls"], lw=0.8, label=f"core {c}")
                a2.plot(s.index, s["avg"].rolling(10, min_periods=1).mean(), color=st["color"], ls=st["ls"], lw=1.2,
                        label=f"core {c}")
            a1.set_title(f"Per minute, last {span:.1f} days: max per core")
            a1.set_ylabel("max load %")
            a2.set_title("Per minute: average per core (10-minute rolling mean)")
            a2.set_ylabel("avg load %")
            C.time_axis(a2, span)
            C.legend_below(a2, len(cores), handlelength=hl)
        out.append(ctx.figure(f, "dp_load_minute"))

        # hour-of-day profile of the per-minute max
        prof = m.assign(h=m.ts.dt.hour).groupby(["h", "core"])["max"].quantile(0.95).unstack()
        if field:
            f, ax = C.fig(C.W, 2.3)
            C.field_plot(ax, prof.reindex(columns=cores), hl_cores, hl_cmap, marker="o")
            ax.set_xticks(range(0, 24, 2))
            ax.set_xlabel("hour of day")
            ax.set_ylabel("p95 of minute max %")
            C.legend_below(ax, 3, y=-0.3)
        else:
            f, ax = C.fig(C.W, 2.3)
            for c in cores:
                st = sty[f"core {c}"]
                ax.plot(prof.index, prof[c], color=st["color"], ls=st["ls"], marker="o", markersize=2.5, label=f"core {c}")
            ax.set_xticks(range(0, 24, 2))
            ax.set_xlabel("hour of day")
            ax.set_ylabel("p95 of minute max %")
            C.legend_below(ax, len(cores), y=-0.3, handlelength=hl)
        ax.set_title("Daily profile: 95th percentile of the per-minute max, by hour")
        out.append(ctx.figure(f, "dp_load_hour_profile"))

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
