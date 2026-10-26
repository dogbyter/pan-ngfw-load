"""Management plane load: 30 days of sar on the MP core(s), plus process view from mp-monitor."""

import pandas as pd

from .. import charts as C

TITLE = "Management plane CPU"

# Processes that are DP workers on platforms where DP and MP share one CPU (PA-400/PA-200 style).
DP_PROCESSES = {"pan_task"}


def build(ctx):
    ds = ctx.ds
    if not ds.has("sar_cpu") and not ds.has("mpm_summary"):
        return []
    out = [ctx.h1(TITLE)]
    dp = ds.meta.get("dp_cores") or []
    if dp:
        out.append(ctx.p(
            f"On this platform the DP workers run on the same CPU as the management plane (MP). Linux sees cores "
            f"{', '.join(map(str, dp))} as about 100% busy all the time because the DP workers busy-poll for packets. "
            "That figure says nothing about real DP load and is ignored here. Only the remaining core(s) show MP load."))

    if ds.has("sar_cpu"):
        s = ds["sar_cpu"]
        mp = s[s.role == "MP"]
        span = (mp.ts.max() - mp.ts.min()).total_seconds() / 86400
        f, ax = C.fig(C.W, 2.8)
        cmap = C.colors_for([f"core {c}" for c in sorted(mp.core.unique())])
        for c in sorted(mp.core.unique()):
            x = mp[mp.core == c].set_index("ts").sort_index()
            ax.plot(x.index, x.busy, color=cmap[f"core {c}"], lw=0.6, alpha=0.55)
            ax.plot(x.index, x.busy.rolling(36, min_periods=1).mean(), color=cmap[f"core {c}"], lw=1.6,
                    label=f"core {c} (6 h mean)")
        ax.set_ylim(0, 100)
        ax.set_ylabel("busy %")
        ax.set_title(f"MP core utilisation, last {span:.0f} days (sar, 10-minute samples)")
        C.time_axis(ax, span)
        C.legend_below(ax, 3)
        out.append(ctx.figure(f, "mp_sar"))

        parts = mp.assign(day=mp.ts.dt.date).groupby("day")[["%usr", "%nice", "%sys", "%iowait", "%irq", "%soft"]].mean()
        f, ax = C.fig(C.W, 2.5)
        cols = list(parts.columns)
        cmap = C.colors_for(cols)
        bottom = pd.Series(0.0, index=parts.index)
        for c in cols:
            ax.bar(pd.to_datetime(parts.index), parts[c], bottom=bottom, color=cmap[c], width=0.8, edgecolor=C.SURFACE,
                   linewidth=0.6, label=c)
            bottom += parts[c]
        ax.set_ylabel("% (daily mean)")
        ax.set_title("MP CPU split per day")
        C.time_axis(ax, span)
        C.legend_below(ax, 6)
        out.append(ctx.figure(f, "mp_split"))
        pk = mp.sort_values("busy").iloc[-1]
        level = "notice" if mp.busy.quantile(0.95) > 70 else "info"
        ctx.find(level, "MP",
                 f"MP core busy over {span:.0f} days: mean {mp.busy.mean():.0f}%, p95 {mp.busy.quantile(0.95):.0f}%, "
                 f"max {pk.busy:.0f}% ({pk.ts:%d.%m. %H:%M}).")

    if ds.has("mpm_procs"):
        p = ds["mpm_procs"]
        p = p[~p.cmd.isin(DP_PROCESSES)]
        n = p.ts.nunique()
        agg = p.groupby("cmd").agg(avg_cpu=("cpu", lambda v: v.sum() / n), max_cpu=("cpu", "max"),
                                   res_mb=("res_kb", lambda v: v.max() / 1024)).sort_values("avg_cpu", ascending=False)
        agg = agg.head(15).reset_index()
        out.append(ctx.h2(f"Top MP processes (mp-monitor 'top', {n} snapshots)"))
        out.append(ctx.small(f"DP worker processes ({', '.join(sorted(DP_PROCESSES))}) are left out. "
                             "avg = mean %CPU over all snapshots (absent = 0)."))
        out.append(ctx.table(agg.rename(columns={"cmd": "process", "avg_cpu": "avg %CPU", "max_cpu": "max %CPU",
                                                 "res_mb": "max RES MB"}), [5.0, 2.5, 2.5, 2.5],
                             fmt={"avg %CPU": lambda v: f"{v:.2f}", "max %CPU": lambda v: f"{v:.1f}",
                                  "max RES MB": lambda v: f"{v:,.0f}"}))
    if ds.has("mpm_summary"):
        m = ds["mpm_summary"].dropna(subset=["load1"]).sort_values("ts")
        if not m.empty:
            span = (m.ts.max() - m.ts.min()).total_seconds() / 86400
            f, ax = C.fig(C.W, 2.2)
            ax.plot(m.ts, m.load1, color=C.CAT[0], lw=1)
            if dp:
                ax.axhline(len(dp), color=C.INK2, lw=0.8, ls="--")
                ax.text(m.ts.min(), len(dp) + 0.05, f"  {len(dp)} = DP busy-poll baseline", fontsize=C.VALUE_FS, color=C.INK2, va="bottom")
            ax.set_title("Load average (1 min), mp-monitor")
            C.time_axis(ax, span)
            out.append(ctx.figure(f, "mp_loadavg"))
    return out
