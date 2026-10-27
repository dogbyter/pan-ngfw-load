"""Management plane in depth: CPU over 30 days (sar), processes and their meaning (mp-monitor), memory and the
MP's network interfaces."""

import pandas as pd

from .. import charts as C
from .. import knowledge as K

TITLE = "Management plane - CPU, processes, memory"

# Processes that are DP workers on platforms where DP and MP share one CPU (PA-400/PA-200 style).
DP_PROCESSES = {"pan_task"}


def build(ctx):
    ds = ctx.ds
    if not ds.has("sar_cpu") and not ds.has("mpm_summary"):
        return []
    out = [ctx.h1(TITLE), ctx.p(
        "The management plane (MP) runs the web UI and API, commits, logging, reporting, User-ID, content "
        "updates and the dynamic services. It does not forward traffic, but a busy MP makes the GUI slow, delays "
        "commits and can lose logs. This section shows how busy it is, which processes use it, and its memory."
        + (" <b>NGFW cluster, non-leader node:</b> management runs on the leader node; this chassis works like a "
           "line card of it. Its MP figures describe a control plane on standby - the TSF of the leader shows the "
           "management load of the cluster." if ds.non_leader else ""))]
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
        agg["meaning"] = agg.cmd.map(K.process_desc)
        span_p = (p.ts.max() - p.ts.min()).total_seconds() / 86400
        out.append(ctx.h2(f"Processes (mp-monitor 'top', {n} snapshots over {span_p:.1f} days)"))
        out.append(ctx.small(f"DP worker processes ({', '.join(sorted(DP_PROCESSES))}) are left out. "
                             "avg = mean %CPU over all snapshots (absent = 0); 100% = one CPU core. Names longer than "
                             "9 characters are cut by 'top' (+). Meanings are inferred from the process names."))
        out.append(ctx.table(agg.rename(columns={"cmd": "process", "avg_cpu": "avg %CPU", "max_cpu": "max %CPU",
                                                 "res_mb": "max RES MB"}), [2.6, 1.7, 1.7, 2.0, 9.0],
                             fmt={"avg %CPU": lambda v: f"{v:.2f}", "max %CPU": lambda v: f"{v:.1f}",
                                  "max RES MB": lambda v: f"{v:,.0f}"}))
        top = agg.head(5).cmd.tolist()
        if top and n >= 3:
            w = (p[p.cmd.isin(top)].groupby(["ts", "cmd"]).cpu.sum().unstack().reindex(columns=top)
                 .reindex(sorted(p.ts.unique())).fillna(0))
            w = w.rolling(3, min_periods=1).mean()
            cmap = C.colors_for(top)
            f, ax = C.fig(C.W, 2.5)
            for c in top:
                ax.plot(w.index, w[c], color=cmap[c], lw=1.1, label=c)
            ax.set_ylabel("%CPU (100 = one core)")
            ax.set_title("Top 5 MP processes over time")
            C.time_axis(ax, span_p)
            C.legend_below(ax, 5)
            out.append(ctx.figure(f, "mp_processes"))
        lead = agg.iloc[0] if len(agg) else None
        if lead is not None and lead.avg_cpu >= 20:
            d = K.process_desc(lead.cmd)
            ctx.find("info", "MP", f"Busiest MP process: {lead.cmd} ({lead.avg_cpu:.0f}% of a core on average"
                                   + (f"; {d[0].lower() + d[1:]}" if d else "") + ").")

    # --- memory -------------------------------------------------------------------------
    if ds.has("sar_mem") and {"kbavail", "kbmemused", "%memused"}.issubset(ds["sar_mem"].columns):
        m = ds["sar_mem"].dropna(subset=["kbavail", "kbmemused", "%memused"]).sort_values("ts")
        m = m[m["%memused"] > 0]
        if len(m) >= 2:
            total = (m.kbmemused / (m["%memused"] / 100)).median()
            avail = m.kbavail / total * 100
            span_m = (m.ts.max() - m.ts.min()).total_seconds() / 86400
            out.append(ctx.h2("Memory"))
            out.append(ctx.p(
                f"MP memory: {total / 1024 ** 2:.1f} GB. Linux keeps otherwise unused memory filled with file cache "
                "and hands it back on demand, so 'used' looks high on a healthy system. What counts is the "
                "<b>available</b> memory - free plus reclaimable cache. If it stays low, processes get slow or are "
                "restarted."))
            f, ax = C.fig(C.W, 2.2)
            ax.plot(m.ts, avail, color=C.CAT[0], lw=0.8)
            ax.set_ylim(0, 100)
            ax.set_ylabel("% available")
            ax.set_title(f"MP memory available, last {span_m:.0f} days (sar)")
            C.time_axis(ax, span_m)
            out.append(ctx.figure(f, "mp_memory"))
            lo = avail.min()
            lvl = "warning" if lo < 5 else "notice" if lo < 15 else "info"
            ctx.find(lvl, "MP", f"MP memory available over {span_m:.0f} days: median {avail.median():.0f}%, "
                                f"lowest {lo:.0f}% ({m.ts.iloc[int(avail.values.argmin())]:%d.%m. %H:%M}).")

    # --- network interfaces of the MP ---------------------------------------------------------
    if ds.has("sar_net"):
        net = ds["sar_net"]
        net = net[net.IFACE != "lo"]
        agg = net.groupby("IFACE").agg(rx=("rxkB/s", "mean"), rx_max=("rxkB/s", "max"), tx=("txkB/s", "mean"),
                                       tx_max=("txkB/s", "max"))
        agg = agg[(agg.rx_max + agg.tx_max) > 0.5].sort_values("rx", ascending=False).head(8)
        if not agg.empty:
            def role(i):
                if i == "eth0":
                    return "management port (MGT)"
                if i.startswith("kni"):
                    return "internal link dataplane <-> MP (logs, DNS proxy, service routes, ...)"
                if i.startswith("eth"):
                    return "other MP port (e.g. HA control link)"
                return ""
            agg = agg.reset_index()
            agg["role"] = agg.IFACE.map(role)
            kb = lambda v: f"{v * 8 / 1000:,.2f} Mbit/s"
            out.append(ctx.h2("MP network interfaces"))
            out.append(ctx.small("As Linux on the MP sees them (sar, 30 days): mean and peak of the 10-minute averages. "
                                 "The roles are the usual ones on PAN-OS."))
            out.append(ctx.table(agg.rename(columns={"IFACE": "interface", "rx": "rx mean", "rx_max": "rx peak",
                                                     "tx": "tx mean", "tx_max": "tx peak"}),
                                 [1.8, 2.4, 2.4, 2.4, 2.4, 5.6],
                                 fmt={c: kb for c in ("rx mean", "rx peak", "tx mean", "tx peak")}))

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
            ax.set_ylabel("runnable processes")
            C.time_axis(ax, span)
            out.append(ctx.figure(f, "mp_loadavg"))
    return out
