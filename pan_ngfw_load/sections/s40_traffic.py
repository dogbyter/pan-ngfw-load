"""Which traffic drives the load: volume over time, load-vs-traffic correlation, applications, counters."""

import numpy as np
import pandas as pd

from .. import charts as C

TITLE = "Traffic that drives the load"
DP_SCOPED = "partly"  # chassis: rates and load over time come from one DP (see dataset.select_dp)


def _rate(ds, name):
    r = ds["dp_counter_rates"]
    return r[r.name == name].set_index("ts").rate.sort_index() if not r.empty else pd.Series(dtype=float)


def build(ctx):
    ds = ctx.ds
    out = [ctx.h1(TITLE), ctx.p(
        "The tech support file has no traffic logs, so load can't be traced to single sessions. "
        "This section combines three things instead: traffic volume over time, how closely the DP load follows "
        "packet and connection rates, and the application statistics accumulated since boot.")]

    # --- traffic over time ---------------------------------------------------
    if ds.has("dp_counter_rates"):
        pps, cps = _rate(ds, "pkt_recv"), _rate(ds, "session_installed")
        sess = ds["dpm_session"].set_index("ts").sessions_allocated if ds.has("dpm_session") else pd.Series(dtype=float)
        span = (pps.index.max() - pps.index.min()).total_seconds() / 86400 if len(pps) else 1
        f, axes = C.plt.subplots(3, 1, figsize=(C.W, 4.8), dpi=150, sharex=True)
        for ax, s, title, col in ((axes[0], pps, "Packets received per second (10-min average)", C.CAT[0]),
                                  (axes[1], cps, "New sessions per second (10-min average)", C.CAT[0]),
                                  (axes[2], sess, "Allocated sessions (snapshot)", C.CAT[0])):
            ax.plot(s.index, s.values, color=col, lw=1.1)
            ax.set_title(title)
        C.time_axis(axes[2], span)
        out.append(ctx.figure(f, "traffic_time"))

    # --- load vs traffic -----------------------------------------------------
    if ds.has("dp_pow_interval") and ds.has("dp_counter_rates"):
        pi = ds["dp_pow_interval"]
        load = pi[pi.kind == "group"].groupby("ts").pct.sum()
        df = pd.DataFrame({"load": load, "pps": _rate(ds, "pkt_recv"), "cps": _rate(ds, "session_installed")}).dropna()
        if len(df) > 10:
            f, axes = C.plt.subplots(1, 2, figsize=(C.W, 2.8), dpi=150, sharey=True)
            corr = {}
            for ax, col, lab in ((axes[0], "pps", "packets / s"), (axes[1], "cps", "new sessions / s")):
                r = df["load"].corr(df[col])
                corr[col] = r
                ax.scatter(df[col], df["load"], s=10, color=C.CAT[0], alpha=0.6, edgecolors=C.SURFACE, linewidths=0.4)
                if df[col].std() > 0:
                    k, d = np.polyfit(df[col], df["load"], 1)
                    xs = np.linspace(df[col].min(), df[col].max(), 20)
                    ax.plot(xs, k * xs + d, color=C.INK2, lw=1, ls="--")
                ax.set_xlabel(lab)
                ax.set_title(f"DP load vs {lab}  (r = {r:.2f})")
            axes[0].set_ylabel("% of DP capacity")
            out.append(ctx.figure(f, "load_vs_traffic",
                                  "Each dot is one 10-minute interval. r = Pearson correlation (1 = load rises in step with the rate)."))
            drv = max(corr, key=lambda k: corr[k] if not np.isnan(corr[k]) else -9)
            ctx.find("info", "Traffic",
                     f"DP load follows {'packet rate' if drv == 'pps' else 'new-session rate'} most closely "
                     f"(r = {corr[drv]:.2f}; pps r = {corr['pps']:.2f}, cps r = {corr['cps']:.2f}).")
            fixed = df["load"].min()
            ctx.find("info", "Traffic",
                     f"Baseline DP load with almost no traffic is about {fixed:.2f}% of capacity (timers, housekeeping). "
                     "That work is fixed and doesn't grow with traffic.")

    # --- applications since boot --------------------------------------------
    if ds.has("apps"):
        a = ds["apps"].groupby("app")[["sessions", "packets", "bytes"]].sum()
        out.append(ctx.h2("Applications since boot"))
        f, axes = C.plt.subplots(1, 3, figsize=(C.W, 3.3), dpi=150)
        for ax, col, title in ((axes[0], "bytes", "Bytes"), (axes[1], "packets", "Packets"),
                               (axes[2], "sessions", "Sessions")):
            s = C.top_n(a[col].astype(float), 8)
            C.hbar(ax, s, color=C.CAT[0], labeler=C.human)
            ax.set_title(title)
        out.append(ctx.figure(f, "apps_boot",
                              "From 'show running application statistics' (vsys totals since boot). More packets usually "
                              "means more DP work. Each new session costs slow-path work."))
        t = a.sort_values("bytes", ascending=False).head(15).reset_index()
        t["bytes/pkt"] = t.bytes / t.packets.where(t.packets > 0)
        t["pkt/session"] = t.packets / t.sessions.where(t.sessions > 0)
        t["share pkts"] = t.packets / a.packets.sum() * 100
        out.append(ctx.table(t[["app", "sessions", "packets", "bytes", "share pkts", "bytes/pkt", "pkt/session"]],
                             [4.4, 2.0, 2.2, 2.6, 1.8, 1.8, 2.0],
                             fmt={"sessions": lambda v: f"{v:,}", "packets": lambda v: f"{v:,}", "bytes": C.human_bytes,
                                  "share pkts": lambda v: f"{v:.1f}%", "bytes/pkt": lambda v: f"{v:,.0f}",
                                  "pkt/session": lambda v: f"{v:,.0f}"}))
        top_b, top_s = a.bytes.idxmax(), a.sessions.idxmax()
        ctx.find("info", "Traffic",
                 f"Since boot, '{top_b}' carried the most bytes ({C.human_bytes(a.bytes.max())}), '{a.packets.idxmax()}' "
                 f"the most packets, and '{top_s}' opened the most sessions ({a.sessions.max():,}). "
                 f"High session counts drive slow-path work.", whole=True)

    # --- session snapshot ----------------------------------------------------
    if ds.has("sessions_now"):
        s = ds["sessions_now"]
        out.append(ctx.h2(f"Session snapshot at TSF time ({len(s)} sessions)"))
        t = (s.groupby(["app", "from_zone", "to_zone"]).size().rename("sessions").reset_index()
             .sort_values("sessions", ascending=False).head(15))
        out.append(ctx.table(t, [5.5, 3.5, 3.5, 2.0]))

    # --- global counters -----------------------------------------------------
    if ds.has("dp_counter_rates"):
        r = ds["dp_counter_rates"]
        agg = r.groupby("name").rate.agg(["mean", "max"]).sort_values("mean", ascending=False)
        agg = agg[agg["mean"] > 0].head(20).reset_index()
        out.append(ctx.h2("Busiest global counters (per-second rates)"))
        out.append(ctx.small("Counters show what the DP spends its time on: ctd_* = content inspection, flow_* = "
                             "packet/session handling, proxy_* = decryption, log_* = logging. Rates are averaged over "
                             "the sampling intervals (dp-monitor or collector)."))
        out.append(ctx.table(agg.rename(columns={"name": "counter", "mean": "avg / s", "max": "max / s"}), [7.0, 3.0, 3.0],
                             fmt={"avg / s": lambda v: f"{v:,.1f}", "max / s": lambda v: f"{v:,.1f}"}))
        drops = r[r.name.str.contains("drop|_err|fail", regex=True)].groupby("name").rate.mean()
        drops = drops[drops > 0.01].sort_values(ascending=False).head(10)
        if not drops.empty:
            out.append(ctx.h2("Drop / error counters with a non-zero rate"))
            out.append(ctx.table(drops.rename("avg / s").reset_index().rename(columns={"name": "counter"}), [7.0, 3.0],
                                 fmt={"avg / s": lambda v: f"{v:,.2f}"}))
    return out
