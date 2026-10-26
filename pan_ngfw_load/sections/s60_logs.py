"""Traffic-log attribution: which apps, rules, hosts and zone pairs generate the work."""

import numpy as np
import pandas as pd

from .. import charts as C

TITLE = "Traffic logs - who generates the load"


def _share(s: pd.Series) -> pd.Series:
    return s / s.sum() * 100 if s.sum() else s


def build(ctx):
    ds = ctx.ds
    if not ds.has("logs_traffic"):
        return []
    lg = ds["logs_traffic"].copy()
    for c in ("bytes", "packets", "bytes_sent", "bytes_received", "pkts_sent", "pkts_received", "elapsed", "repeatcnt"):
        if c in lg.columns:
            lg[c] = pd.to_numeric(lg[c], errors="coerce").fillna(0)
    lg["sessions"] = lg["repeatcnt"].clip(lower=1) if "repeatcnt" in lg.columns else 1
    t0, t1 = lg.receive_time.min(), lg.receive_time.max()
    span = (t1 - t0).total_seconds() / 86400
    out = [ctx.h1(TITLE), ctx.p(
        f"{len(lg):,} traffic log entries from {t0:%Y-%m-%d %H:%M} to {t1:%Y-%m-%d %H:%M} ({span:.1f} days). "
        "A log is written when a session ends and carries that session's total packets and bytes. Long sessions "
        "therefore count at their end time. Only sessions matched by rules with logging enabled appear here. "
        "DP load follows the <b>packet rate</b> most closely (see 'Traffic that drives the load'), so packets are the best "
        "available measure of which traffic drives DP work. New sessions add slow-path work on top.")]

    # --- over time by app ----------------------------------------------------
    freq = "5min" if span <= 0.5 else "1h" if span <= 3 else "6h" if span <= 14 else "1D"
    top_apps = lg.groupby("app").packets.sum().sort_values(ascending=False).index[:7].tolist()
    lg["app_g"] = np.where(lg.app.isin(top_apps), lg.app, "Other")
    order = top_apps + (["Other"] if (lg.app_g == "Other").any() else [])
    cmap = C.colors_for(order)
    wide = lg.groupby([pd.Grouper(key="receive_time", freq=freq), "app_g"]).packets.sum().unstack().reindex(columns=order).fillna(0)
    per_s = pd.Timedelta(freq).total_seconds()
    f, ax = C.fig(C.W, 3.0)
    C.stacked_area(ax, wide / per_s, cmap)
    C.time_axis(ax, max(span, 0.5))
    ax.set_ylabel("packets / s (avg)")
    ax.set_title(f"Logged packets per second by application ({freq} buckets)")
    C.legend_below(ax, 4)
    out.append(ctx.figure(f, "logs_app_time"))

    # --- top apps / rules ----------------------------------------------------
    by_app = lg.groupby("app").agg(sessions=("sessions", "sum"), packets=("packets", "sum"), bytes=("bytes", "sum"))
    f, axes = C.plt.subplots(1, 3, figsize=(C.W, 3.3), dpi=150)
    for ax, col, title in ((axes[0], "packets", "Packets"), (axes[1], "sessions", "Sessions"), (axes[2], "bytes", "Bytes")):
        C.hbar(ax, C.top_n(_share(by_app[col]), 8), unit="%")
        ax.set_title(f"{title} %")
    out.append(ctx.figure(f, "logs_top_apps"))

    agg = dict(sessions=("sessions", "sum"), packets=("packets", "sum"), bytes=("bytes", "sum"))
    t = lg.groupby("app").agg(**agg).sort_values("packets", ascending=False).head(15).reset_index()
    t["pkt %"] = t.packets / lg.packets.sum() * 100
    t["sess %"] = t.sessions / lg.sessions.sum() * 100
    t["pkt/sess"] = t.packets / t.sessions
    out.append(ctx.table(t[["app", "sessions", "sess %", "packets", "pkt %", "bytes", "pkt/sess"]], [4.4, 2.0, 1.6, 2.2, 1.6, 2.4, 1.8],
                         fmt={"sessions": lambda v: f"{v:,.0f}", "packets": lambda v: f"{v:,.0f}", "bytes": C.human,
                              "sess %": lambda v: f"{v:.1f}", "pkt %": lambda v: f"{v:.1f}", "pkt/sess": lambda v: f"{v:,.0f}"}))

    out.append(ctx.h2("By rule and zone pair"))
    r = lg.groupby("rule").agg(**agg).sort_values("packets", ascending=False).head(12).reset_index()
    r["pkt %"] = r.packets / lg.packets.sum() * 100
    out.append(ctx.table(r[["rule", "sessions", "packets", "pkt %", "bytes"]], [6.0, 2.4, 2.6, 1.6, 2.4],
                         fmt={"sessions": lambda v: f"{v:,.0f}", "packets": lambda v: f"{v:,.0f}", "bytes": C.human,
                              "pkt %": lambda v: f"{v:.1f}"}))
    z = lg.groupby(["from", "to"]).agg(**agg).sort_values("packets", ascending=False).head(10).reset_index()
    out.append(ctx.table(z, [3.5, 3.5, 2.6, 2.8, 2.6],
                         fmt={"sessions": lambda v: f"{v:,.0f}", "packets": lambda v: f"{v:,.0f}", "bytes": C.human}))

    out.append(ctx.h2("Top talkers"))
    for col, label in (("src", "Source"), ("dst", "Destination")):
        h = lg.groupby(col).agg(**agg).sort_values("packets", ascending=False).head(10).reset_index()
        h["top app"] = h[col].map(lg.groupby(col).app.agg(lambda s: s.value_counts().index[0]))
        out.append(ctx.small(f"{label} hosts by packets"))
        out.append(ctx.table(h[[col, "top app", "sessions", "packets", "bytes"]], [3.6, 4.6, 2.4, 2.6, 2.4],
                             fmt={"sessions": lambda v: f"{v:,.0f}", "packets": lambda v: f"{v:,.0f}", "bytes": C.human}))

    # --- heatmap day x hour --------------------------------------------------
    if span >= 2:
        hm = lg.assign(d=lg.receive_time.dt.date, h=lg.receive_time.dt.hour).groupby(["d", "h"]).packets.sum().unstack(fill_value=0)
        hm = hm.reindex(columns=range(24), fill_value=0)
        f, ax = C.fig(C.W, 0.18 * len(hm) + 1.2)
        from matplotlib.colors import LinearSegmentedColormap
        cm = LinearSegmentedColormap.from_list("seq", C.SEQ)
        im = ax.imshow(hm.values / 3600, aspect="auto", cmap=cm, interpolation="nearest")
        ax.set_yticks(range(len(hm)))
        ax.set_yticklabels([d.strftime("%d.%m.") for d in hm.index], fontsize=6)
        ax.set_xticks(range(0, 24, 2))
        ax.set_xlabel("hour of day")
        ax.grid(False)
        cb = f.colorbar(im, ax=ax, fraction=0.03, pad=0.01)
        cb.set_label("packets / s", fontsize=7)
        ax.set_title("Logged packets per second by day and hour")
        out.append(ctx.figure(f, "logs_heatmap"))

    # --- features that make traffic expensive -------------------------------
    def flag(c):
        return lg[c].astype(str).str.lower().isin(["yes", "true", "1"]) if c in lg.columns else pd.Series(False, index=lg.index)

    rows = []
    for label, mask in (("Decrypted (SSL decryption)", flag("s_decrypted") | flag("flag-decrypt-forwarded")),
                        ("Tunnel content inspected", flag("flag-tunnel-inspected")),
                        ("L7 inspection skipped", flag("flag-l7-skipped")),
                        ("Offloaded", flag("offloaded")),
                        ("Denied / dropped", lg.action.astype(str).str.contains("deny|drop|reset", regex=True))):
        rows.append((label, mask.sum(), mask.mean() * 100, lg.loc[mask, "packets"].sum() / max(lg.packets.sum(), 1) * 100))
    out.append(ctx.h2("Traffic properties that change the DP cost"))
    out.append(ctx.table(pd.DataFrame(rows, columns=["property", "sessions", "% sessions", "% packets"]), [6.0, 2.6, 2.4, 2.4],
                         fmt={"sessions": lambda v: f"{v:,.0f}", "% sessions": lambda v: f"{v:.1f}", "% packets": lambda v: f"{v:.1f}"}))
    ends = lg.session_end_reason.value_counts().head(8).rename("sessions").reset_index()
    out.append(ctx.small("Session end reasons"))
    out.append(ctx.table(ends.rename(columns={"session_end_reason": "end reason"}), [6.0, 2.6],
                         fmt={"sessions": lambda v: f"{v:,.0f}"}))

    # --- findings ------------------------------------------------------------
    pk = _share(by_app.packets).sort_values(ascending=False)
    ss = _share(by_app.sessions).sort_values(ascending=False)
    ctx.find("info", "Traffic logs",
             f"{span:.0f} days of traffic logs: '{pk.index[0]}' has the most packets ({pk.iloc[0]:.0f}%), followed by "
             f"'{pk.index[1]}' ({pk.iloc[1]:.0f}%). '{ss.index[0]}' opens the most sessions ({ss.iloc[0]:.0f}%), "
             "so it drives most of the session-setup work.")
    src_top = lg.groupby("src").packets.sum().sort_values(ascending=False)
    ctx.find("info", "Traffic logs",
             f"Busiest source host: {src_top.index[0]} ({src_top.iloc[0] / src_top.sum() * 100:.0f}% of logged packets).")
    return out
