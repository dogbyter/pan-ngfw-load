"""Sessions: how full the session table is, the TCP/UDP/ICMP mix over time, and what the sessions in the
table were when the tech support file was taken (zones, applications, ports, NAT)."""

import pandas as pd

from .. import charts as C

TITLE = "Sessions"
DP_SCOPED = "partly"  # chassis: rates and load over time come from one DP (see dataset.select_dp)

PROTO = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6", 50: "ESP", 47: "GRE"}


def build(ctx):
    ds = ctx.ds
    si = ds.meta.get("session_info") or {}
    has_ts = ds.has("dpm_session") and "sessions_allocated" in ds["dpm_session"].columns
    if not si and not has_ts and not ds.has("sessions_now"):
        return []
    out = [ctx.h1(TITLE), ctx.p(
        "Every connection through the firewall is a session in the dataplane's session table - including UDP "
        "flows, ICMP and denied attempts that are still being tracked. The table has a fixed maximum per model. "
        "Sessions stay in it until they close or time out, so long timeouts and scans keep it fuller than the "
        "real traffic would.")]

    # --- current state ----------------------------------------------------------------
    if si:
        up = None
        if ds.meta.get("boot_time") is not None and ds.meta.get("tsf_time") is not None:
            up = (ds.meta["tsf_time"] - ds.meta["boot_time"]).total_seconds()
        rows = [
            ("Sessions in the table", si.get("sessions_allocated"), "{:,.0f}"),
            ("Maximum for this model", si.get("sessions_supported"), "{:,.0f}"),
            ("Table utilisation", si.get("session_util_pct"), "{:.0f}%"),
            ("TCP / UDP / ICMP", None, ""),
            ("New sessions per second (now)", si.get("cps"), "{:,.0f}"),
            ("Sessions created since boot", si.get("sessions_created_total"), "{:,.0f}"),
            ("Average new sessions per second since boot",
             si.get("sessions_created_total") / up if up and si.get("sessions_created_total") else None, "{:,.0f}"),
        ]
        tcp, udp, icmp = (si.get(k) for k in ("sessions_tcp", "sessions_udp", "sessions_icmp"))
        tab = []
        for lab, v, fmt in rows:
            if lab.startswith("TCP"):
                if tcp is not None:
                    tab.append((lab, f"{tcp:,.0f} / {udp or 0:,.0f} / {icmp or 0:,.0f}"))
            elif v is not None:
                tab.append((lab, fmt.format(v)))
        when = "at the time of the tech support file" if ds.source != "live" else "in the latest sample"
        out.append(ctx.h2("Session table now"))
        out.append(ctx.small(f"From 'show session info' {when}."))
        out.append(ctx.table(pd.DataFrame(tab, columns=["", "value"]), [7.5, 4.5]))
        if si.get("session_util_pct") is not None:
            lvl = "warning" if si["session_util_pct"] >= 90 else "notice" if si["session_util_pct"] >= 70 else "info"
            ctx.find(lvl, "Sessions", f"Session table {si['session_util_pct']:.0f}% full "
                                      f"({si.get('sessions_allocated', 0):,.0f} of {si.get('sessions_supported', 0):,.0f}).", whole=True)

    # --- over time ----------------------------------------------------------------------
    if has_ts:
        s = ds["dpm_session"].set_index("ts").sort_index()
        cols = [c for c in ("sessions_tcp", "sessions_udp", "sessions_icmp") if c in s.columns and s[c].notna().any()]
        if cols and len(s) >= 2:
            span = (s.index.max() - s.index.min()).total_seconds() / 86400
            labels = {"sessions_tcp": "TCP", "sessions_udp": "UDP", "sessions_icmp": "ICMP"}
            cmap = C.colors_for([labels[c] for c in cols])
            f, ax = C.fig(C.W, 2.5)
            ax.stackplot(s.index, *[s[c].fillna(0).values for c in cols], labels=[labels[c] for c in cols],
                         colors=[cmap[labels[c]] for c in cols], linewidth=0)
            ax.set_ylabel("sessions")
            ax.yaxis.set_major_formatter(C.plt.FuncFormatter(lambda v, _p: C.human(v)))
            ax.set_title(f"Sessions in the table by protocol, last {span:.1f} days")
            C.time_axis(ax, span)
            C.legend_below(ax, len(cols))
            out.append(ctx.figure(f, "sessions_mix"))
            a = s.sessions_allocated.dropna()
            if len(a):
                ctx.find("info", "Sessions", f"Over {span:.1f} days the table held {a.min():,.0f} to {a.max():,.0f} "
                                             f"sessions (median {a.median():,.0f}).")

    # --- snapshot ---------------------------------------------------------------------
    if ds.has("sessions_now"):
        x = ds["sessions_now"].copy()
        total = si.get("sessions_allocated")
        out.append(ctx.h2("What is in the table"))
        out.append(ctx.p(
            f"The tech support file lists {len(x):,} sessions"
            + (f" of the {total:,.0f} in the table" if total and total > len(x) else "")
            + (" - only the first entries of the table, so treat the shares as a sample, not exact numbers." if
               total and total > len(x) * 1.2 else ".")))
        x["protocol"] = x.proto.map(lambda p: PROTO.get(int(p), str(p)) if pd.notna(p) else "?")
        x["zones"] = x.from_zone.astype(str) + " → " + x.to_zone.astype(str)
        x["nat"] = (x.xsrc != x.src) | (x.xdst != x.dst)
        x["service"] = x.protocol + "/" + x.dport.astype(str)

        def share(col, n=8):
            v = x[col].value_counts()
            t = C.top_n(v.astype(float), n)
            return (t / len(x) * 100)

        f, axes = C.plt.subplots(1, 3, figsize=(C.W, 3.2), dpi=150)
        for ax, col, title in ((axes[0], "app", "Applications"), (axes[1], "zones", "Zone pairs"),
                               (axes[2], "service", "Destination ports")):
            C.hbar(ax, share(col), unit="%")
            ax.set_title(f"{title} (% of sessions)")
        out.append(ctx.figure(f, "sessions_snapshot"))

        parts = [f"{x.nat.mean() * 100:.0f}% of the listed sessions are translated (NAT)"]
        pr = x.protocol.value_counts(normalize=True) * 100
        parts.append(", ".join(f"{k} {v:.0f}%" for k, v in pr.head(4).items()))
        if "state" in x.columns:
            st = x.state.value_counts(normalize=True) * 100
            parts.append("state " + ", ".join(f"{k} {v:.0f}%" for k, v in st.head(3).items()))
        out.append(ctx.p("; ".join(parts) + "."))

        src = x.src.value_counts().head(8)
        dst = x.dst.value_counts().head(8)
        if len(x) >= 50 and (src.iloc[0] / len(x) >= 0.1 or dst.iloc[0] / len(x) >= 0.1):
            out.append(ctx.small("Hosts with the most sessions in the list:"))
            tab = pd.DataFrame({"source": [f"{k} ({v})" for k, v in src.items()]}).join(
                pd.DataFrame({"destination": [f"{k} ({v})" for k, v in dst.items()]}), how="outer").fillna("")
            out.append(ctx.table(tab, [8.0, 8.0]))
    return out
