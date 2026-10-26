"""Extended: physical interfaces - traffic since boot, average use of the link speed, errors and drops."""

import pandas as pd

from .. import charts as C

TITLE = "Interfaces"

ERR_NOTICE = 1e-5  # receive errors per received packet (10 per million)


def build(ctx):
    ds = ctx.ds
    if not ds.has("if_counters"):
        return []
    ic = ds["if_counters"]
    ic = ic[ic.interface.str.match(r"^(ethernet\d+/\d+|ae\d+)$")].copy()
    ic = ic[(ic.rx_bytes > 0) | (ic.tx_bytes > 0)]
    if ic.empty:
        return []
    boot, now = ds.meta.get("boot_time"), ds.meta.get("tsf_time")
    up = (now - boot).total_seconds() if boot is not None and now is not None else None
    if ds.has("if_hw"):
        ic = ic.merge(ds["if_hw"][["interface", "speed", "state"]], on="interface", how="left")
    else:
        ic["speed"], ic["state"] = float("nan"), ""
    for col in ("rx_errors", "rx_discards", "drops"):
        if col not in ic.columns:
            ic[col] = 0
    ic = ic.fillna({"rx_errors": 0, "rx_discards": 0, "drops": 0})
    if up:
        ic["rx_mbps"] = ic.rx_bytes * 8 / up / 1e6
        ic["tx_mbps"] = ic.tx_bytes * 8 / up / 1e6
        ic["use_pct"] = (ic[["rx_mbps", "tx_mbps"]].max(axis=1) / ic.speed * 100).where(ic.speed > 0)
    ic["err_ppm"] = ic.rx_errors / ic.rx_pkts.where(ic.rx_pkts > 0) * 1e6
    ic["pkt"] = ic.rx_bytes / ic.rx_pkts.where(ic.rx_pkts > 0)
    ic = ic.sort_values("rx_bytes", ascending=False)

    out = [ctx.h1(TITLE), ctx.p(
        "Traffic and errors per physical port and aggregate group since the last boot (dataplane counters, "
        "'show counter interface all'). The averages spread the whole period evenly, so they show which ports "
        "carry the bulk of the traffic, not how high the peaks were. An aggregate (ae) and its members both "
        "appear when both are counted.")]

    show = ic[["interface", "speed", "rx_bytes", "tx_bytes"] + (["rx_mbps", "tx_mbps", "use_pct"] if up else [])
              + ["pkt", "rx_errors", "err_ppm"]].rename(columns={
                  "speed": "link", "rx_bytes": "received", "tx_bytes": "sent", "rx_mbps": "avg in",
                  "tx_mbps": "avg out", "use_pct": "avg use", "pkt": "avg pkt", "rx_errors": "rx errors",
                  "err_ppm": "errors / M pkts"})
    fmt = {"link": lambda v: "-" if pd.isna(v) else (f"{v / 1000:g}G" if v >= 1000 else f"{v:g}M"),
           "received": lambda v: C.human(v) + "B", "sent": lambda v: C.human(v) + "B",
           "avg in": lambda v: f"{v:,.0f} Mb/s", "avg out": lambda v: f"{v:,.0f} Mb/s",
           "avg use": lambda v: "-" if pd.isna(v) else f"{v:.1f}%", "avg pkt": lambda v: "-" if pd.isna(v) else f"{v:,.0f} B",
           "rx errors": lambda v: f"{v:,.0f}", "errors / M pkts": lambda v: "-" if pd.isna(v) else f"{v:.2f}"}
    widths = [2.4, 1.2, 1.8, 1.8] + ([1.9, 1.9, 1.5] if up else []) + [1.5, 1.6, 1.6]
    out.append(ctx.table(show, widths, fmt=fmt))

    phys = ic[~ic.interface.str.startswith("ae")]  # an aggregate repeats its members' traffic
    tot = phys.assign(total=phys.rx_bytes + phys.tx_bytes).set_index("interface").total
    tot = C.top_n(tot[tot > 0].astype(float), 9)
    f, ax = C.fig(C.W, 0.28 * len(tot) + 0.8)
    C.hbar(ax, tot, labeler=lambda v: C.human(v) + "B")
    ax.set_title("Traffic per physical port since boot (received + sent)")
    out.append(ctx.figure(f, "interfaces_traffic"))

    bad = ic[ic.err_ppm >= ERR_NOTICE * 1e6]
    if not bad.empty:
        out.append(ctx.p(
            "<b>Receive errors</b> are frames the port received damaged (CRC, alignment, runts). More than a few per "
            "million packets usually points to a cable, optic or the device on the other end - not to load."))
        ctx.find("notice", "Interfaces", "Receive errors above 10 per million packets: " + ", ".join(
            f"{r.interface} {r.rx_errors:,.0f} ({r.err_ppm:.1f}/M)" for r in bad.itertuples()) + ".")
    if up and ic.use_pct.notna().any() and ic.use_pct.max() >= 1:
        hi = ic.sort_values("use_pct", ascending=False).iloc[0]
        ctx.find("info", "Interfaces", f"Busiest port on average since boot: {hi.interface} "
                                       f"({hi.use_pct:.0f}% of {hi.speed / 1000:g} Gbit/s, larger direction).")
    return out
