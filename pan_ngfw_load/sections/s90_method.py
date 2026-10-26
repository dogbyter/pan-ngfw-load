"""Methodology, caveats and data files."""

TITLE = "Appendix - method and caveats"


def build(ctx):
    ds = ctx.ds
    items = [
        "<b>Time stamps</b> are the device's local time. Resource-monitor tables list the newest sample first; each "
        "sample is anchored to the 'show clock' time of the TSF.",
        "<b>Resource-monitor max</b> values (week/day/hour) catch short bursts. They show <i>that</i> a burst happened, "
        "not <i>what</i> caused it. Only bursts inside the dp-monitor window (last ~2-3 days) can be explained.",
        "<b>pow performance</b> accumulated values (ac-*) cover the whole time since boot. The 10-minute view is "
        "computed from the difference between consecutive dp-monitor snapshots, divided by (worker cores x interval).",
        "<b>Groups vs functions:</b> the two are measured separately and can overlap. Some functions (e.g. "
        "tim_check) run outside every group, so neither view alone adds up to the total DP busy time. "
        "'*_latency' functions measure waiting time, not CPU time, and are left out.",
        "<b>Function to feature mapping</b> is inferred from function names (pan_ngfw_load/knowledge.py). Treat it as a "
        "best guess and refine it when Palo Alto Networks documentation or a TAC answer shows otherwise.",
        "<b>sar on shared-CPU platforms:</b> DP worker cores always look 100% busy (busy-polling). Only MP cores count.",
        "<b>No traffic logs</b> are in a TSF. Per-session, per-rule or per-source attribution needs logs from the "
        "device. The live collector of pan-ngfw-load exports them through the read-only XML API.",
    ]
    out = [ctx.h1(TITLE)] + [ctx.p("- " + t) for t in items]
    out.append(ctx.h2("Data files"))
    out.append(ctx.p("All tables behind this report are saved as CSV in <i>data/</i> next to this PDF, and every chart "
                     "as PNG in <i>charts/</i>. Tables: " + ", ".join(sorted(k for k, v in ds.t.items() if not v.empty)) + "."))
    out.append(ctx.h2("Bundle inventory"))
    if ds.bundle is not None:
        inv = ds.bundle.inventory()
        if ds.meta.get("anonymized"):  # file names can contain the hostname
            inv = {k: ("present" if k == "CLI dump" and v != "missing" else v) for k, v in inv.items()}
        out.append(ctx.p("<br/>".join(f"{k}: {v}" for k, v in inv.items())))
    else:
        out[-1] = ctx.h2("Source")
        out.append(ctx.p("Live collection via the read-only XML API. The pow performance breakdown needs "
                         "superuser rights and is only available from tech support files."))
    return out
