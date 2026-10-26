"""Methodology, caveats and data files."""

from datetime import datetime

from .. import __version__
from .. import capacity as CAP

# Public sources (also in docs/SOURCES.md - keep both in sync)
SOURCES = [
    ("Model datasheet values (capacity, model limits)", "Palo Alto Networks product comparison",
     "https://www.paloaltonetworks.com/products/product-selection.html"),
    ("Reference: end-of-sale / end-of-life dates of models", "Palo Alto Networks end-of-life summary",
     "https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary"),
    ("CLI commands read from the firewall", "PAN-OS CLI Quick Start",
     "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-cli-quick-start"),
    ("XML API (live mode)", "PAN-OS and Panorama API Usage Guide",
     "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api"),
    ("Tech support files, resource monitor, HA, interfaces", "PAN-OS Administrator's Guide",
     "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin"),
    ("Background on counters and dataplane behaviour", "Palo Alto Networks Knowledge Base",
     "https://knowledgebase.paloaltonetworks.com"),
    ("Counter descriptions", "PAN-OS itself: 'show counter global' (description column)", ""),
    ("Source code", "pan-ngfw-load (MIT license)", "https://github.com/dogbyter/pan-ngfw-load"),
]

NOTICE = (
    "pan-ngfw-load contains and uses <b>no non-public data</b>. Everything this report shows about the firewall comes "
    "from the firewall itself - its tech support file or its read-only XML API. Datasheet values come only from the "
    "public product comparison of Palo Alto Networks, fetched on request ('pan-ngfw-load capacity update'); they are "
    "not part of pan-ngfw-load. Counter descriptions are those PAN-OS reports itself. The meaning of dataplane "
    "functions, resources and management-plane processes is inferred from their names and observed behaviour and is "
    "marked as such - it is not vendor documentation. The parsers were developed and tested with tech support files "
    "of firewalls the authors have access to; those files are not part of pan-ngfw-load and nothing from them is "
    "contained in it. pan-ngfw-load is an independent project, not affiliated with, endorsed by or supported by Palo "
    "Alto Networks. \"Palo Alto Networks\" and \"PAN-OS\" are trademarks of Palo Alto Networks, Inc.")

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
    out = [ctx.h1(TITLE), ctx.h2("About this report"), ctx.table(_about(ctx), [5.0, 12.0]), ctx.h2("Method and caveats")]
    out += [ctx.p("- " + t) for t in items]
    out.append(ctx.h2("Sources and legal notice"))
    out.append(ctx.p(NOTICE))
    import pandas as pd
    link = lambda u: f"<link href='{u}' color='#2a78d6'>{u}</link>" if u else "in the tech support file / API output"
    out.append(ctx.table(pd.DataFrame([(w, t, link(u)) for w, t, u in SOURCES], columns=["used for", "source", "where"]),
                         [4.6, 4.4, 8.0]))
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


def _about(ctx):
    """pan-ngfw-load version and the options this report was made with."""
    import pandas as pd
    st, meta = ctx.settings, ctx.ds.meta
    kind = st.get("report_kind", "standard") + (", with sub-interface detail" if st.get("subinterfaces") else "")
    _vals, _notes, src, status = CAP.limits(st, meta.get("model", ""))
    rows = [
        ("pan-ngfw-load version", __version__),
        ("Created", f"{datetime.now():%Y-%m-%d %H:%M}"),
        ("Report", kind),
        ("Source", "live collection (XML API)" if ctx.ds.source == "live" else "tech support file"),
        ("Anonymized", "yes" if meta.get("anonymized") else "no"),
        ("Core spikes", f"{st.get('spike_threshold', 10):g} points above the other cores for "
                        f"{st.get('spike_min_minutes', 15)} min or longer"),
        ("Datasheet values", src if status == "ok" else "model not in the public product comparison"
                             if status == "no_model" else "not fetched ('pan-ngfw-load capacity update')"),
    ]
    return pd.DataFrame(rows, columns=["", "value"])
