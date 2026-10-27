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

# Listed only in reports of chassis models (PA-7000/7500) and NGFW clusters - not in docs/SOURCES.md
CHASSIS_SOURCES = [
    ("NGFW clusters (PA-7500): nodes, states, HSCI links, MC-LAG", "PAN-OS Administrator's Guide: NGFW Clusters",
     "https://docs.paloaltonetworks.com/ngfw/administration/ngfw-clustering/ngfw-clusters"),
    ("NGFW cluster settings and verification commands", "Configure an NGFW Cluster",
     "https://docs.paloaltonetworks.com/ngfw/administration/ngfw-clustering/configure-an-ngfw-cluster"),
    ("Active/passive HA on PA-7500 (from PAN-OS 12.1.5)", "Configure Active/Passive HA",
     "https://docs.paloaltonetworks.com/ngfw/administration/high-availability/set-up-activepassive-ha/configure-activepassive-ha"),
]

NOTICE = (
    "pan-ngfw-load contains and uses <b>no non-public data</b>. Everything this report shows about the firewall comes "
    "from the firewall itself - its tech support file or its read-only XML API. Datasheet values come only from the "
    "public product comparison of Palo Alto Networks: a snapshot of it ships with pan-ngfw-load (with its retrieval "
    "date), current values are fetched with 'pan-ngfw-load capacity update'. They are Palo Alto Networks' published "
    "figures, unchanged except for unit conversion. Counter descriptions are those PAN-OS reports itself. The meaning of dataplane "
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
    if ds.dps:
        items.append(
            f"<b>Chassis with {len(ds.dps)} dataplanes:</b> every DP has its own cores, resource-monitor, pow "
            "performance and dp-monitor history (opt/var/s&lt;slot&gt;/dp&lt;n&gt;/ in the TSF). The DP sections cover one "
            "DP each; global counters, sessions, application statistics and interface counters cover the whole "
            "firewall. The busiest DP is the one with the highest mean core load over its dp-monitor history. The CSV "
            "files of each DP are in <i>data/dp_&lt;name&gt;/</i> when the report was built with --all-dps.")
    if ds.nodes:
        items.append(
            f"<b>Cluster report ({len(ds.nodes)} nodes):</b> each node counts only the traffic its own dataplanes "
            "processed, also for ports of the other chassis. Counters, applications, sessions and interface traffic "
            "are therefore added up over the nodes; that the shares add up is inferred from the counters (received "
            "and sent bytes balance only over all nodes), not from vendor documentation. Management plane, "
            "configuration, limits and logs come from the leader's TSF. 'Now' values are from the moment each TSF "
            "was taken. Each node's own tables are in <i>data/node&lt;n&gt;/</i>.")
    out = [ctx.h1(TITLE), ctx.h2("About this report"), ctx.table(_about(ctx), [5.0, 12.0]), ctx.h2("Method and caveats")]
    out += [ctx.p("- " + t) for t in items]
    out.append(ctx.h2("Sources and legal notice"))
    out.append(ctx.p(NOTICE))
    import pandas as pd
    link = lambda u: f"<link href='{u}' color='#2a78d6'>{u}</link>" if u else "in the tech support file / API output"
    src = SOURCES[:-3] + CHASSIS_SOURCES + SOURCES[-3:] if ds.dps or ds.has("cluster") else SOURCES
    out.append(ctx.table(pd.DataFrame([(w, t, link(u)) for w, t, u in src], columns=["used for", "source", "where"]),
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
    ]
    if ctx.ds.nodes:
        rows.append(("Cluster", f"{len(ctx.ds.nodes)} nodes, leader node {meta.get('cluster_leader')}; DP sections for "
                                "the busiest DP of each node: " + ", ".join(meta.get("dp_shown") or [])))
    elif ctx.ds.dps:
        n = len(ctx.ds.dps)
        rows.append(("Dataplanes", f"{n} - DP sections for each of them (--all-dps)" if st.get("all_dps_doc") else
                     f"{n} - DP sections for {meta.get('dp')} (" + ("chosen with --dp" if st.get("dp") else
                                                                   "the busiest") + ")"))
    rows += [
        ("Core spikes", f"{st.get('spike_threshold', 10):g} points above the other cores for "
                        f"{st.get('spike_min_minutes', 15)} min or longer"),
        ("Datasheet values", src if status == "ok" else "model not in the public product comparison"
                             if status == "no_model" else "not fetched ('pan-ngfw-load capacity update')"),
    ]
    return pd.DataFrame(rows, columns=["", "value"])
