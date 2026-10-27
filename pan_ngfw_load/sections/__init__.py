"""Report sections, in report order.

A section is a module with
    TITLE: str
    build(ctx) -> list[flowable]   (return [] if its data is missing or it has nothing to show)
It may call ctx.find(level, section, text) to add a line to the summary page.
To add a focus area: create sNN_<name>.py and add it to SECTIONS (and optionally to a profile).
"""

from . import (s10_coverage, s12_cluster, s15_dp_compare, s20_dp_load, s22_dp_resources, s25_core_spikes, s28_drops,
               s30_dp_breakdown, s40_traffic, s42_interfaces, s45_sessions, s46_vpn, s48_capacity, s49_scale, s50_mp,
               s55_health, s60_logs, s90_method)

SECTIONS = {
    "coverage": s10_coverage,
    "cluster": s12_cluster,
    "dp_compare": s15_dp_compare,
    "dp_load": s20_dp_load,
    "core_spikes": s25_core_spikes,
    "dp_resources": s22_dp_resources,
    "drops": s28_drops,
    "dp_breakdown": s30_dp_breakdown,
    "traffic": s40_traffic,
    "interfaces": s42_interfaces,
    "vpn": s46_vpn,
    "sessions": s45_sessions,
    "capacity": s48_capacity,
    "scale": s49_scale,
    "mp": s50_mp,
    "health": s55_health,
    "logs": s60_logs,
    "method": s90_method,
}

STANDARD = ["coverage", "dp_compare", "dp_load", "core_spikes", "dp_resources", "dp_breakdown", "traffic", "sessions", "mp",
            "health", "logs", "method"]
EXTENDED_ONLY = {"drops", "interfaces", "vpn", "capacity", "scale"}  # added by --extended
EXTENDED = ["coverage", "dp_compare", "dp_load", "core_spikes", "dp_resources", "drops", "dp_breakdown", "traffic", "interfaces",
            "vpn", "sessions", "capacity", "scale", "mp", "health", "logs", "method"]

# Separate document with every DP of a chassis (--all-dps): the comparison, then these sections once per DP
ALL_DPS = ["dp_load", "core_spikes", "dp_resources", "dp_breakdown"]

# Cluster report (TSFs of all nodes of an NGFW cluster): these sections form one part per node, for that node's
# busiest DP and its chassis; the others cover the whole cluster
CLUSTER_PART = ["dp_load", "core_spikes", "dp_resources", "dp_breakdown", "health"]

# Named section sets, selectable with --profile (--extended = profile 'extended')
PROFILES = {
    "standard": STANDARD,
    "extended": EXTENDED,
    "load": STANDARD,  # old name of 'standard'
    "dp": ["coverage", "dp_compare", "dp_load", "core_spikes", "dp_resources", "dp_breakdown", "traffic", "method"],
}
