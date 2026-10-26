"""Report sections, in report order.

A section is a module with
    TITLE: str
    build(ctx) -> list[flowable]   (return [] if its data is missing or it has nothing to show)
It may call ctx.find(level, section, text) to add a line to the summary page.
To add a focus area: create sNN_<name>.py and add it to SECTIONS (and optionally to a profile).
"""

from . import (s10_coverage, s20_dp_load, s22_dp_resources, s25_core_spikes, s28_drops, s30_dp_breakdown,
               s40_traffic, s42_interfaces, s45_sessions, s46_vpn, s48_capacity, s50_mp, s55_health, s60_logs,
               s90_method)

SECTIONS = {
    "coverage": s10_coverage,
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
    "mp": s50_mp,
    "health": s55_health,
    "logs": s60_logs,
    "method": s90_method,
}

STANDARD = ["coverage", "dp_load", "core_spikes", "dp_resources", "dp_breakdown", "traffic", "sessions", "mp",
            "health", "logs", "method"]
EXTENDED_ONLY = {"drops", "interfaces", "vpn", "capacity"}  # added by --extended
EXTENDED = ["coverage", "dp_load", "core_spikes", "dp_resources", "drops", "dp_breakdown", "traffic", "interfaces",
            "vpn", "sessions", "capacity", "mp", "health", "logs", "method"]

# Named section sets, selectable with --profile (--extended = profile 'extended')
PROFILES = {
    "standard": STANDARD,
    "extended": EXTENDED,
    "load": STANDARD,  # old name of 'standard'
    "dp": ["coverage", "dp_load", "core_spikes", "dp_resources", "dp_breakdown", "traffic", "method"],
}
