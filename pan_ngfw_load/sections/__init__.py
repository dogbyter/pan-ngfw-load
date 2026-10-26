"""Report sections, in report order.

A section is a module with
    TITLE: str
    build(ctx) -> list[flowable]   (return [] if its data is missing or it has nothing to show)
It may call ctx.find(level, section, text) to add a line to the summary page.
To add a focus area: create sNN_<name>.py and add it to SECTIONS (and optionally to a profile).
"""

from . import s10_coverage, s20_dp_load, s25_core_spikes, s30_dp_breakdown, s40_traffic, s50_mp, s60_logs, s90_method

SECTIONS = {
    "coverage": s10_coverage,
    "dp_load": s20_dp_load,
    "core_spikes": s25_core_spikes,
    "dp_breakdown": s30_dp_breakdown,
    "traffic": s40_traffic,
    "mp": s50_mp,
    "logs": s60_logs,
    "method": s90_method,
}

# Named section sets, selectable with --profile
PROFILES = {
    "load": ["coverage", "dp_load", "core_spikes", "dp_breakdown", "traffic", "mp", "logs", "method"],
    "dp": ["coverage", "dp_load", "core_spikes", "dp_breakdown", "traffic", "method"],
}
