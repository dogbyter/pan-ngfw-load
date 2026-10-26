"""Data coverage: which time frame can each source answer?"""

import pandas as pd

from .. import charts as C

TITLE = "Data coverage - how far back can we look?"


def _dur(days: float) -> str:
    return f"{days:.0f} days" if days >= 2 else f"{days * 24:.1f} hours"


def build(ctx):
    ds = ctx.ds
    cov = ds["coverage"]
    if cov.empty:
        return []
    out = [ctx.h1(TITLE)]
    series = cov[~cov.resolution.str.contains("total") & ~cov.source.str.startswith("sar") & ~cov.source.str.contains("logs")]
    longest = series.sort_values("days").iloc[-1] if not series.empty else cov.sort_values("days").iloc[-1]
    boot = ds.meta.get("boot_time")
    out.append(ctx.p(
        "A tech support file holds several data sources, and each covers a different period. "
        "Dataplane (DP) statistics are reset when the device reboots, so no DP load history goes back "
        f"further than the last boot ({boot:%Y-%m-%d %H:%M})." if boot else
        "A tech support file holds several data sources, and each covers a different period."))

    f, ax = C.fig(C.W, 0.32 * len(cov) + 0.9)
    cov = cov.iloc[::-1].reset_index(drop=True)
    for i, r in cov.iterrows():
        start, end = pd.Timestamp(r.start), pd.Timestamp(r.end)
        width = max((end - start).total_seconds() / 86400, 0.05)
        col = C.CAT[0] if "total since boot" not in r.resolution else C.SEQ[2]
        ax.barh(i, width, left=start, height=0.55, color=col, edgecolor=C.SURFACE)
        ax.text(end, i, f"  {r.days:.1f} d" if r.days >= 0.1 else f"  {r.days * 1440:.0f} min",
                va="center", fontsize=C.VALUE_FS, color=C.INK2)
    ax.set_yticks(range(len(cov)))
    ax.set_yticklabels([f"{s} - {c}" if len(c) < 38 else f"{s} - {c[:36]}..." for s, c in zip(cov.source, cov.content)])
    ax.grid(axis="y", visible=False)
    span = (pd.Timestamp(cov.end.max()) - pd.Timestamp(cov.start.min())).days + 1
    C.time_axis(ax, span)
    ax.set_xlim(pd.Timestamp(cov.start.min()) - pd.Timedelta(days=0.5), pd.Timestamp(cov.end.max()) + pd.Timedelta(days=3))
    ax.set_title("Time span of each data source")
    out.append(ctx.figure(f, "coverage", "Dark blue = time series. Light blue = values accumulated since boot "
                                          "(one total, no time detail)."))

    show = cov.iloc[::-1][["source", "content", "start", "end", "resolution", "days"]]
    out.append(ctx.table(show, [3.4, 5.4, 2.6, 2.6, 2.0, 1.2], fmt={"days": lambda v: f"{v:.1f}"}))

    ctx.find("info", "Coverage",
             f"Longest DP time series: {_dur(longest.days)} ({longest.source}: {longest.content}). DP totals "
             f"accumulated since boot cover {_dur(cov[cov.resolution.str.contains('total')].days.max())}. "
             + (f"Detailed DP samples cover {_dur(cov[cov.source.str.startswith(('dp-monitor', 'collector'))].days.max())}."
                if cov.source.str.startswith(("dp-monitor", "collector")).any() else ""))
    return out
