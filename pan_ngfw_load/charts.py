"""Shared chart style (matplotlib, print/light) and a few reusable chart builders.

Colors: validated reference palette (dataviz skill), categorical slots used in
fixed order and never cycled; more than 8 series fold into 'Other' (gray).
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.colors as mcolors  # noqa: E402
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#e4e3df"
OTHER = "#b5b4ae"
CAT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"]
SEQ = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID, "axes.labelcolor": INK2, "axes.titlecolor": INK,
    "axes.titlesize": 8, "axes.titleweight": "bold", "axes.titlelocation": "left", "axes.titlepad": 5,
    "axes.labelsize": 7, "xtick.color": INK2, "ytick.color": INK2, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "axes.spines.top": False, "axes.spines.right": False,
    "legend.fontsize": 6.5, "legend.frameon": False, "font.size": 7, "lines.linewidth": 1.3,
    "font.family": "DejaVu Sans",
})


def colors_for(keys: list[str], fixed: dict[str, str] | None = None) -> dict[str, str]:
    """Stable entity->color mapping: fixed overrides, then slots in order, rest gray."""
    out, i = {}, 0
    for k in keys:
        if fixed and k in fixed:
            out[k] = fixed[k]
        elif k == "Other":
            out[k] = OTHER
        elif i < len(CAT):
            out[k] = CAT[i]
            i += 1
        else:
            out[k] = OTHER
    return out


# Figures are drawn at the width they are printed at (17 cm), so the font sizes above are the real
# point sizes in the PDF - nothing gets scaled up or down.
W = 6.7
VALUE_FS = 6  # direct value labels next to bars / points


# More series than CAT has colours (e.g. DP cores): the colours start again, and each new round gets a second
# visual feature so no two series look the same - line style for lines, hatching for bars. Grey stays reserved
# for 'Other'. Three rounds = 24 distinguishable series.
LINESTYLES = ["-", (0, (4, 1.6)), (0, (1, 1.4))]
HATCHES = [None, "////", "...."]
ROUND_NAMES = ["solid", "dashed / hatched", "dotted / dotted hatching"]


def series_styles(keys: list) -> dict:
    """key -> {color, ls, hatch, round} in rounds of len(CAT)."""
    out = {}
    for i, k in enumerate(keys):
        r = (i // len(CAT)) % len(LINESTYLES)
        out[k] = {"color": CAT[i % len(CAT)], "ls": LINESTYLES[r], "hatch": HATCHES[r], "round": r}
    return out


# Many series (e.g. 40 DP cores): draw the field instead of every series - the median of all, the range from the
# lowest to the highest as a band, and only the few series that differ most from the field in colour.
FIELD_MAX_HIGHLIGHT = 4
FIELD_MIN_DEV = 2.0  # mean distance from the median (in the chart's unit) a series needs to be highlighted


def notable(wide: pd.DataFrame, n: int = FIELD_MAX_HIGHLIGHT, min_dev: float = FIELD_MIN_DEV) -> list:
    """Columns of `wide` (index = x, columns = series) furthest from the median of all columns, most notable first."""
    med = wide.median(axis=1)
    dev = wide.sub(med, axis=0).abs().mean()
    dev = dev[dev >= min_dev].sort_values(ascending=False)
    return list(dev.index[:n])


def field_plot(ax, wide: pd.DataFrame, highlight: list, cmap: dict, what: str = "core", marker: str | None = None,
               lw: float = 1.1) -> None:
    """Median line + min-max band of all columns, plus the given columns in colour (same keys and colours in
    every chart of a section - pick them once with notable())."""
    x = wide.index
    ax.fill_between(x, wide.min(axis=1), wide.max(axis=1), color=OTHER, alpha=0.35, lw=0,
                    label=f"range of all {wide.shape[1]} {what}s")
    ax.plot(x, wide.median(axis=1), color=INK2, lw=lw + 0.4, marker=marker, markersize=2.5,
            label=f"median of all {what}s")
    for c in highlight:
        if c in wide.columns:
            ax.plot(x, wide[c], color=cmap[c], lw=lw, marker=marker, markersize=2.5, label=f"{what} {c}")


def fig(w=W, h=3.0):
    return plt.subplots(figsize=(w, h), dpi=150)


def time_axis(ax, span_days: float):
    lo, hi = ax.dataLim.intervalx
    if np.isfinite(lo) and np.isfinite(hi) and hi - lo < 1 / 288:  # single point / tiny range: matplotlib would pad +-2 years
        mid = (lo + hi) / 2
        ax.set_xlim(mid - 1 / 24, mid + 1 / 24)
        span_days = 2 / 24
    if span_days > 10:
        ax.xaxis.set_major_locator(mdates.DayLocator(interval=max(1, int(round(span_days / 7)))))
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%d.%m."))
    elif span_days > 5:
        ax.xaxis.set_major_locator(mdates.DayLocator())
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%d.%m."))
    elif span_days > 1.5:
        # midnight ticks show the date, noon ticks only the time - short labels that never collide
        ax.xaxis.set_major_locator(mdates.HourLocator(byhour=[0, 12]))
        ax.xaxis.set_major_formatter(plt.FuncFormatter(
            lambda v, _p: mdates.num2date(v).strftime("%d.%m." if mdates.num2date(v).hour == 0 else "%H:%M")))
    else:
        if span_days < 0.25:
            ax.xaxis.set_major_locator(mdates.MinuteLocator(byminute=range(0, 60, 15)))
        else:
            ax.xaxis.set_major_locator(mdates.HourLocator(interval=max(1, int(span_days * 24 // 8))))
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.tick_params(axis="x", rotation=0)


def top_n(series: pd.Series, n: int = 7) -> pd.Series:
    """Keep the n largest, fold the rest into 'Other'."""
    s = series.sort_values(ascending=False)
    if len(s) <= n + 1:
        return s
    head = s.iloc[:n]
    return pd.concat([head, pd.Series({"Other": s.iloc[n:].sum()})])


def hbar(ax, s: pd.Series, color=CAT[0], fmt="{:.1f}", unit="", labeler=None):
    """Horizontal bars, largest on top. The category name sits above its bar and the value at the bar end,
    so long names never eat into the plot width or run into a neighbouring panel; no x axis needed."""
    s = s[::-1]
    n = len(s)
    cols = [OTHER if k == "Other" else color for k in s.index]
    ax.barh(range(n), s.values, color=cols, height=0.42, edgecolor=SURFACE, linewidth=0.5)
    vmax = float(np.nanmax(s.values)) if n else 1
    vmax = vmax if vmax > 0 else 1
    for i, (k, v) in enumerate(s.items()):
        ax.text(0, i + 0.26, str(k), va="bottom", ha="left", fontsize=6.3, color=INK, clip_on=False)
        lab = labeler(v) if labeler else fmt.format(v) + unit
        ax.text(v + vmax * 0.015, i, lab, va="center", ha="left", fontsize=VALUE_FS, color=INK2, clip_on=False)
    ax.set_xlim(0, vmax * 1.22)
    ax.set_ylim(-0.5, n - 0.1)
    ax.set_yticks([])
    ax.set_xticks([])
    ax.grid(False)
    ax.spines["bottom"].set_visible(False)


def stacked_area(ax, wide: pd.DataFrame, cmap: dict[str, str]):
    cols = list(wide.columns)
    ax.stackplot(wide.index, *[wide[c].fillna(0).values for c in cols],
                 labels=cols, colors=[cmap[c] for c in cols], linewidth=0)


def legend_below(ax, ncol=4, y=-0.16, handlelength=1.2):
    """Legend under the plot. More than 8 entries wrap into balanced rows that read left to right
    (matplotlib fills legends column by column, so the entries are reordered and padded)."""
    handles, labels = ax.get_legend_handles_labels()
    n = len(handles)
    if n > 8:
        rows = -(-n // 8)
        ncol = -(-n // rows)
        blank = plt.Line2D([], [], alpha=0)
        grid = [[(handles[r * ncol + c], labels[r * ncol + c]) if r * ncol + c < n else (blank, "")
                 for c in range(ncol)] for r in range(rows)]
        pairs = [grid[r][c] for c in range(ncol) for r in range(rows)]
        handles, labels = [h for h, _l in pairs], [l for _h, l in pairs]
    ax.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, y), ncol=min(ncol, 8),
              handlelength=handlelength, columnspacing=1.2)


def human_bytes(v: float) -> str:
    """5204941e9 -> '5.2 PB' (decimal units, like interface speeds)."""
    for div, suf in ((1e15, "PB"), (1e12, "TB"), (1e9, "GB"), (1e6, "MB"), (1e3, "kB")):
        if abs(v) >= div:
            return f"{v / div:.1f} {suf}"
    return f"{v:.0f} B"


def human(v: float) -> str:
    """12345 -> '12.3 k', 6232404 -> '6.2 M'."""
    for div, suf in ((1e12, " T"), (1e9, " G"), (1e6, " M"), (1e3, " k")):
        if abs(v) >= div:
            return f"{v / div:.1f}{suf}"
    return f"{v:.0f}"
