"""Core spikes: single DP cores that run clearly above the other cores - when, how long, and what
changes in the traffic and the dataplane work while they do. Shown only when at least one core spikes.

Definition: a core spikes while its load is at least `spike_threshold` points above the median of
the other DP cores, for at least `spike_min_duration` (gaps of up to GAP_MIN minutes are bridged).
The comparison with the other cores - not an absolute load level - is what makes it a spike: a
busy firewall with all cores at 70% is evenly loaded, one core at 45% while the rest sit at 30% is not.
"""

import importlib.util

import numpy as np
import pandas as pd

from .. import charts as C
from .. import knowledge as K

TITLE = "Core spikes - single DP cores above the rest"

GAP_MIN = 5          # minutes below the threshold that do not end an episode
SIMILAR_LOAD = 10    # baseline intervals: median core load within +-this many points of the spike intervals
RATIO_HOT = 1.5      # "clearly more" for per-core comparisons since boot


# --- detection ----------------------------------------------------------------
def _runs(mask: pd.Series, gap: pd.Timedelta) -> list[tuple[pd.Timestamp, pd.Timestamp]]:
    """Start/end timestamps of True stretches; stretches closer than `gap` are merged."""
    idx = mask[mask].index
    if len(idx) == 0:
        return []
    out, s, e = [], idx[0], idx[0]
    for t in idx[1:]:
        if t - e <= gap:
            e = t
        else:
            out.append((s, e))
            s = e = t
    out.append((s, e))
    return out


def detect(ds, threshold: float, min_minutes: int) -> dict | None:
    cores = ds.meta.get("dp_cores") or []
    if len(cores) < 2:
        return None
    if ds.has("dpm_minute"):
        m = ds["dpm_minute"]
        w = m[m.core.isin(cores)].pivot_table(index="ts", columns="core", values="avg").sort_index()
        step, src = 60, "per-minute averages"
    elif ds.has("rm_cpu"):
        r = ds["rm_cpu"]
        w = r[(r.step_s == 3600) & r.core.isin(cores)].pivot_table(index="end", columns="core", values="avg").sort_index()
        step, src = 3600, "hourly averages (no per-minute data available)"
    else:
        return None
    w = w.dropna(how="all")
    if len(w) < 2 or w.shape[1] < 2:
        return None
    others = pd.DataFrame({c: w.drop(columns=c).median(axis=1) for c in w.columns})
    dev = w - others
    gap = pd.Timedelta(minutes=GAP_MIN) if step == 60 else pd.Timedelta(seconds=step)
    eps = []
    for c in w.columns:
        for s, e in _runs(dev[c] >= threshold, gap):
            minutes = (e - s).total_seconds() / 60 + step / 60
            if minutes < min_minutes:
                continue
            sl = slice(s, e)
            eps.append(dict(core=int(c), start=s - pd.Timedelta(seconds=step), end=e, minutes=minutes,
                            excess=dev[c][sl].mean(), peak=dev[c][sl].max(),
                            core_load=w[c][sl].mean(), others=others[c][sl].mean()))
    eps = pd.DataFrame(eps, columns=["core", "start", "end", "minutes", "excess", "peak", "core_load", "others"])
    hot = pd.Series(False, index=w.index)  # minutes in which at least one core spikes
    for _, e in eps.iterrows():
        hot[(hot.index > e.start) & (hot.index <= e.end)] = True
    return dict(w=w, dev=dev, eps=eps.sort_values("start").reset_index(drop=True), hot=hot, step=step, src=src,
                observed_min=len(w) * step / 60)


def _hours(idx: pd.DatetimeIndex) -> str:
    """Hours of the day that hold most spike minutes, compressed: '18-22h, 02h'."""
    if len(idx) == 0:
        return ""
    share = pd.Series(idx.hour).value_counts(normalize=True)
    hrs = sorted(h for h, v in share.items() if v >= 0.05)
    parts, i = [], 0
    while i < len(hrs):
        j = i
        while j + 1 < len(hrs) and hrs[j + 1] == hrs[j] + 1:
            j += 1
        parts.append(f"{hrs[i]:02d}h" if i == j else f"{hrs[i]:02d}-{hrs[j]:02d}h")
        i = j + 1
    return ", ".join(parts)


def _per_core(det) -> pd.DataFrame:
    eps, w = det["eps"], det["w"]
    rows = []
    for c, g in eps.groupby("core"):
        mins = g.minutes.sum()
        idx = w.index[np.any([(w.index > e.start) & (w.index <= e.end) for _, e in g.iterrows()], axis=0)]
        rows.append(dict(core=c, episodes=len(g), hours=mins / 60, share=mins / det["observed_min"] * 100,
                         excess=(g.excess * g.minutes).sum() / mins, peak=g.peak.max(), when=_hours(idx)))
    return pd.DataFrame(rows).sort_values("hours", ascending=False).reset_index(drop=True)


def _fmt_h(h: float) -> str:
    return f"{h * 60:.0f} min" if h < 1 else f"{h:.1f} h"


# --- what changes during the spikes ---------------------------------------------
def _split(det, ts: pd.Index):
    """Interval timestamps of a coarser series (counter rates, pow intervals) -> (spike, baseline) index
    lists. Baseline = intervals without any spike whose overall core load is similar to the spike intervals."""
    ts = pd.DatetimeIndex(sorted(set(ts)))
    if len(ts) < 3:
        return [], [], False
    step = pd.Series(ts).diff().median()
    hot, level = det["hot"], det["w"].median(axis=1)
    frac, lev = [], []
    for t in ts:
        sel = (hot.index > t - step) & (hot.index <= t)
        frac.append(hot[sel].mean() if sel.any() else np.nan)
        lev.append(level[sel].mean() if sel.any() else np.nan)
    frac, lev = pd.Series(frac, index=ts), pd.Series(lev, index=ts)
    spike = frac[frac >= 0.5].index
    calm = frac[frac == 0].index
    if len(spike) == 0 or len(calm) == 0:
        return list(spike), list(calm), False
    target = lev[spike].mean()
    similar = lev[calm][(lev[calm] - target).abs() <= SIMILAR_LOAD].index
    if len(similar) >= 3:
        return list(spike), list(similar), True
    return list(spike), list(calm), False


def _changes(ds, det) -> dict:
    out = {}
    if ds.has("dp_counter_rates"):
        r = ds["dp_counter_rates"].pivot_table(index="ts", columns="name", values="rate")
        spike, base, similar = _split(det, r.index)
        if spike and base:
            a, b = r.loc[spike].mean(), r.loc[base].mean()
            t = pd.DataFrame({"spike": a, "base": b}).fillna(0)
            t["diff"] = t.spike - t.base
            t["ratio"] = t.spike / t.base.replace(0, np.nan)
            t = t[(t.spike >= 50) & ((t.ratio >= 1.3) | t.ratio.isna())].sort_values("diff", ascending=False)
            out["counters"] = t
            out["similar"] = similar
            out["n"] = (len(spike), len(base))
    if ds.has("dp_pow_interval"):
        p = ds["dp_pow_interval"]
        p = p[~p.name.str.contains(K.NOT_CPU)]
        pv = p.pivot_table(index="ts", columns=["kind", "name"], values="pct")
        spike, base, _s = _split(det, pv.index)
        if spike and base:
            t = pd.DataFrame({"spike": pv.loc[spike].mean(), "base": pv.loc[base].mean()}).fillna(0)
            t["diff"] = t.spike - t.base
            out["pow"] = t[t["diff"] > 0.05].sort_values("diff", ascending=False)
    if ds.has("dpm_session"):
        s = ds["dpm_session"].set_index("ts")
        spike, base, _s = _split(det, s.index)
        if spike and base:
            prof = {}
            for lab, idx in (("spike", spike), ("base", base)):
                x = s.loc[idx]
                prof[lab] = dict(pps=x.pps.mean(), mbps=x.kbps.mean() / 1000 if "kbps" in x else np.nan,
                                 cps=x.cps.mean() if "cps" in x else np.nan,
                                 pkt=(x.kbps * 125 / x.pps.replace(0, np.nan)).mean() if "kbps" in x else np.nan)
            out["profile"] = prof
    return out


# --- per-core work since boot ------------------------------------------------------
def _per_core_boot(ds, flagged: list[int]) -> pd.DataFrame:
    if not ds.has("pow_core"):
        return pd.DataFrame()
    cores = ds.meta.get("dp_cores") or []
    pc = ds["pow_core"]
    pc = pc[pc.core.isin(cores) & ~pc.name.str.contains(K.NOT_CPU)]
    x = pc.pivot_table(index=["kind", "name"], columns="core", values="ac_total_us", aggfunc="sum").fillna(0) / 1e6
    rows = []
    for c in flagged:
        if c not in x.columns:
            continue
        oth = x.drop(columns=c).median(axis=1)
        total = x[c][x.index.get_level_values(0) == "group"].sum()
        for (kind, name), v in x[c].items():
            o = oth[(kind, name)]
            if v <= 0 or v < 0.005 * total:
                continue
            if o == 0 or v / o >= RATIO_HOT:
                desc = K.group_desc(name) if kind == "group" else K.FUNC_HELP.get(name, K.func_feature(name) or "")
                rows.append(dict(core=c, kind=kind, name=name, this=v, others=o, ratio=(v / o) if o else np.inf,
                                 extra=v - o, meaning=desc))
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    return df.sort_values(["core", "extra"], ascending=[True, False]).groupby("core").head(8).reset_index(drop=True)


def _rx_imbalance(ds, flagged) -> tuple[pd.DataFrame, dict]:
    if not ds.has("pow_status"):
        return pd.DataFrame(), {}
    ps = ds["pow_status"].dropna(subset=["io_rcv"])
    cores = ds.meta.get("dp_cores") or []
    ps = ps[ps.core.isin(cores)].copy()
    if len(ps) < 2:
        return pd.DataFrame(), {}
    ratios = {}
    for _, r in ps.iterrows():
        ratios[int(r.core)] = r.io_rcv / ps[ps.core != r.core].io_rcv.median()
    ps["vs_median"] = ps.core.map(ratios)
    return ps, {c: ratios[c] for c in flagged if c in ratios}


def _tunnels(ds) -> pd.DataFrame:
    if not ds.has("if_counters"):
        return pd.DataFrame()
    t = ds["if_counters"]
    t = t[t.interface.str.match(r"tunnel\.\d+$") & (t.rx_bytes > 0)].copy()
    if t.empty:
        return t
    t["share"] = t.rx_bytes / t.rx_bytes.sum() * 100
    t["pkt"] = t.rx_bytes / t.rx_pkts.replace(0, np.nan)
    return t.sort_values("rx_bytes", ascending=False).head(5)


def _sessions_in_spikes(ds, det) -> pd.DataFrame:
    """Live data with traffic logs: sessions active during the spike episodes, largest first."""
    if not ds.has("logs_traffic") or det["eps"].empty:
        return pd.DataFrame()
    lg = ds["logs_traffic"]
    need = {"start", "elapsed", "bytes", "src", "dst", "app"}
    if not need.issubset(lg.columns):
        return pd.DataFrame()
    st = pd.to_datetime(lg.start)
    el = pd.to_numeric(lg.elapsed, errors="coerce").fillna(0)
    en = st + pd.to_timedelta(el, unit="s")
    ov = pd.Series(0.0, index=lg.index)
    for _, e in det["eps"].iterrows():
        lo = st.where(st > e.start, e.start)
        hi = en.where(en < e.end, e.end)
        ov += (hi - lo).dt.total_seconds().clip(lower=0)
    sel = ov > 0
    if not sel.any():
        return pd.DataFrame()
    x = lg[sel].copy()
    x["bytes_in_spikes"] = pd.to_numeric(x.bytes, errors="coerce") * (ov[sel] / el[sel].clip(lower=1)).clip(upper=1)
    cols = [c for c in ("from", "to", "src", "dst", "dport", "app") if c in x.columns]
    return (x.groupby(cols, dropna=False).bytes_in_spikes.sum().sort_values(ascending=False).head(10).reset_index())


# --- report section ---------------------------------------------------------------
def build(ctx):
    ds = ctx.ds
    th = float(ctx.settings.get("spike_threshold", 10))
    min_min = int(ctx.settings.get("spike_min_minutes", 15))
    det = detect(ds, th, min_min)
    if det is None or det["eps"].empty:
        return []
    eps, w, dev = det["eps"], det["w"], det["dev"]
    pc = _per_core(det)
    flagged = [int(c) for c in pc.core]
    main = [int(c) for c in pc.core[pc.hours >= 0.25 * pc.hours.max()]]  # the cores that dominate
    span = f"{w.index.min():%d.%m. %H:%M} - {w.index.max():%d.%m. %H:%M}"

    short = pc[~pc.core.isin(main)]
    ctx.find("notice", "Core spikes",
             f"{'Cores' if len(main) > 1 else 'Core'} {' and '.join(map(str, main))} ran at least {th:g} points above "
             f"the other DP cores for {min_min} min or longer: "
             + "; ".join(f"<b>core {r.core}</b> {_fmt_h(r.hours)} in {r.episodes} episode{'s' if r.episodes > 1 else ''}"
                         f" (+{r.excess:.0f} points, mostly {r.when})" for r in pc[pc.core.isin(main)].itertuples())
             + (f". Shorter episodes on core{'s' if len(short) > 1 else ''} {', '.join(map(str, short.core))} "
                f"({_fmt_h(short.hours.sum())} in total)" if not short.empty else "")
             + f". Observed {span}; see '{TITLE}'.")

    out = [ctx.h1(TITLE), ctx.p(
        f"A core <b>spikes</b> while its load is at least <b>{th:g} points</b> above the median of the other DP "
        f"cores, for at least <b>{min_min} minutes</b> (dips shorter than {GAP_MIN} minutes don't end an episode). "
        "Comparing with the other cores, not with a fixed load level, separates real imbalance from a busy "
        "firewall: with all cores at 70% the load is high but even. "
        f"Data: {det['src']}, {span}. Thresholds: <i>spike_threshold</i> and <i>spike_min_duration</i> in the "
        "config file, or --spike-threshold / --spike-min-duration.")]

    # long-term context from the weekly averages
    if ds.has("rm_cpu"):
        r = ds["rm_cpu"]
        wk = r[(r.step_s == 604800) & r.core.isin(ds.meta.get("dp_cores") or [])].pivot_table(
            index="idx", columns="core", values="avg").dropna(how="all")
        if len(wk) >= 2:
            lt = {c: (wk[c] - wk.drop(columns=c).median(axis=1)).mean() for c in main if c in wk.columns}
            lt = {c: v for c, v in lt.items() if abs(v) >= 1}
            if lt:
                out.append(ctx.p(f"Over the last {len(wk)} weeks the weekly averages show the same pattern: "
                                 + ", ".join(f"core {c} {v:+.1f} points" for c, v in lt.items())
                                 + " compared with the median of the other cores."))

    out.append(ctx.h2("Which cores, how long, when"))
    out.append(ctx.table(
        pc.rename(columns={"hours": "time", "share": "% of time", "excess": "avg excess", "peak": "max excess",
                           "when": "mostly at"}),
        [1.2, 1.8, 1.8, 1.8, 2.0, 2.0, 6.8],
        fmt={"time": _fmt_h, "% of time": lambda v: f"{v:.1f}%", "avg excess": lambda v: f"+{v:.1f}",
             "max excess": lambda v: f"+{v:.0f}"}))

    # chart: excess over time
    cmap = C.colors_for([f"core {c}" for c in main])
    f, ax = C.fig(C.W, 2.6)
    smooth = dev.rolling(5, min_periods=1).mean() if det["step"] == 60 else dev
    for c in dev.columns:
        if int(c) not in main:
            ax.plot(smooth.index, smooth[c], color=C.OTHER, linewidth=0.6, alpha=0.7)
    for c in main:
        ax.plot(smooth.index, smooth[c], color=cmap[f"core {c}"], linewidth=1.0, label=f"core {c}")
    ax.axhline(th, color=C.INK2, linestyle="--", linewidth=0.8)
    ax.text(1.0, th, f"threshold {th:g} ", transform=ax.get_yaxis_transform(), ha="right", va="bottom",
            fontsize=C.VALUE_FS, color=C.INK2)
    ax.axhline(0, color=C.GRID, linewidth=0.8)
    C.time_axis(ax, (w.index.max() - w.index.min()).total_seconds() / 86400)
    ax.set_ylabel("points above other cores")
    ax.set_title("Load of each core minus the median of the other cores" +
                 (" (5-minute mean)" if det["step"] == 60 else ""))
    C.legend_below(ax, min(len(main), 6))
    out.append(ctx.figure(f, "spike_excess", "Gray: the other cores" + (
        f", including {', '.join(map(str, short.core))} with shorter episodes." if not short.empty else ".")))

    # chart: hour-of-day heatmap
    if det["step"] == 60 and (w.index.max() - w.index.min()) >= pd.Timedelta(hours=12):
        hm = dev.groupby(dev.index.hour).mean().reindex(range(24)).T.clip(lower=0)
        f, ax = C.fig(C.W, 0.22 * len(hm) + 1.0)
        im = ax.imshow(hm.values, aspect="auto", cmap=C.mcolors.LinearSegmentedColormap.from_list("seq", ["#ffffff"] + C.SEQ),
                       vmin=0, vmax=max(th * 1.5, float(np.nanmax(hm.values))))
        ax.set_yticks(range(len(hm)))
        ax.set_yticklabels([f"core {c}" for c in hm.index])
        ax.set_xticks(range(0, 24, 2))
        ax.set_xticklabels([f"{h:02d}" for h in range(0, 24, 2)])
        ax.set_xlabel("hour of day")
        ax.grid(False)
        cb = f.colorbar(im, ax=ax, fraction=0.03, pad=0.01)
        cb.set_label("avg points above other cores")
        cb.outline.set_visible(False)
        ax.set_title("Average excess by hour of day")
        out.append(ctx.figure(f, "spike_hours"))

    out.append(ctx.h2("Episodes"))
    show = eps.sort_values(["start", "core"])
    out.append(ctx.p(f"{len(eps)} episode{'s' if len(eps) > 1 else ''}"
                     + (" - the 25 longest are listed." if len(eps) > 25 else ".")))
    if len(show) > 25:
        show = show.nlargest(25, "minutes").sort_values(["start", "core"])
    out.append(ctx.table(
        show.rename(columns={"minutes": "duration", "excess": "avg excess", "peak": "max excess",
                             "core_load": "core load", "others": "other cores"}),
        [1.2, 3.0, 3.0, 2.0, 2.0, 2.0, 2.0, 2.2],
        fmt={"start": lambda v: f"{v:%Y-%m-%d %H:%M}", "end": lambda v: f"{v:%Y-%m-%d %H:%M}",
             "duration": lambda v: _fmt_h(v / 60), "avg excess": lambda v: f"+{v:.1f}",
             "max excess": lambda v: f"+{v:.0f}", "core load": lambda v: f"{v:.0f}%",
             "other cores": lambda v: f"{v:.0f}%"}, max_rows=25))

    # --- what changes -------------------------------------------------------------
    ch = _changes(ds, det)
    findings = []  # interpretation bullets
    if ch.get("counters") is not None or ch.get("pow") is not None or ch.get("profile"):
        out.append(ctx.h2("What changes during the spikes"))
        n_s, n_b = ch.get("n", (0, 0))
        out.append(ctx.p(
            "Average rates in intervals with a spike compared with intervals without one"
            + (" at a similar overall core load" if ch.get("similar") else
               " (no interval without spikes had a similar overall load, so all calm intervals are used - "
               "differences partly reflect the general load level)")
            + (f" ({n_s} vs {n_b} intervals)." if n_s else ".")))
        prof = ch.get("profile")
        if prof:
            rows = [("packets/s", "pps", "{:,.0f}"), ("throughput Mbit/s", "mbps", "{:,.0f}"),
                    ("new sessions/s", "cps", "{:,.0f}"), ("avg packet size (bytes)", "pkt", "{:,.0f}")]
            tab = pd.DataFrame([(lab, fmt.format(prof["spike"][k]), fmt.format(prof["base"][k]))
                                for lab, k, fmt in rows if np.isfinite(prof["spike"][k]) and np.isfinite(prof["base"][k])],
                               columns=["traffic", "during spikes", "without spikes"])
            out.append(ctx.table(tab, [5.0, 3.5, 3.5]))
            ps, pb = prof["spike"]["pkt"], prof["base"]["pkt"]
            if np.isfinite(ps) and np.isfinite(pb) and pb > 0 and ps >= 1.5 * pb:
                findings.append(f"Average packet size rises from {pb:,.0f} to {ps:,.0f} bytes during the spikes. "
                                "Large packets at moderate packet rates are typical of bulk transfers "
                                "(backup, replication, large file transfers).")
        t = ch.get("counters")
        if t is not None and not t.empty:
            tt = t.head(10).reset_index().rename(columns={"name": "counter"})
            tt["meaning"] = tt.counter.map(K.counter_desc)
            out.append(ctx.small("Global counters that rise the most (per second):"))
            out.append(ctx.table(tt[["counter", "base", "spike", "ratio", "meaning"]].rename(
                columns={"base": "without", "spike": "during"}), [5.2, 2.0, 2.0, 1.4, 6.6],
                fmt={"without": lambda v: f"{v:,.0f}", "during": lambda v: f"{v:,.0f}",
                     "ratio": lambda v: "new" if not np.isfinite(v) else f"{v:.1f}x"}))
            esp = t.loc["flow_tunnel_ipsec_esp_decap"] if "flow_tunnel_ipsec_esp_decap" in t.index else None
            if esp is not None and (not np.isfinite(esp.ratio) or esp.ratio >= 2):
                findings.append(f"IPsec decryption rises from {esp.base:,.0f} to {esp.spike:,.0f} ESP packets/s "
                                "during the spikes.")
        t = ch.get("pow")
        if t is not None and not t.empty:
            tt = t.head(8).reset_index()
            tt["meaning"] = [K.group_desc(n) if k == "group" else K.FUNC_HELP.get(n, K.func_feature(n) or "")
                             for k, n in zip(tt.kind, tt.name)]
            out.append(ctx.small("Dataplane work that grows the most (% of total DP capacity):"))
            out.append(ctx.table(tt[["kind", "name", "base", "spike", "meaning"]].rename(
                columns={"base": "without", "spike": "during"}), [1.4, 4.2, 2.0, 2.0, 7.6],
                fmt={"without": lambda v: f"{v:.2f}%", "during": lambda v: f"{v:.2f}%"}))

    # --- per core since boot --------------------------------------------------------
    rx, rx_flag = _rx_imbalance(ds, flagged)
    boot = _per_core_boot(ds, main)
    if not rx.empty or not boot.empty:
        out.append(ctx.h2("Work per core since boot"))
        out.append(ctx.p("Totals since the last boot, per core. They cover more than the spike episodes, so they show "
                         "lasting differences: what a core does clearly more of (at least "
                         f"{RATIO_HOT:g}x the median of the other cores), or what only it does."))
    if not rx.empty:
        rr = rx.copy()
        rr["flag"] = np.where(rr.core.isin(flagged), "spikes", "")
        out.append(ctx.small("Packets taken from the port receive queues (debug dataplane pow status, io rcv num):"))
        out.append(ctx.table(rr[["core", "io_rcv", "vs_median", "flag"]].rename(
            columns={"io_rcv": "packets received", "vs_median": "vs median of other cores", "flag": ""}),
            [1.2, 4.0, 4.0, 2.0],
            fmt={"packets received": lambda v: C.human(v), "vs median of other cores": lambda v: f"{v:.2f}x"}))
        for c, ratio in rx_flag.items():
            if ratio >= RATIO_HOT:
                findings.insert(0, (
                    f"Core {c} takes {ratio:.1f}x as many packets from the port receive queues as the median core. "
                    "The network ports spread incoming packets over the cores by a hash of the packet headers; "
                    "traffic whose headers are all alike - one IPsec tunnel (all ESP between the same two peers), "
                    "GRE, or one very large flow - always lands on the same core. That core then also does the "
                    "receive and decryption work for it."))
    if not boot.empty:
        out.append(ctx.small("Work groups and functions a spiking core does clearly more of:"))
        out.append(ctx.table(boot[["core", "kind", "name", "this", "others", "ratio", "meaning"]].rename(
            columns={"this": "this core (s)", "others": "median others (s)"}),
            [1.0, 1.3, 3.6, 2.2, 2.4, 1.4, 5.1],
            fmt={"this core (s)": lambda v: f"{v:,.0f}", "median others (s)": lambda v: f"{v:,.0f}",
                 "ratio": lambda v: "only here" if not np.isfinite(v) else f"{v:.1f}x"}))
        for c, g in boot.groupby("core"):
            np_row = g[(g.kind == "group") & (g.name == "flow_np")]
            if not np_row.empty and c not in rx_flag:
                findings.append(f"Core {c} spends {np_row.ratio.iloc[0]:.1f}x the median time on packet receive "
                                "(flow_np): it receives more traffic from the ports than the other cores.")
            only = g[~np.isfinite(g.ratio) & (g.kind == "group")].name.tolist()
            if only:
                findings.append(f"Core {c} is the only core running {', '.join(only)} "
                                f"({'; '.join(K.group_desc(n) for n in only)}). This work is usually small "
                                "and constant; it adds a fixed share but doesn't explain spikes by itself.")
            tun = g[g.name.str.startswith("tunnel_")]
            if not tun.empty:
                findings.append(f"Core {c} does more IPsec work than the other cores since boot "
                                f"({', '.join(f'{n} {r:.1f}x' if np.isfinite(r) else n for n, r in zip(tun.name, tun.ratio))}).")

    # --- tunnels ----------------------------------------------------------------------
    tun = _tunnels(ds)
    ipsec_hint = any("IPsec" in x for x in findings)
    if ipsec_hint and not tun.empty:
        out.append(ctx.small("Busiest tunnel interfaces since boot (received):"))
        cols = ["interface"] + [c for c in ("ipsec_tunnel", "peer") if c in tun.columns and tun[c].notna().any()]
        tt = tun[cols + ["rx_bytes", "share", "tx_bytes", "pkt"]].rename(
            columns={"ipsec_tunnel": "IPsec tunnel", "rx_bytes": "received", "share": "% of tunnel rx",
                     "tx_bytes": "sent", "pkt": "avg pkt"})
        widths = {"interface": 2.0, "IPsec tunnel": 3.6, "peer": 2.8, "received": 1.9, "% of tunnel rx": 2.0,
                  "sent": 1.9, "avg pkt": 1.6}
        out.append(ctx.table(tt, [widths[c] for c in tt.columns],
                             fmt={"received": lambda v: C.human(v) + "B", "sent": lambda v: C.human(v) + "B",
                                  "% of tunnel rx": lambda v: f"{v:.0f}%", "avg pkt": lambda v: f"{v:,.0f} B"}))
        top = tun.iloc[0]
        name = f" ({top.ipsec_tunnel})" if "ipsec_tunnel" in tun.columns and isinstance(top.get("ipsec_tunnel"), str) else ""
        findings.append(f"The busiest tunnel is {top.interface}{name} with {top.share:.0f}% of all tunnel traffic "
                        f"received since boot. Its encrypted packets all arrive on one core.")

    # --- sessions (live with traffic logs) ------------------------------------------
    ss = _sessions_in_spikes(ds, det)
    if not ss.empty:
        out.append(ctx.h2("Largest sessions during the spikes"))
        out.append(ctx.p("From the exported traffic logs: sessions that were active during a spike episode, with "
                         "their bytes scaled to the time inside the episodes. A session is processed by one core at "
                         "a time, so a few very large sessions are a common cause of one hot core."))
        out.append(ctx.table(ss.rename(columns={"bytes_in_spikes": "bytes (in spikes)"}),
                             fmt={"bytes (in spikes)": lambda v: C.human(v) + "B"}))

    # --- interpretation ---------------------------------------------------------------
    out.append(ctx.h2("Interpretation"))
    others_short = [c for c in flagged if c not in main]
    if others_short:
        findings.append(f"Cores {', '.join(map(str, others_short))} have only short episodes"
                        f"{' at the same times as the main ones' if _overlaps(eps, main, others_short) else ''}. "
                        "A single large session can move between cores now and then, which looks like this.")
    if not findings:
        findings.append("No single cause stands out in the counters. A session is processed by one core at a time, "
                        "so one or a few very large sessions are the usual reason for one hot core.")
    if ds.source != "live":
        live = importlib.util.find_spec("pan_ngfw_load.collect") is not None
        findings.append(
            "To name the sessions behind the spikes, check the traffic logs for the episode times, or run "
            "'show session all filter ...' while a spike is happening (the tech support file holds no per-session "
            "history). <b>pan-ngfw-load can also run as a long-term collector</b>: set up with 'pan-ngfw-load init' "
            "and cron, it samples the firewall every few minutes over the read-only XML API and exports the traffic "
            "logs. Its reports then have per-minute detail for weeks (a tech support file holds about two days), and they list "
            "the largest sessions during each spike"
            + ("." if live else " (this installation is TSF-only - run install.sh without --tsf-only to add the "
                                "collector)."))
    elif not ds.has("logs_traffic"):
        findings.append("To name the sessions behind the spikes, export the traffic logs as well ('pan-ngfw-load logs', "
                        "hourly from cron by default; log_types = traffic). The next report then lists the largest "
                        "sessions during each spike.")
    for x in findings:
        out.append(ctx.p("&bull; " + x))
    return out


def _overlaps(eps, main, short) -> bool:
    a = eps[eps.core.isin(main)]
    for _, e in eps[eps.core.isin(short)].iterrows():
        if ((a.start < e.end) & (a.end > e.start)).any():
            return True
    return False
