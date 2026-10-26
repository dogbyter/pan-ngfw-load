"""What consumes dataplane CPU? pow-performance breakdown by stage, group, feature, function, core and time."""

import pandas as pd

from .. import charts as C
from .. import knowledge as K

TITLE = "What consumes dataplane CPU"

STAGE_COLORS = C.colors_for(K.STAGE_ORDER)
FEATURE_ORDER = [f for f, _ in K.FEATURES] + ["Other"]
FEATURE_COLORS = C.colors_for(FEATURE_ORDER[:7] + ["Other"])


def _feat_color(f):
    return FEATURE_COLORS.get(f, C.OTHER)


def build(ctx):
    ds = ctx.ds
    if not ds.has("pow_boot"):
        return []
    out = [ctx.h1(TITLE), ctx.p(
        "PAN-OS keeps a profile of how much CPU time the DP workers spend in each processing "
        "<b>group</b> (a type of scheduled work, roughly a pipeline stage) and in selected code paths called "
        "<b>functions</b> (<i>debug dataplane pow performance</i>). The two views are measured separately. "
        "Functions can also run outside every group: the timer check <i>tim_check</i> alone uses more time than "
        "all groups together. So each view is compared only within itself. Functions that measure waiting "
        "time (latency) are left out. Mapping functions to features (App-ID, threat inspection, ...) is "
        "inferred from their names.")]

    pb = ds["pow_boot"]
    g = pb[pb.kind == "group"].copy()
    fn = pb[(pb.kind == "func") & (pb.feature != "(latency, not CPU)")].copy()
    ncores = ds.meta.get("dp_core_count") or 1
    boot, now = ds.meta.get("boot_time"), ds.meta.get("tsf_time")
    total_us = g.ac_total_us.sum()
    if boot and now:
        cap_us = (now - boot).total_seconds() * ncores * 1e6
        out.append(ctx.p(
            f"Since boot the DP workers spent <b>{total_us / 1e6:,.0f} s</b> of CPU time in tracked work groups. "
            f"That is <b>{total_us / cap_us * 100:.2f}%</b> of the capacity of {ncores} cores over "
            f"{(now - boot).total_seconds() / 86400:.1f} days."))

    out.append(ctx.h2("Since boot - by stage and group"))
    by_stage = g.groupby("stage").ac_total_us.sum()
    by_stage = (by_stage / total_us * 100).reindex([s for s in K.STAGE_ORDER if s in by_stage.index])
    by_stage = by_stage[by_stage > 0].sort_values(ascending=False)
    f, (a1, a2) = C.plt.subplots(1, 2, figsize=(C.W, 2.9), dpi=150, gridspec_kw={"width_ratios": [1, 1.1]})
    C.hbar(a1, by_stage, unit="%")
    a1.set_title("Share by stage")
    grp = (g.set_index("name").ac_total_us / total_us * 100)
    grp = C.top_n(grp[grp > 0], 9)
    C.hbar(a2, grp, color=C.CAT[0], unit="%")
    a2.set_title("Share by group")
    out.append(ctx.figure(f, "pow_stage_group", "Share of tracked DP CPU time since boot."))

    gt = g[g.ac_total_us > 0].sort_values("ac_total_us", ascending=False)
    gt = pd.DataFrame({
        "group": gt.name, "stage": gt.stage, "meaning": gt.name.map(K.group_desc),
        "share": gt.ac_total_us / total_us * 100, "calls": gt.ac_count, "avg us": gt.ac_avg_us, "max us": gt.ac_max_us})
    out.append(ctx.table(gt, [2.6, 2.8, 6.0, 1.3, 1.9, 1.2, 1.3],
                         fmt={"share": lambda v: f"{v:.1f}%", "calls": lambda v: f"{v:,.0f}",
                              "avg us": lambda v: f"{v:.1f}", "max us": lambda v: f"{v:,.0f}"}))

    out.append(ctx.h2("Since boot - by feature and function"))
    ftot = fn.ac_total_us.sum()
    feat = (fn.groupby("feature").ac_total_us.sum() / ftot * 100)
    feat = feat[feat > 0].sort_values(ascending=False)
    topf = (fn.set_index("name").ac_total_us / ftot * 100).sort_values(ascending=False).head(12)
    f, (a1, a2) = C.plt.subplots(1, 2, figsize=(C.W, 3.2), dpi=150)
    C.hbar(a1, feat, unit="%")
    a1.set_title("Share by feature")
    C.hbar(a2, topf, color=C.CAT[1], unit="%")
    a2.set_title("Top functions")
    out.append(ctx.figure(f, "pow_feature_func", "Share of tracked function CPU time since boot (latency counters excluded)."))
    rows = [(k, f"{v:.1f}%", K.FEATURE_HELP.get(k, "")) for k, v in feat.items()]
    out.append(ctx.table(pd.DataFrame(rows, columns=["feature", "share", "what it is"]), [4.2, 1.4, 11.5]))

    # --- per core ------------------------------------------------------------
    if ds.has("pow_core"):
        cores = ds.meta.get("dp_cores") or []
        pc = ds["pow_core"]
        pc = pc[(pc.kind == "group") & pc.core.isin(cores)]
        wide = pc.pivot_table(index="core", columns="stage", values="ac_total_us", aggfunc="sum").fillna(0) / 1e6
        wide = wide[[s for s in K.STAGE_ORDER if s in wide.columns and wide[s].sum() > 0]]
        f, ax = C.fig(C.W, 2.4)
        left = pd.Series(0.0, index=wide.index)
        for s in wide.columns:
            ax.barh([f"core {c}" for c in wide.index], wide[s], left=left, color=STAGE_COLORS[s],
                    edgecolor=C.SURFACE, linewidth=1, height=0.6, label=s)
            left += wide[s]
        ax.invert_yaxis()
        ax.grid(axis="y", visible=False)
        ax.set_title("Work per DP core, by stage (CPU seconds since boot)")
        C.legend_below(ax, 4, y=-0.12)
        out.append(ctx.figure(f, "pow_per_core"))
        tot = left
        if len(tot) > 1 and tot.min() > 0:
            ratio = tot.max() / tot.min()
            top_core = tot.idxmax()
            dom = wide.loc[top_core].idxmax()
            if ratio > 1.5:
                ctx.find("notice", "DP breakdown",
                         f"DP work is unevenly spread across cores: core {top_core} did {ratio:.1f}x the work of the "
                         f"least busy core, mostly '{dom}'. Control and housekeeping work is usually pinned to one "
                         "core, so this is expected at low traffic.")

    # --- over time (dp-monitor) ----------------------------------------------
    if ds.has("dp_pow_interval"):
        pi = ds["dp_pow_interval"]
        span = ((pi.ts.max() - pi.ts.min()).total_seconds() + pi.interval_s.median()) / 86400  # incl. first interval
        out.append(ctx.h2(f"Over time - last {span:.1f} days (10-minute intervals)"))
        out.append(ctx.p("The y-axis is the share of total DP capacity (all worker cores) used in each interval. "
                         "Unlike the resource-monitor max values, these are exact interval averages."))
        gs = pi[pi.kind == "group"].pivot_table(index="ts", columns="stage", values="pct", aggfunc="sum").fillna(0)
        gs = gs[[s for s in K.STAGE_ORDER if s in gs.columns and gs[s].sum() > 0]]
        f, ax = C.fig(C.W, 2.8)
        C.stacked_area(ax, gs, STAGE_COLORS)
        C.time_axis(ax, span)
        ax.set_ylabel("% of DP capacity")
        ax.set_title("DP CPU by stage over time")
        C.legend_below(ax, 4)
        out.append(ctx.figure(f, "pow_stage_time"))

        fs = pi[(pi.kind == "func") & (pi.feature != "(latency, not CPU)")]
        fw = fs.pivot_table(index="ts", columns="feature", values="pct", aggfunc="sum").fillna(0)
        keep = list(fw.sum().sort_values(ascending=False).index[:7])
        fw2 = fw[keep].copy()
        rest = [c for c in fw.columns if c not in keep]
        if rest:
            fw2["Other"] = fw[rest].sum(axis=1)
        cmap = C.colors_for(list(fw2.columns))
        f, ax = C.fig(C.W, 2.8)
        C.stacked_area(ax, fw2, cmap)
        C.time_axis(ax, span)
        ax.set_ylabel("% of DP capacity")
        ax.set_title("Function CPU by feature over time")
        C.legend_below(ax, 3)
        out.append(ctx.figure(f, "pow_feature_time"))

        # busiest intervals
        tot = gs.sum(axis=1).sort_values(ascending=False).head(8)
        rows = []
        for ts, v in tot.items():
            gi = pi[(pi.ts == ts) & (pi.kind == "group")].sort_values("pct", ascending=False)
            fi = fs[fs.ts == ts].groupby("feature").pct.sum().sort_values(ascending=False)
            rows.append((ts, v, f"{gi.iloc[0]['name']} ({gi.iloc[0].pct:.2f})", f"{fi.index[0]} ({fi.iloc[0]:.2f})" if len(fi) else "-"))
        out.append(ctx.h2("Busiest 10-minute intervals"))
        out.append(ctx.table(pd.DataFrame(rows, columns=["interval end", "DP %", "top group (%)", "top feature (%)"]),
                             [3.2, 1.6, 5.5, 6.5], fmt={"DP %": lambda v: f"{v:.2f}"}))
        base = gs.sum(axis=1).median()
        period = f"{span:.1f} days" if span >= 2 else f"{span * 24:.1f} hours" if span >= 1 / 24 else f"{span * 1440:.0f} minutes"
        ctx.find("info", "DP breakdown",
                 f"Last {period}: the profiled DP work averaged {gs.sum(axis=1).mean():.2f}% of DP capacity "
                 f"(median {base:.2f}%, busiest interval {tot.iloc[0]:.2f}% at {tot.index[0]:%d.%m. %H:%M}).")

    top_stage = by_stage.index[0]
    traffic_feats = feat.drop([x for x in ("Timers & ageing", "Internal messaging (mi_*)") if x in feat.index])
    ctx.find("info", "DP breakdown",
             f"Since boot, the largest DP stage is '{top_stage}' ({by_stage.iloc[0]:.0f}% of DP time). The largest "
             f"traffic-driven feature is '{traffic_feats.index[0]}' ({traffic_feats.iloc[0]:.0f}% of function time), "
             f"followed by '{traffic_feats.index[1]}' ({traffic_feats.iloc[1]:.0f}%).")
    return out
