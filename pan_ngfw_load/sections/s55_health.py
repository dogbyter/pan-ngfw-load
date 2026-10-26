"""Stability and health: uptime, crashes, processes, high availability, hardware sensors, disks and lost logs.
Each check ends in one line of the summary when something needs attention."""

import pandas as pd

from .. import knowledge as K

TITLE = "Health and stability"

DISK_NOTICE, DISK_WARN = 80, 90  # % used


def build(ctx):
    ds = ctx.ds
    keys = ("crashes", "software", "ha", "environment", "disk", "counters_boot")
    if not any(ds.has(k) for k in keys) and ds.meta.get("boot_time") is None:
        return []
    out = [ctx.h1(TITLE), ctx.p(
        "Checks that are not about load but explain odd load figures or point to trouble: restarts and crashes, "
        "processes that are not running, the high-availability pair, hardware sensors, disk space and logs that "
        "never reached the log database.")]
    checks = []  # (check, result, status) for the overview table

    # --- uptime ------------------------------------------------------------------------
    boot, now = ds.meta.get("boot_time"), ds.meta.get("tsf_time")
    if boot is not None and now is not None:
        days = (now - boot).total_seconds() / 86400
        checks.append(("Last boot", f"{boot:%Y-%m-%d %H:%M} ({days:.0f} days before the data was taken)", "info"))

    # --- crashes -------------------------------------------------------------------------
    if ds.bundle is not None:
        cr = ds["crashes"] if ds.has("crashes") else pd.DataFrame(columns=["process", "time", "version"])
        if cr.empty:
            checks.append(("Crashes", "no crash reports in the tech support file", "ok"))
        else:
            after = cr[cr.time.notna() & (cr.time >= boot)] if boot is not None else cr.iloc[0:0]
            txt = f"{len(cr)} crash report{'s' if len(cr) > 1 else ''}" + (
                f", {len(after)} since the last boot" if boot is not None else "")
            lvl = "warning" if len(after) else "notice"
            checks.append(("Crashes", txt, lvl))
            out.append(ctx.h2("Crash reports"))
            out.append(ctx.small("From opt/panlogs/cores/crashinfo: a process that crashed and was restarted by "
                                 "PAN-OS. Crashes of dataplane processes interrupt traffic."))
            out.append(ctx.table(cr.sort_values("time"), [4.0, 4.0, 3.0],
                                 fmt={"time": lambda v: "?" if pd.isna(v) else f"{v:%Y-%m-%d %H:%M}"}))
            ctx.find(lvl, "Health", f"{txt}: " + ", ".join(
                f"{r.process} ({'?' if pd.isna(r.time) else f'{r.time:%Y-%m-%d}'}, {r.version or '?'})"
                for r in cr.sort_values("time").tail(5).itertuples()) + ".")

    # --- processes -----------------------------------------------------------------------
    if ds.has("software"):
        sw = ds["software"]
        bad = sw[sw.state != "running"]
        if bad.empty:
            checks.append(("Processes", f"all {len(sw)} groups and processes running", "ok"))
        else:
            names = ", ".join(f"{r.name} ({r.state})" for r in bad.itertuples())
            checks.append(("Processes", f"{len(bad)} not running: {names}", "warning"))
            ctx.find("warning", "Health", f"Not running: {names}.")

    # --- high availability --------------------------------------------------------------
    if ds.has("ha"):
        ha = dict(zip(ds["ha"].key, ds["ha"].value))
        if ha.get("enabled") == "no":
            checks.append(("High availability", "not enabled (standalone)", "info"))
        else:
            loc, peer = ha.get("local state", "?"), ha.get("peer state", "?")
            sync = ha.get("running configuration", "?")
            ss = ha.get("state synchronization", "?")
            links_down = [k for k, v in ha.items() if k.endswith(" link") and v.lower() != "up"]
            problems = []
            if sync != "synchronized":
                problems.append(f"configuration {sync}")
            if not ss.lower().startswith("complete"):
                problems.append(f"session sync {ss}")
            if links_down:
                problems.append("link down: " + ", ".join(links_down))
            if not any(w in peer for w in ("passive", "active")):
                problems.append(f"peer {peer}")
            lvl = "warning" if problems else "ok"
            checks.append(("High availability", f"{ha.get('mode', '?')}: this firewall {loc}, peer {peer}; "
                                                 f"config {sync}, session sync {ss.split(';')[0].lower()}", lvl))
            if problems:
                ctx.find("warning", "Health", "HA: " + "; ".join(problems) + ".")
            else:
                ctx.find("info", "Health", f"HA {ha.get('mode', '')}: this firewall {loc.split(' (')[0]}, peer "
                                           f"{peer.split(' (')[0]}, configuration synchronized.")
            out.append(ctx.h2("High availability"))
            out.append(ctx.table(ds["ha"][ds["ha"].key != "enabled"], [5.0, 9.0]))

    # --- hardware sensors -------------------------------------------------------------------
    if ds.has("environment"):
        env = ds["environment"]
        alarms = env[env.alarm]
        if alarms.empty:
            checks.append(("Hardware sensors", f"no alarm on {len(env)} sensors ("
                           + ", ".join(f"{k} {v}" for k, v in env.kind.value_counts().items()) + ")", "ok"))
        else:
            checks.append(("Hardware sensors", f"{len(alarms)} alarm(s): " + ", ".join(alarms.description), "warning"))
            ctx.find("warning", "Health", "Hardware alarm: " + ", ".join(
                f"{r.description} {r.value:g} (limit {r.min:g}-{r.max:g})" for r in alarms.itertuples()) + ".")
        th = env[env.kind == "thermal"]
        if not th.empty:
            th = th.assign(headroom=th["max"] - th.value)
            hot = th.sort_values("headroom").iloc[0]
            checks.append(("Temperature", f"warmest relative to its limit: {hot.description} {hot.value:.0f} °C "
                                          f"(limit {hot['max']:.0f} °C)", "ok" if hot.headroom > 10 else "notice"))

    # --- disks -------------------------------------------------------------------------------
    if ds.has("disk"):
        dk = ds["disk"]
        dk = dk[~dk.mount.str.contains("ssl/private")]
        full = dk.sort_values("use_pct", ascending=False).iloc[0] if not dk.empty else None
        if full is not None:
            lvl = "warning" if full.use_pct >= DISK_WARN else "notice" if full.use_pct >= DISK_NOTICE else "ok"
            checks.append(("Disk space", f"fullest: {full.mount} {full.use_pct:.0f}% ({full.used} of {full.size})", lvl))
            if lvl != "ok":
                ctx.find(lvl, "Health", f"Disk {full.mount} is {full.use_pct:.0f}% full.")
            out.append(ctx.h2("Disk space"))
            out.append(ctx.small("/opt/panlogs holds logs and reports, /opt/panrepo software and content images, "
                                 "/opt/pancfg configuration and state. Old software images in /opt/panrepo can be "
                                 "deleted to free space."))
            out.append(ctx.table(dk.drop(columns=["filesystem"]), [5.0, 2.0, 2.0, 2.0, 2.0],
                                 fmt={"use_pct": lambda v: f"{v:.0f}%"}))

    # --- lost logs -----------------------------------------------------------------------------
    if ds.has("counters_boot"):
        c = ds["counters_boot"]
        lost = c[c.name.str.match(K.LOG_LOSS_COUNTERS) & (c.value > 0)]
        if lost.empty:
            checks.append(("Lost logs", "no log-loss counter above zero since boot", "ok"))
        else:
            tot = lost[lost.name.str.endswith("_cnt")].value.sum() or lost.value.max()
            checks.append(("Lost logs", f"{tot:,.0f} logs lost since boot", "notice"))
            out.append(ctx.h2("Lost logs"))
            out.append(ctx.p(
                "Logs are generated in the dataplane and sent to the management plane, which writes them to the log "
                "database (and forwards them). When that chain can't keep up - a busy MP, a slow disk, log bursts - "
                "logs are dropped. Traffic still flows, but reports, the ACC and log forwarding miss those sessions."))
            cols = ["name", "value", "description"] if "description" in lost.columns else ["name", "value"]
            out.append(ctx.table(lost[cols], [5.5, 2.5, 9.0][:len(cols)], fmt={"value": lambda v: f"{v:,.0f}"}))
            ctx.find("notice", "Health", f"{tot:,.0f} logs were lost since boot ("
                     + ", ".join(f"{n} {v:,.0f}" for n, v in zip(lost.name, lost.value)) + ").")

    if not checks:
        return []
    mark = {"ok": "OK", "info": "-", "notice": "<font color='#eda100'><b>check</b></font>",
            "warning": "<font color='#d03b3b'><b>problem</b></font>"}
    tab = pd.DataFrame([(c, r, mark.get(s, s)) for c, r, s in checks], columns=["check", "result", "status"])
    out.insert(2, ctx.h2("Overview"))
    out.insert(3, ctx.table(tab, [3.4, 11.6, 2.0]))
    if ds.source == "live":
        out.insert(4, ctx.small("Live data covers only some of these checks; a tech support file has all of them."))
    return out
