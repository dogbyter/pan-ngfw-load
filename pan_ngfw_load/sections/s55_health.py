"""Stability and health: uptime, crashes, processes, high availability, hardware sensors, disks, storage health
and lost logs.
Each check ends in one line of the summary when something needs attention."""

import pandas as pd

from .. import knowledge as K

TITLE = "Health and stability"

DISK_NOTICE, DISK_WARN = 80, 90  # % used
INODE_NOTICE, INODE_WARN = 80, 90  # % of the file system's inodes (files) used
WEAR_NOTICE, WEAR_WARN = 80, 90  # SSD 'Percentage Used' (share of the rated write endurance)
CLUSTER_BAD = {"DEGRADED", "FAILED", "SUSPENDED"}  # NGFW cluster node states that need attention


def build(ctx):
    ds = ctx.ds
    keys = ("crashes", "software", "ha", "cluster", "chassis", "environment", "disk", "smart", "fsck",
            "counters_boot")
    if not any(ds.has(k) for k in keys) and ds.meta.get("boot_time") is None:
        return []
    out = [ctx.h1(TITLE), ctx.p(
        "Checks that are not about load but explain odd load figures or point to trouble: restarts and crashes, "
        "processes that are not running, the high-availability pair or cluster, hardware sensors, disk space, the "
        "health of the SSD and its file systems, and logs that never reached the log database.")]
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

    # --- NGFW cluster (PA-7500: two chassis instead of an HA pair) ---------------------------------
    if ds.has("cluster"):
        cl = ds["cluster"]
        st = cl.state.str.upper()
        me = cl[cl.this]
        role = lambda r: f"node {r.node} {r.state.upper()}" + (" (leader)" if r.leader == "yes" else "")
        txt = ("this chassis " + (role(me.iloc[0]) if not me.empty else "?") + "; "
               + "; ".join(role(r) for r in cl[~cl.this].itertuples()))
        problems, lvl = [], "ok"
        if st.isin(CLUSTER_BAD).any():
            lvl = "warning"
            problems += [f"node {r.node} {r.state.upper()}" for r in cl[st.isin(CLUSTER_BAD)].itertuples()]
        elif (st != "ONLINE").any():
            lvl = "notice"
            problems += [f"node {r.node} {r.state.upper()}" for r in cl[st != "ONLINE"].itertuples()]
        hsci = ds["if_hw"][ds["if_hw"].interface.str.startswith("hsci")] if ds.has("if_hw") else pd.DataFrame()
        down = [r.interface for r in hsci.itertuples() if r.state != "up"]
        if len(down) == len(hsci) and len(hsci):
            lvl, problems = "warning", problems + ["both HSCI links down"]
        elif down:
            lvl = "warning" if lvl == "warning" else "notice"
            problems.append(f"{', '.join(down)} down (no backup link left)")
        if len(hsci):
            txt += "; HSCI " + ", ".join(f"{r.interface[-1].upper()} {r.state}" for r in hsci.itertuples())
        cap = ds.meta.get("cluster") or {}
        if cap and ds.has("chassis"):
            ch = ds["chassis"]
            up = lambda kind: int(((ch["card status"] == "Up") & ch.card.str.contains(f"-{kind}-")).sum())
            npc, dpc = up("NPC"), up("DPC")
            txt += (f"; cards up: {npc} network (minimum {cap.get('min_npc', '?')}), {dpc} data processing "
                    f"(minimum {cap.get('min_dpc', '?')}), below the minimum: {cap.get('on_loss', '?')}")
            at_min = [k for k, n, mn in (("network", npc, cap.get("min_npc")), ("data processing", dpc, cap.get("min_dpc")))
                      if mn is not None and n <= mn]
            if at_min:
                lvl = "warning" if lvl == "warning" else "notice"
                # without any working data processing card a node is FAILED, whatever 'State upon capacity loss' says
                state = "FAILED (no data processing card left)" if dpc <= 1 and "data processing" in at_min else \
                    str(cap.get("on_loss", "?")).upper()
                problems.append(f"{' and '.join(at_min)} cards at the configured minimum - one more failed card puts "
                                f"this node in {state}")
        checks.append(("NGFW cluster", txt, lvl))
        if problems:
            ctx.find(lvl, "Health", "Cluster: " + "; ".join(problems) + ".")
        else:
            ctx.find("info", "Health", f"NGFW cluster of {len(cl)} chassis: all nodes ONLINE"
                                       + (", both HSCI links up" if len(hsci) == 2 else "") + ".")
        out.append(ctx.h2("NGFW cluster"))
        out.append(ctx.p(
            "This firewall is a node of an <b>NGFW cluster</b>: two PA-7500 chassis that act as one firewall. The "
            "control planes run active/passive - the <b>leader</b> node runs the management and presents the "
            "interfaces of both chassis (named <i>node1:</i>/<i>node2:</i>), the other node works like a line card "
            "of it - while the dataplanes of both nodes process traffic at the same time. "
            + ("<b>This TSF is from the leader.</b> " if not me.empty and me.leader.iloc[0] == "yes" else
               "<b>This TSF is from the non-leader node</b> - for management, configuration and logs, the TSF of "
               "the leader is the reference. " if not me.empty else "") +
            " The nodes are connected back to back by the <b>HSCI-A</b> and <b>HSCI-B</b> links "
            "(active/backup); aggregate groups with members on both nodes (<b>MC-LAG</b>) look like one link to the "
            "switch. Node states: ONLINE is normal, INIT while starting, DEGRADED (some traffic ports down, still "
            "processes traffic), FAILED (out of the cluster) and SUSPENDED (manual, or after flapping). "
            "<b>A tech support file covers one node:</b> the dataplanes, sessions and counters in this report are "
            "those of this chassis - take a TSF of the other node for its share of the load. Serial numbers and "
            "addresses of the nodes are left out."))
        out.append(ctx.table(cl.assign(this=cl.this.map({True: "this chassis", False: ""}), state=st),
                             [2.0, 3.0, 3.0, 2.0]))

    # --- chassis cards (PA-7000/7500) ---------------------------------------------------------
    if ds.has("chassis"):
        ch = ds["chassis"]
        down = ch[ch["card status"] != "Up"]
        unconf = ch[(ch["card status"] == "Up") & (ch["config status"] != "Success")]
        lvl = "warning" if not down.empty else "notice" if not unconf.empty else "ok"
        checks.append(("Chassis cards", f"{len(ch)} cards, " + (", ".join(f"slot {r.slot} {r._3}" for r in down.itertuples())
                                                              if not down.empty else "all up")
                       + (f"; config not applied on slot(s) {', '.join(map(str, unconf.slot))}" if not unconf.empty else ""),
                       lvl))
        if not down.empty:
            ctx.find("warning", "Health", "Chassis cards not up: " + ", ".join(
                f"slot {r.slot} {r.card} {r._3}" for r in down.itertuples()) + " - DP data of these cards is incomplete.")
        elif not unconf.empty:
            ctx.find("notice", "Health", "Configuration not applied on slot(s) " + ", ".join(map(str, unconf.slot)) + ".")
        out.append(ctx.h2("Chassis cards"))
        out.append(ctx.table(ch, [1.2, 3.4, 2.4, 2.4, 1.8, 1.6]))

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
            checks.append(("Disk space", f"fullest: {full.mount} {full.use_pct:.0f}% "
                                         f"({full['used']} of {full['size']})", lvl))
            if lvl != "ok":
                ctx.find(lvl, "Health", f"Disk {full.mount} is {full.use_pct:.0f}% full.")
            out.append(ctx.h2("Disk space"))
            out.append(ctx.small("/opt/panlogs holds logs and reports, /opt/panrepo software and content images, "
                                 "/opt/pancfg configuration and state. Old software images in /opt/panrepo can be "
                                 "deleted to free space."))
            out.append(ctx.table(dk.drop(columns=["filesystem"]).rename(columns={"use_pct": "used %"}),
                                 [5.0, 2.0, 2.0, 2.0, 2.0], fmt={"used %": lambda v: f"{v:.0f}%"}))

    # --- storage health ------------------------------------------------------------------------
    out += _storage(ctx, checks)

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


def _n(v):
    return None if v is None or pd.isna(v) else v


def _storage(ctx, checks) -> list:
    """SSD SMART data, file-system checks at boot and storage errors in the kernel log."""
    ds, out = ctx.ds, []
    sm = ds["smart"] if ds.has("smart") else None
    fs = ds["fsck"] if ds.has("fsck") else None
    ke = ds.t.get("storage_errors") if ds.meta.get("kernel_log") else None
    if sm is None and fs is None and ke is None:
        return out
    out.append(ctx.h2("Storage health"))

    if sm is not None:
        rows = {}
        for r in sm.itertuples():
            name = "SSD" if len(sm) == 1 else f"SSD {r.disk}"
            health, cw, spare, smin = _n(r.health), _n(r.critical_warning), _n(r.spare), _n(r.spare_min)
            wear, temp, twarn, tcrit = _n(r.wear), _n(r.temp), _n(r.temp_warn), _n(r.temp_crit)
            media, unsafe, cycles = _n(r.media_errors), _n(r.unsafe_shutdowns), _n(r.power_cycles)
            bad, lvl = [], "ok"
            if health and health.upper() not in ("PASSED", "OK"):
                bad.append(f"SMART self-assessment {health}")
            if cw:
                bad.append(f"critical warning 0x{int(cw):02x}")
            if spare is not None and smin is not None and spare < smin:
                bad.append(f"spare blocks {spare:.0f}% below the threshold of {smin:.0f}%")
            if media:
                bad.append(f"{media:,.0f} media and data-integrity errors")
            if wear is not None and wear >= WEAR_WARN or tcrit is not None and temp is not None and temp >= tcrit:
                bad.append(f"wear {wear:.0f}%" if wear is not None and wear >= WEAR_WARN else f"temperature {temp:.0f} °C")
            if bad:
                lvl = "warning"
                ctx.find("warning", "Health", f"{name}: " + ", ".join(bad) + " - plan to replace the SSD (RMA).")
            elif wear is not None and wear >= WEAR_NOTICE or twarn is not None and temp is not None and temp >= twarn:
                lvl = "notice"
                txt = (f"{wear:.0f}% of its rated write endurance used" if wear is not None and wear >= WEAR_NOTICE
                       else f"temperature {temp:.0f} °C above the warning limit of {twarn:.0f} °C")
                ctx.find("notice", "Health", f"{name}: {txt}.")
            res = bad or [health or "?"] + ([f"wear {wear:.0f}%"] if wear is not None else []) + (
                [f"{media:,.0f} media errors"] if media is not None else [])
            checks.append(("SSD health" if len(sm) == 1 else f"SSD health {r.disk}", ", ".join(res), lvl))
            unsafe_txt = "-" if unsafe is None else f"{unsafe:,.0f}" + (
                f" of {cycles:,.0f} power cycles" if cycles else "")
            rows[name] = {
                "Model": r.model or "?",
                "SMART self-assessment": health or "?",
                "Wear (rated endurance used)": "-" if wear is None else f"{wear:.0f}%",
                "Available spare (threshold)": "-" if spare is None else f"{spare:.0f}%" + (
                    f" ({smin:.0f}%)" if smin is not None else ""),
                "Media and data-integrity errors": "-" if media is None else f"{media:,.0f}",
                "Temperature (warning / critical)": "-" if temp is None else f"{temp:.0f} °C" + (
                    f" ({twarn:.0f} / {tcrit:.0f} °C)" if twarn is not None and tcrit is not None else ""),
                "Power-on hours": "-" if _n(r.power_on_hours) is None else f"{r.power_on_hours:,.0f} "
                                                                           f"({r.power_on_hours / 8766:.1f} years)",
                "Unsafe shutdowns": unsafe_txt,
            }
        out.append(ctx.small("SMART data the SSD keeps about itself (debug system disk-smart-info). Wear is the share "
                             "of the write endurance the vendor rates the SSD for; media errors are data the SSD could "
                             "not read back. An unsafe shutdown is a power loss or hard reset without a clean shutdown."))
        tab = pd.DataFrame(rows)
        tab.insert(0, "", tab.index)
        out.append(ctx.table(tab, [6.0] + [11.0 / len(rows)] * len(rows)))

    if fs is not None:
        last = fs.groupby("filesystem", sort=False).tail(1)
        worst = None
        for r in last.itertuples():
            when = "?" if pd.isna(r.time) else f"{r.time:%Y-%m-%d}"
            if r.exit >= 4:
                worst = ("warning", f"the check of {r.filesystem} at the boot on {when} found errors it could not "
                                    f"repair (fsck exit code {r.exit}) - open a support case")
            elif r.fixes and not r.harmless and (worst is None or worst[0] != "warning"):
                worst = ("notice", f"the check of {r.filesystem} at the boot on {when} repaired errors: {r.fixes}")
        if worst:
            ctx.find(worst[0], "Health", f"File system: {worst[1]}.")
        lp = fs[fs.filesystem == "panlogs"]
        jr = int(lp.journal.sum())
        txt = (worst[1] if worst else "no errors at the last boot") + (
            f"; panlogs journal recovered at {jr} of {len(lp)} boots" if len(lp) > 1 and jr else "")
        checks.append(("File-system check", txt, worst[0] if worst else "ok"))
        ino = fs[fs.files_total.notna() & (fs.files_total > 0)].groupby("filesystem", sort=False).tail(1)
        if not ino.empty:
            ino = ino.assign(pct=100 * ino.files_used / ino.files_total).sort_values("pct", ascending=False)
            top = ino.iloc[0]
            lvl = "warning" if top.pct >= INODE_WARN else "notice" if top.pct >= INODE_NOTICE else "ok"
            checks.append(("Inodes", f"most used: {top.filesystem} {top.pct:.0f}% of {top.files_total:,.0f}", lvl))
            if lvl != "ok":
                ctx.find(lvl, "Health", f"File system {top.filesystem} has {top.pct:.0f}% of its inodes (files) in "
                                        "use - when they run out, no new files can be written although space is left.")

        def result(r):
            if r.exit >= 4:
                return f"<font color='#d03b3b'><b>errors left (exit {r.exit})</b></font>"
            if r.fixes:
                return "repaired: summary counters" if r.harmless else f"<b>repaired:</b> {r.fixes}"
            return "clean"
        tab = pd.DataFrame({
            "boot": ["last boot" if pd.isna(t) else f"{t:%Y-%m-%d %H:%M}" for t in fs.time],
            "file system": fs.filesystem,
            "unclean before": ["yes" if j else "-" for j in fs.journal],
            "full check": ["yes" if f else "-" for f in fs.forced],
            "result": [result(r) for r in fs.itertuples()],
            "files used": ["-" if pd.isna(u) or not t else f"{100 * u / t:.0f}%"
                           for u, t in zip(fs.files_used, fs.files_total)],
        }).tail(15)
        out.append(ctx.small(
            "File-system checks (fsck) at boot, from var/log/pan/panlogs-partition.log (panlogs, several boots) and "
            "the kernel log (the other file systems, last boot only). 'Unclean before': the journal had to be "
            "replayed, so the file system was not unmounted cleanly - usually a power loss or hard reset. 'Repaired: summary "
            "counters' is the usual tidy-up after that and changes no data. 'Files used' is the share of the inodes."))
        out.append(ctx.table(tab, [3.2, 2.4, 2.6, 2.2, 4.6, 2.0]))

    if ke is not None:
        if ke.empty:
            checks.append(("Storage errors", "no disk or file-system errors in the kernel log", "ok"))
        else:
            n = int(ke["count"].sum())
            checks.append(("Storage errors", f"{n:,} disk or file-system error messages in the kernel log", "warning"))
            ctx.find("warning", "Health", f"{n:,} disk or file-system error messages in the kernel log (e.g. "
                                          f"'{ke.iloc[0].message[:90]}') - check the SSD and open a support case.")
            out.append(ctx.small("Disk and file-system errors in var/log/dmesg and var/log/messages (I/O errors, "
                                 "file-system errors, file systems switched to read-only)."))
            ke = ke.assign(last=ke["last"].replace("", "this boot")).rename(columns={"last": "last seen"})
            out.append(ctx.table(ke.sort_values("count", ascending=False), [11.5, 2.0, 3.5],
                                 fmt={"count": lambda v: f"{v:,.0f}"}))
    return out
