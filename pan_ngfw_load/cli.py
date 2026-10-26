"""pan-ngfw-load - PAN-OS load analysis: offline (tech support files) and live (read-only XML API).

A TSF-only installation (install.sh --tsf-only) has no collect/ package and wizard; then only
the 'tsf' command is offered.

Commands
  init      guided setup: paths, device, admin role/admin, API key, TLS pinning, permission test, cron
  status    configuration, keys, last sample/log export per device
  test      check what the device keys may do (expected: show/logs yes, config no)
  info      device facts and how far back logs reach
  sample    take one sample now
  tick      for cron (every minute): sample each device whose interval has elapsed
  logs      export logs (incremental by default, or --since/--until)
  report    build the report for the last N days into report_dir
  tsf       analyse a tech support file (.tgz or extracted directory)
  prune     delete samples/logs/reports older than the retention settings
  cron      print (or --install / --remove) the crontab block
"""

from __future__ import annotations

import argparse
import fcntl
import html
import importlib.util
import json
import logging
import logging.handlers
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import warnings
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

from . import __version__
from . import config as C

log = logging.getLogger("pan-ngfw-load")
_stop = False


# --- infrastructure ------------------------------------------------------
def setup_logging(cfg: C.Config, verbose: bool) -> None:
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    fh = logging.handlers.RotatingFileHandler(cfg.data_dir / "pan-ngfw-load.log", maxBytes=5_000_000, backupCount=3)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
    log.addHandler(fh)
    if sys.stderr.isatty() or verbose:
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("[pan-ngfw-load] %(message)s"))
        log.addHandler(sh)


@contextmanager
def lock(cfg: C.Config, name: str):
    """Non-blocking per-device lock, so overlapping cron runs skip instead of piling up."""
    d = cfg.data_dir / ".locks"
    d.mkdir(parents=True, exist_ok=True)
    fh = open(d / f"{name}.lock", "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.close()
        yield False
        return
    try:
        yield True
    finally:
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


def _on_signal(_s, _f):
    global _stop
    _stop = True
    log.info("stop requested - finishing current step")


def bin_path() -> Path:
    """Path of the installed launcher for cron lines: the one that started us (set by bin/pan-ngfw-load),
    else the one in PATH, else the launcher next to this package."""
    launcher = os.environ.get("PAN_NGFW_LOAD_LAUNCHER")
    if launcher and Path(launcher).exists():
        return Path(launcher).resolve()
    exe = shutil.which("pan-ngfw-load")
    if exe:
        return Path(exe).resolve()
    return Path(__file__).resolve().parent.parent / "bin" / "pan-ngfw-load"


# --- commands --------------------------------------------------------------
def cmd_status(cfg, args) -> int:
    print(f"config       {cfg.path} {'(exists)' if cfg.path.exists() else '(MISSING - run pan-ngfw-load init)'}")
    print(f"data_dir     {cfg.data_dir}")
    print(f"report_dir   {cfg.report_dir}")
    print(f"secrets_dir  {cfg.secrets_dir}")
    print(f"retention    samples {cfg.retain_samples / 86400:.0f}d, logs {cfg.retain_logs / 86400:.0f}d, "
          f"reports {cfg.retain_reports / 86400:.0f}d")
    from .collect.core import load_state
    for dev in cfg.devices.values():
        st = load_state(cfg.data_dir / "devices" / dev.name)
        print(f"\ndevice {dev.name}  host {dev.host}  interval {dev.sample_interval / 60:g} min")
        print(f"  key        {dev.key_file} {'ok' if dev.key_file.exists() else 'MISSING'}")
        if dev.diag_key_file:
            print(f"  diag key   {dev.diag_key_file} {'ok' if dev.diag_key_file.exists() else 'MISSING'}")
        print(f"  pinned TLS {'ok' if dev.fingerprint_file.exists() else 'MISSING'}")
        print(f"  last sample      {st.get('last_sample', '-')}")
        for lt, t in st.get("last_log_time", {}).items():
            print(f"  last {lt + ' log':11s} {t}")
        print(f"  last report      {st.get('last_report', '-')}")
    if not cfg.devices:
        print("\nno devices configured - run 'pan-ngfw-load init'")
    return 0


def cmd_test(cfg, args) -> int:
    from .collect.core import permission_test
    rc = 0
    for dev in cfg.device(args.device):
        print(f"device {dev.name} ({dev.host})")
        for key, check, expected, outcome in permission_test(dev):
            ok = (expected is None) or (expected and outcome == "allowed") or (expected is False and outcome == "denied")
            want = ("info only" if expected is None else "should be allowed" if expected else "should be DENIED")
            mark = "OK  " if ok else "FAIL"
            rc |= 0 if ok else 1
            print(f"  {mark} [{key}] {check:28s} {outcome:8s} ({want})")
    return rc


def cmd_info(cfg, args) -> int:
    from .collect.core import apis, device_info, log_range
    for dev in cfg.device(args.device):
        api, _ = apis(dev)
        info = device_info(cfg, dev, api)
        print(f"device {dev.name}")
        for k, v in info.items():
            print(f"  {k:15s} {v}")
        for lt in ("traffic", "threat"):
            o, n = log_range(api, lt)
            print(f"  {lt + ' logs':15s} oldest {o or '-'}  newest {n or '-'}")
    return 0


def _sample(cfg, dev) -> bool:
    from .collect.core import apis, take_sample
    with lock(cfg, dev.name) as got:
        if not got:
            log.info("%s: previous run still active - skipped", dev.name)
            return False
        api, diag = apis(dev)
        d, errors = take_sample(cfg, dev, api, diag)
        pow_ok = diag is not None and not any(e.startswith("pow_performance") for e in errors)
        log.info("%s: sample %s%s%s", dev.name, d.name, " (+pow)" if pow_ok else "",
                 f" with {len(errors)} error(s)" if errors else "")
        return not errors


def cmd_sample(cfg, args) -> int:
    rc = 0
    for dev in cfg.device(args.device):
        try:
            _sample(cfg, dev)
        except Exception as e:
            log.error("%s: sample failed: %s", dev.name, e)
            rc = 1
    return rc


def cmd_tick(cfg, args) -> int:
    """Called by cron every minute: sample devices whose interval has elapsed (30 s tolerance)."""
    from .collect.core import load_state
    rc = 0
    for dev in cfg.devices.values():
        st = load_state(cfg.data_dir / "devices" / dev.name)
        last = st.get("last_sample")
        due = last is None or (datetime.now() - datetime.fromisoformat(last)).total_seconds() >= dev.sample_interval - 30
        if not due:
            continue
        try:
            _sample(cfg, dev)
        except Exception as e:
            log.error("%s: sample failed: %s", dev.name, e)
            rc = 1
    return rc


def cmd_logs(cfg, args) -> int:
    from .collect.core import TS_FMT, apis, export_logs, incremental_logs
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    rc = 0
    for dev in cfg.device(args.device):
        with lock(cfg, f"{dev.name}-logs") as got:
            if not got:
                log.info("%s: log export already running - skipped", dev.name)
                continue
            try:
                api, _ = apis(dev)
                if args.since:
                    since = datetime.strptime(args.since, TS_FMT)
                    until = datetime.strptime(args.until, TS_FMT) if args.until else datetime.now()
                    for lt in ([args.type] if args.type else cfg.log_types):
                        n, _ = export_logs(cfg, dev, api, lt, since, until, args.filter, stop=lambda: _stop)
                        log.info("%s: %d %s logs exported (%s .. %s)", dev.name, n, lt, args.since, until.strftime(TS_FMT))
                else:
                    res = incremental_logs(cfg, dev, api, stop=lambda: _stop)
                    log.info("%s: incremental log export %s", dev.name, res)
            except Exception as e:
                log.error("%s: log export failed: %s", dev.name, e)
                rc = 1
    return rc


def _anonymizer(ds, args, alias: str):
    if not getattr(args, "anonymize", False):
        return None
    from .anonymize import Anonymizer
    return Anonymizer(ds.meta, args.alias or alias)


def _settings(cfg, args) -> dict:
    """Analysis thresholds: config file, overridden by command-line options."""
    th = args.spike_threshold if args.spike_threshold is not None else cfg.spike_threshold
    dur = C.parse_duration(args.spike_min_duration) if args.spike_min_duration else cfg.spike_min_duration
    cap = {}  # [capacity <model>] blocks: datasheet values to compare against
    if cfg.raw is not None:
        for sec in cfg.raw.sections():
            m = re.fullmatch(r"capacity\s+(\S+)", sec)
            if m:
                cap[m.group(1)] = {k: float(v) for k, v in cfg.raw[sec].items()
                                   if k in ("firewall_gbps", "threat_gbps", "ipsec_gbps", "cps") and v.strip()}
    return {"spike_threshold": th, "spike_min_minutes": max(1, round(dur / 60)), "capacity": cap,
            "subinterfaces": bool(getattr(args, "subinterfaces", False))}


def _write_report(ds, outdir: Path, profile: str, sections: str | None, title: str, anon=None,
                  settings: dict | None = None) -> list:
    from .report import Ctx, build_pdf
    from .sections import PROFILES, SECTIONS
    if anon is not None:
        anon.apply(ds)
    outdir.mkdir(parents=True, exist_ok=True)
    ds.save(outdir)
    names = sections.split(",") if sections else list(PROFILES[profile])
    if (settings or {}).get("subinterfaces") and "interfaces" not in names and not sections:
        names.insert(names.index("traffic") + 1 if "traffic" in names else len(names) - 1, "interfaces")
    unknown = [n for n in names if n not in SECTIONS]
    if unknown:
        raise SystemExit(f"unknown section(s): {', '.join(unknown)} - known: {', '.join(SECTIONS)}")
    ctx = Ctx(ds=ds, outdir=outdir, settings=settings or {})
    ctx.settings.setdefault("report_kind", "custom selection" if sections else
                            {"standard": "standard", "load": "standard", "extended": "extended"}.get(profile, profile))
    if anon is not None:
        ctx.find("info", "Anonymization", anon.summary())
    pdf = outdir / f"{ds.meta.get('hostname', 'device')}_{outdir.name}.pdf"
    build_pdf(ctx, [SECTIONS[n] for n in names], pdf, title)
    if anon is not None:  # belt and braces: findings are built from anonymized data already
        ctx.findings = [(l, a, anon.text(t)) for l, a, t in ctx.findings]
    # findings may carry PDF markup (<b>, &nbsp;) - plain text for findings.txt/json and the terminal
    findings = [{"level": l, "area": a, "text": html.unescape(re.sub(r"<[^>]+>", "", t))} for l, a, t in ctx.findings]
    (outdir / "findings.json").write_text(json.dumps({"generated": datetime.now().isoformat(timespec="seconds"),
                                                      "meta": {k: str(v) for k, v in ds.meta.items()},
                                                      "findings": findings}, indent=2) + "\n")
    (outdir / "findings.txt").write_text("".join(f"{f['level'].upper():8s} {f['area']}: {f['text']}\n" for f in findings))
    log.info("report: %s", pdf)
    return findings


def _link_latest(parent: Path, target: Path) -> None:
    link = parent / "latest"
    try:
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(target.name)
    except OSError:
        pass


def cmd_report(cfg, args) -> int:
    from . import dataset
    from .collect.core import load_state, save_state
    warnings.simplefilter("ignore", FutureWarning)
    days = args.days if args.days is not None else cfg.report_days
    since = datetime.now() - timedelta(days=days) if days > 0 else None
    for dev in cfg.device(args.device):
        ddir = cfg.data_dir / "devices" / dev.name
        ds = dataset.build_live(ddir, since)
        ds.meta.setdefault("hostname", dev.name)
        anon = _anonymizer(ds, args, "firewall")
        parent = (args.out or cfg.report_dir) / (anon.alias if anon else dev.name)
        out = parent / f"{datetime.now():%Y%m%d_%H%M}_live_{days:g}d{'_anon' if anon else ''}"
        findings = _write_report(ds, out, args.profile, args.sections, "Dataplane & CPU load analysis (live)", anon,
                                 _settings(cfg, args))
        _link_latest(parent, out)
        st = load_state(ddir)
        st["last_report"] = datetime.now().isoformat(timespec="seconds")
        save_state(ddir, st)
        if sys.stdout.isatty():
            for f in findings:
                print(f"  {f['level'].upper():8s} {f['area']}: {f['text']}")
    return 0


def cmd_tsf(cfg, args) -> int:
    from . import dataset
    from .bundle import Bundle
    warnings.simplefilter("ignore", FutureWarning)
    bundle = Bundle.open(args.bundle, cfg.data_dir / "bundles")
    ds = dataset.build(bundle)
    host = ds.meta.get("hostname", "unknown")
    anon = _anonymizer(ds, args, "firewall")
    if anon:
        when = ds.meta.get("tsf_time") or datetime.fromtimestamp(bundle.root.stat().st_mtime)
        out = (args.out or cfg.report_dir) / anon.alias / f"tsf_{anon.bundle_name(bundle.name, when)}_anon"
    else:
        out = (args.out or cfg.report_dir) / host / f"tsf_{bundle.name}"
    findings = _write_report(ds, out, args.profile, args.sections, "Dataplane & CPU load analysis (tech support file)",
                             anon, _settings(cfg, args))
    for f in findings:
        print(f"  {f['level'].upper():8s} {f['area']}: {f['text']}")
    return 0


def cmd_prune(cfg, args) -> int:
    now = time.time()
    removed = 0

    def old(p: Path, keep: float) -> bool:
        return now - p.stat().st_mtime > keep

    for ddir in (cfg.data_dir / "devices").glob("*"):
        for p in (ddir / "samples").glob("*"):
            if old(p, cfg.retain_samples):
                removed += 1
                args.dry_run or shutil.rmtree(p)
        for p in (ddir / "logs").glob("*.csv*"):
            if old(p, cfg.retain_logs):
                removed += 1
                args.dry_run or p.unlink()
    for ddir in cfg.report_dir.glob("*"):
        for p in ddir.glob("*"):
            if p.is_dir() and not p.is_symlink() and not p.name.startswith("tsf_") and old(p, cfg.retain_reports):
                removed += 1
                args.dry_run or shutil.rmtree(p)
    log.info("prune: %d item(s) %s", removed, "would be removed (dry run)" if args.dry_run else "removed")
    return 0


CRON_BEGIN, CRON_END = "# >>> pan-ngfw-load >>>", "# <<< pan-ngfw-load <<<"


def cron_block(cfg) -> str:
    b = bin_path()
    env = f"PAN_NGFW_LOAD_CONFIG={cfg.path}"
    return "\n".join([
        CRON_BEGIN,
        "# pan-ngfw-load - PAN-OS load analysis. Edit times here; the sample interval is set in the config file.",
        f"# every minute: take a sample for each device whose interval ({cfg.sample_interval / 60:g} min default) has elapsed",
        f"* * * * *   {env} {b} tick   >/dev/null 2>&1",
        "# hourly: incremental log export",
        f"7 * * * *   {env} {b} logs   >/dev/null 2>&1",
        f"# daily 06:15: report for the last {cfg.report_days:g} days, then apply retention",
        f"15 6 * * *  {env} {b} report >/dev/null 2>&1 && {env} {b} prune >/dev/null 2>&1",
        f"# all output goes to {cfg.data_dir / 'pan-ngfw-load.log'}",
        CRON_END,
    ]) + "\n"


def _crontab_get() -> str:
    r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def _crontab_strip(text: str) -> str:
    out, skip = [], False
    for line in text.splitlines():
        if line.strip() == CRON_BEGIN:
            skip = True
            continue
        if line.strip() == CRON_END:
            skip = False
            continue
        if not skip:
            out.append(line)
    return "\n".join(out).rstrip() + ("\n" if out else "")


def cmd_cron(cfg, args) -> int:
    if not shutil.which("crontab") and (args.install or args.remove):
        raise SystemExit("crontab command not found - install cron, or use the systemd units in contrib/systemd/")
    if args.remove:
        new = _crontab_strip(_crontab_get())
        subprocess.run(["crontab", "-"], input=new, text=True, check=True)
        print("pan-ngfw-load block removed from crontab")
        return 0
    block = cron_block(cfg)
    if not args.install:
        print(block, end="")
        return 0
    current = _crontab_strip(_crontab_get())
    new = (current + "\n" if current else "") + block
    if not getattr(args, "yes", False):  # the wizard has already shown the block and asked
        print(block, end="")
        if sys.stdin.isatty() and input("Install this block into your crontab? [y/N] ").strip().lower() != "y":
            print("not installed")
            return 1
    subprocess.run(["crontab", "-"], input=new, text=True, check=True)
    print("installed (replaces an existing pan-ngfw-load block). Check with: crontab -l")
    return 0


def cmd_init(cfg, args) -> int:
    from .wizard import run
    return run(cfg, args)


# --- main -------------------------------------------------------------------
def live_installed() -> bool:
    """False for a TSF-only installation (install.sh --tsf-only leaves out the collector)."""
    return importlib.util.find_spec("pan_ngfw_load.collect") is not None


def main(argv=None) -> int:
    live = live_installed()
    ap = argparse.ArgumentParser(
        prog="pan-ngfw-load",
        description=("PAN-OS load analysis: offline (tech support files) and live (read-only XML API)." if live else
                     "PAN-OS load analysis of tech support files (TSF-only installation; the live commands "
                     "are not installed - run install.sh without --tsf-only to add them)."),
        epilog="Details for one command: pan-ngfw-load -h <command>.  Documentation: README.md, docs/SETUP.md")
    ap.add_argument("-c", "--config", type=Path, help=f"config file (default: {C.DEFAULT_PATH}, or $PAN_NGFW_LOAD_CONFIG)"
                    + ("" if live else "; optional - only data_dir/report_dir are used"))
    ap.add_argument("-v", "--verbose", action="store_true", help="show progress in the terminal and log debug details")
    ap.add_argument("-a", "--anonymize", dest="pre_anonymize", action="store_true",
                    help="anonymized report - same as -a after 'tsf' or 'report'")
    ap.add_argument("-x", "--extended", dest="pre_extended", action="store_true",
                    help="extended report - same as -x after 'tsf' or 'report'")
    ap.add_argument("-V", "--version", action="version",
                    version=f"pan-ngfw-load {__version__}" + ("" if live else " (TSF-only)"))
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="command", title="commands")

    def dev_arg(p):
        p.add_argument("-d", "--device", help="only this device (default: all)")

    def report_args(p):
        p.add_argument("-a", "--anonymize", action="store_true",
                       help="replace hostname, serial number and the device's own IP addresses in the report")
        p.add_argument("--alias", help="name used instead of the hostname with --anonymize (default: firewall)")
        p.add_argument("-o", "--out", type=Path, help="output base directory (default: report_dir)")
        p.add_argument("-x", "--extended", action="store_true",
                       help="extended report: adds drops/errors, interfaces, IPsec VPN and capacity")
        p.add_argument("--subinterfaces", action="store_true",
                       help="add a detailed table of every sub-interface and VLAN interface (zone, VLAN, traffic, "
                            "drops) to the Interfaces section - in any report")
        p.add_argument("-p", "--profile", default="standard",
                       help="section profile: standard (default), extended, dp")
        p.add_argument("-s", "--sections", help="comma-separated sections, overrides --profile")
        p.add_argument("--spike-threshold", type=float, metavar="POINTS",
                       help="core spike: load points above the median of the other DP cores (default: config, 10)")
        p.add_argument("--spike-min-duration", metavar="DURATION",
                       help="core spike: minimum duration, e.g. 15m (default: config, 15m)")

    if live:
        p = sub.add_parser("init", help="guided setup: paths, firewall, admin role/admin, API key, TLS pinning, permission test, cron")
        p.add_argument("--device", help="(re)configure this device name")
        sub.add_parser("status", help="configuration, keys, last sample / log export / report per device")
        dev_arg(sub.add_parser("test", help="check what the API keys may do (show/logs: yes, config: no)"))
        dev_arg(sub.add_parser("info", help="firewall facts and how far back the logs reach"))
        dev_arg(sub.add_parser("sample", help="take one sample now"))
        sub.add_parser("tick", help="for cron, every minute: sample each firewall whose interval has passed")
        p = sub.add_parser("logs", help="export logs (incremental since the last run, or --since/--until)")
        dev_arg(p)
        p.add_argument("--since", help="'YYYY/MM/DD HH:MM:SS' - explicit window instead of incremental")
        p.add_argument("--until", help="'YYYY/MM/DD HH:MM:SS' (default: now)")
        p.add_argument("--type", choices=["traffic", "threat"], help="default: log_types from config")
        p.add_argument("--filter", help="extra PAN-OS log filter, e.g. \"app eq 'dns-base'\"")
        p = sub.add_parser("report", help="build a report for the last N days into report_dir")
        dev_arg(p)
        p.add_argument("--days", type=float, help="time window (default: report_days; 0 = everything)")
        report_args(p)
    p = sub.add_parser("tsf", help="analyse a tech support file (.tgz or extracted directory)")
    p.add_argument("bundle", type=Path, help="techsupport .tgz or extracted directory")
    report_args(p)
    if live:
        p = sub.add_parser("prune", help="delete samples/logs/reports older than the retention settings")
        p.add_argument("-n", "--dry-run", action="store_true")
        p = sub.add_parser("cron", help="print, --install or --remove the crontab block")
        g = p.add_mutually_exclusive_group()
        g.add_argument("--install", action="store_true")
        g.add_argument("--remove", action="store_true")
        p.add_argument("-y", "--yes", action="store_true", help="install without asking")
    for action in sub._choices_actions:  # show the one-line help as description in '<command> -h'
        sub.choices[action.dest].description = action.help
    argv = list(sys.argv[1:] if argv is None else argv)
    # 'pan-ngfw-load -h <command>' -> help of that command (argparse only knows '<command> -h')
    if len(argv) >= 2 and argv[0] in ("-h", "--help") and argv[1] in sub.choices:
        argv = [argv[1], "-h"]
    LIVE_CMDS = ("init", "status", "test", "info", "sample", "tick", "logs", "report", "prune", "cron")
    if not live and any(a in LIVE_CMDS for a in argv[:3]):
        cmd = next(a for a in argv[:3] if a in LIVE_CMDS)
        raise SystemExit(f"pan-ngfw-load: '{cmd}' is part of the live collector, which this TSF-only installation "
                         "does not include.\nTo add it, run install.sh again without --tsf-only (config and reports are kept).")
    args = ap.parse_args(argv)
    if args.pre_anonymize:  # 'pan-ngfw-load -a tsf x.tgz' works like 'pan-ngfw-load tsf -a x.tgz'
        if not hasattr(args, "anonymize"):
            ap.error(f"-a/--anonymize only applies to {'tsf and report' if live else 'tsf'}, not to '{args.cmd}'")
        args.anonymize = True
    if args.pre_extended:
        if not hasattr(args, "extended"):
            ap.error(f"-x/--extended only applies to {'tsf and report' if live else 'tsf'}, not to '{args.cmd}'")
        args.extended = True
    if getattr(args, "extended", False) and args.profile == "standard":
        args.profile = "extended"

    cfg = C.load(args.config)
    if args.cmd not in ("init", "status", "cron", "tsf") and not cfg.path.exists():
        raise SystemExit(f"no configuration at {cfg.path} - run 'pan-ngfw-load init' first")
    setup_logging(cfg, args.verbose)
    os.umask(0o027)
    handler = {"init": cmd_init, "status": cmd_status, "test": cmd_test, "info": cmd_info, "sample": cmd_sample,
               "tick": cmd_tick, "logs": cmd_logs, "report": cmd_report, "tsf": cmd_tsf, "prune": cmd_prune,
               "cron": cmd_cron}[args.cmd]
    try:
        return handler(cfg, args) or 0
    except KeyboardInterrupt:
        return 130
