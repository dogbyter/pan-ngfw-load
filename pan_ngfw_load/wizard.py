"""'pan-ngfw-load init' - interactive, explained setup. Safe to re-run (keeps existing values as defaults)."""

from __future__ import annotations

import getpass
import shutil
import sys
import textwrap
from pathlib import Path

from . import config as C
from .collect.api import ApiError, fetch_fingerprint, keygen, write_secret

W = 78


def say(text: str = "") -> None:
    """Print text: plain paragraphs are re-flowed to the terminal width, indented blocks
    (lists, commands, settings) are printed as written."""
    for block in textwrap.dedent(text).strip("\n").split("\n\n"):
        lines = block.split("\n")
        if any(l.startswith(" ") for l in lines):
            print(block)
        else:
            print(textwrap.fill(" ".join(l.strip() for l in lines), W, break_long_words=False, break_on_hyphens=False))
        print()


def head(n: int, title: str) -> None:
    print("\n" + "=" * W + f"\n Step {n}: {title}\n" + "=" * W)


def ask(prompt: str, default: str | None = None) -> str:
    sfx = f" [{default}]" if default not in (None, "") else ""
    while True:
        v = input(f"{prompt}{sfx}: ").strip()
        if v:
            return v
        if default is not None:
            return default


def yes(prompt: str, default: bool = False) -> bool:
    v = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not v else v in ("y", "yes", "j", "ja")


def pause(prompt: str = "Press Enter when done (Ctrl-C aborts)") -> None:
    input(f"{prompt} ")


ROLE_STEPS = """
  Firewall web UI -> Device -> Admin Roles -> Add      (Panorama-managed firewall:
  create it locally on the firewall, or in the template and push it)

    Name:            {role}
    Role:            Device
    Web UI:          disable everything (click each top-level item until it is
                     greyed out / "Disable")
    XML API:         enable ONLY  "Operational Requests"  and  "Log"
                     (Report, Configuration, Commit, User-ID Agent, IoT Agent,
                      Export, Import: disabled)
    REST API:        disable everything
    Command Line:    None
  -> OK

  Device -> Administrators -> Add
    Name:                    {admin}
    Authentication Profile:  None (local password)
    Password:                a long random password (used once for the key)
    Administrator Type:      Role Based,  Profile: {role}
  -> OK, then Commit.

  Optional but recommended: restrict management access to this host
  (Device -> Setup -> Interfaces -> Management -> Permitted IP Addresses).
"""

READONLY_STEPS = """
  Device -> Administrators -> Add
    Name:                    {admin}
    Authentication Profile:  None (local password)
    Administrator Type:      Dynamic,  "Superuser (read-only)"
  -> OK, then Commit.
"""


def run(cfg: C.Config, args) -> int:
    if not sys.stdin.isatty():
        print("pan-ngfw-load init is interactive - run it in a terminal.")
        return 2
    cp = cfg.raw
    g = cp["general"]

    title = "pan-ngfw-load - setup"
    print(f"\n{title}\n{'-' * len(title)}\n")
    say(f"""
    pan-ngfw-load measures how busy a PAN-OS firewall's dataplane (DP) and management plane are, and
    which traffic causes the load. It works from two sources:

      * tech support files (offline, 'pan-ngfw-load tsf <file>'), and
      * live data read through the firewall's XML API (this setup).

    What pan-ngfw-load does on the firewall: it only runs 'show ...' commands, the diagnostic
    command 'debug dataplane pow performance' and log queries. Every request is checked
    against a built-in allow-list before it leaves this host - configuration changes,
    commits, restarts or 'clear' commands are never sent, regardless of the admin's rights.

    What you need:
      * Python 3.10+ and this installation (done if you can read this)
      * HTTPS access from this host to the firewall's management IP
      * an admin account on the firewall (or Panorama) to create a role and an admin
      * cron (or systemd timers) for unattended operation

    Nothing is changed on the firewall by this wizard - you create the role and admin
    yourself following the instructions below. Config file: {cfg.path}
    """)
    if not yes("Continue?", True):
        return 1

    # 1 paths -------------------------------------------------------------
    head(1, "Where to store data, reports and secrets")
    say("""
    data_dir    raw samples, exported logs, extracted tech support files, state, pan-ngfw-load.log
    report_dir  generated reports: PDF, charts (PNG), tables (CSV), findings.json/.txt
    secrets_dir API keys and the pinned TLS fingerprints (created with mode 700, files 600)
    """)
    for k in ("data_dir", "report_dir", "secrets_dir"):
        g[k] = ask(k, g.get(k))
    say("""
    Sample interval: how often cron takes a sample per device. Each sample is 7 short API
    calls (a few seconds of management-plane work). 5 minutes is a good default; 1 minute
    is the minimum.
    """)
    while True:
        v = ask("sample_interval (e.g. 5m, 10m, 1h)", g.get("sample_interval"))
        try:
            if C.parse_duration(v) < 60:
                print("  minimum is 60s")
                continue
            g["sample_interval"] = v
            break
        except ValueError as e:
            print(f"  {e}")
    g["report_days"] = ask("report window in days for the scheduled daily report", g.get("report_days"))
    g["log_types"] = ask("log types to export (traffic, threat)", g.get("log_types"))
    g["log_initial"] = ask("first log export looks back (e.g. 1d, 7d; older logs: 'pan-ngfw-load logs --since')", g.get("log_initial"))
    for k in ("retain_samples", "retain_logs", "retain_reports"):
        g[k] = ask(f"{k} (delete older data)", g.get(k))
    secrets = Path(g["secrets_dir"]).expanduser()
    secrets.mkdir(parents=True, exist_ok=True)
    secrets.chmod(0o700)

    # 2 device ------------------------------------------------------------
    head(2, "Firewall and TLS certificate")
    existing = [s.split(None, 1)[1] for s in cp.sections() if s.startswith("device ")]
    name = args.device or ask("Device name (short, no spaces - used for files and reports)",
                              existing[0] if existing else None)
    sec = f"device {name}"
    if sec not in cp:
        cp[sec] = {}
    d = cp[sec]
    d["host"] = ask("Management IP or FQDN", d.get("host"))
    say("""
    The firewall's web/API certificate is usually self-signed, so pan-ngfw-load cannot verify it via a
    CA. Instead it pins the certificate's SHA-256 fingerprint now and refuses to talk to the
    firewall if it ever changes (protects the API key against interception).
    """)
    try:
        fp = fetch_fingerprint(d["host"])
    except OSError as e:
        print(f"  cannot reach {d['host']}:443 - {e}")
        return 1
    print(f"\n  SHA-256 fingerprint: {':'.join(fp[i:i + 2] for i in range(0, len(fp), 2))}\n")
    say(f"""
    To verify it independently, run on a trusted machine:
      openssl s_client -connect {d['host']}:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
    """)
    if not yes("Does the fingerprint match / do you trust it?", False):
        print("aborted - nothing pinned")
        return 1
    key_name = d.get("key", name)
    d["key"] = key_name
    write_secret(secrets / f"{key_name}.fingerprint", fp)

    # 3 role + admin --------------------------------------------------------
    head(3, "Admin role and admin account on the firewall")
    say("""
    PAN-OS cannot restrict the API to single commands. Two layouts are possible:

      A) one admin with a custom role: XML API "Operational Requests" + "Log" only.   (recommended)
         + live DP breakdown by stage/function ('debug dataplane pow performance')
         + cannot read or change the configuration, cannot commit
         - "Operational Requests" would also allow disruptive commands (restart, clear
           sessions). pan-ngfw-load never sends them (allow-list), but protect the key file.

      B) strictly read-only admin (Dynamic "Superuser (read-only)") - optionally plus the
         custom-role admin from A as a separate "diag" key for pow performance only.
         + device-enforced read-only
         - can read the whole configuration (incl. password hashes)
         - without the diag key: no live DP breakdown (tech support files still have it)

    Known issue: on PAN-OS 11.2.6 newly created admins could not log in at all
    ("Authentication profile not found for the user"); fixed in later 11.2 releases.
    """)
    layout = ask("Layout A or B", "A").upper()
    if layout == "A":
        admin = ask("Admin name", "pan-ngfw-load-collector")
        say(ROLE_STEPS.format(role="pan-ngfw-load-collector", admin=admin))
        pause()
        if not _make_key(d["host"], fp, admin, secrets / f"{key_name}.key"):
            return 1
        d.pop("diag_key", None)
        d["diag_key"] = key_name  # same key: allowed to run pow performance
    else:
        admin = ask("Read-only admin name", "pan-ngfw-load-readonly")
        say(READONLY_STEPS.format(admin=admin))
        pause()
        if not _make_key(d["host"], fp, admin, secrets / f"{key_name}.key"):
            return 1
        if yes("Also set up the optional diag admin (custom role) for the live DP breakdown?", True):
            diag_admin = ask("Diag admin name", "pan-ngfw-load-diag")
            say(ROLE_STEPS.format(role="pan-ngfw-load-diag", admin=diag_admin))
            pause()
            diag_key = f"{key_name}-diag"
            if _make_key(d["host"], fp, diag_admin, secrets / f"{diag_key}.key"):
                d["diag_key"] = diag_key
                shutil.copyfile(secrets / f"{key_name}.fingerprint", secrets / f"{diag_key}.fingerprint")
        else:
            d.pop("diag_key", None)
    if yes(f"Use a different sample interval for {name} than the default ({g['sample_interval']})?", False):
        d["sample_interval"] = ask("sample_interval", g["sample_interval"])
    C.save(cfg)
    cfg = C.load(cfg.path)
    print(f"\n  configuration written: {cfg.path}")

    # 4 test -------------------------------------------------------------
    head(4, "Permission test")
    say("""
    pan-ngfw-load now checks what the key(s) may do. The configuration probes are sent directly
    (bypassing the allow-list) to prove that the firewall itself denies them; their
    content is discarded. Nothing is changed.
    """)
    from .cli import cmd_test
    import argparse as _ap
    rc = cmd_test(cfg, _ap.Namespace(device=name))
    if rc:
        say("""
        One or more checks did not match the expectation. Review the role settings, commit,
        and re-run 'pan-ngfw-load test'. Collection still works for the allowed parts.
        """)

    # 5 first data ---------------------------------------------------------
    head(5, "First sample")
    from .cli import cmd_info, cmd_sample
    try:
        cmd_info(cfg, _ap.Namespace(device=name))
        cmd_sample(cfg, _ap.Namespace(device=name))
        print(f"  data: {cfg.data_dir / 'devices' / name}")
    except ApiError as e:
        print(f"  failed: {e}")

    # 6 cron ----------------------------------------------------------------
    head(6, "Unattended operation (cron)")
    from .cli import cmd_cron, cron_block
    say("""
    The block below runs 'pan-ngfw-load tick' every minute (it only samples when a device's interval
    has elapsed), exports logs hourly and builds a report every morning, followed by the
    retention clean-up. The schedule can be edited with 'crontab -e'; the sample interval
    lives in the config file.
    """)
    print(cron_block(cfg))
    if shutil.which("crontab") and yes("Install it into the crontab of this user now?", False):
        cmd_cron(cfg, _ap.Namespace(install=True, remove=False, yes=True))
    else:
        print("  Not installed. Later: 'pan-ngfw-load cron --install', or systemd units from contrib/systemd/.")

    say(f"""

    Done.
      pan-ngfw-load status            overview
      pan-ngfw-load report            build a report now (last {cfg.report_days:g} days) -> {cfg.report_dir}/{name}/latest/
      pan-ngfw-load logs --since "YYYY/MM/DD HH:MM:SS"   back-fill older logs (large: ~6k logs/h on a PA-440)
      pan-ngfw-load tsf <file.tgz>    analyse a tech support file
    Note: changing the admin's password on the firewall invalidates its API key. After a
    password change, re-run 'pan-ngfw-load init --device {name}' to create a new key.
    """)
    return 0


def _make_key(host: str, fp: str, admin: str, key_file: Path) -> bool:
    say(f"""
    API key for '{admin}': pan-ngfw-load asks for the password once, requests a key over the pinned
    connection and stores only the key in {key_file} (mode 600). The password is not saved.
    Changing the password later invalidates the key (re-run 'pan-ngfw-load init --device <name>').
    """)
    if key_file.exists() and yes(f"{key_file.name} exists - keep it?", True):
        return True
    for _ in range(3):
        pw = getpass.getpass(f"Password of {admin} (not echoed): ")
        try:
            key = keygen(host, fp, admin, pw)
        except (ApiError, OSError) as e:
            print(f"  {e}")
            continue
        finally:
            pw = None  # noqa: F841
        write_secret(key_file, key)
        print(f"  key stored: {key_file}")
        return True
    print("  giving up after 3 attempts")
    return False
