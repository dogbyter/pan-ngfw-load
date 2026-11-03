"""Storage health: SSD SMART data, file-system checks at boot and storage errors in the kernel log."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

SMART_COLS = ["disk", "model", "health", "critical_warning", "temp", "temp_warn", "temp_crit", "spare", "spare_min",
              "wear", "power_on_hours", "power_cycles", "unsafe_shutdowns", "media_errors"]
FSCK_COLS = ["time", "filesystem", "journal", "forced", "fixes", "harmless", "exit", "files_used", "files_total"]
# counter fixes e2fsck makes after every unclean shutdown - they change no data
HARMLESS_FIX = re.compile(r"^(Free (blocks|inodes) count wrong|Padding at end of inode bitmap|"
                          r"Inode bitmap differences|Block bitmap differences)")
KERNEL_ERR = re.compile(
    r"EXT[234]-fs error|EXT[234]-fs \(\S+\): (error|warning).*(corrupt|error)|Remounting filesystem read-only|"
    r"\bI/O error\b|blk_update_request|critical medium error|nvme\S*: .*(I/O \d+ QID|controller is down|"
    r"Removing after probe failure|resetting controller)|ata\d+(\.\d+)?: (failed command|exception|"
    r"hard resetting)|mmc\d+: .*(error -\d+|card removed|timeout waiting)", re.I)


def _int(s: str) -> int:
    return int(re.sub(r"[,\s]", "", s))


def smart(text: str, disk: str) -> dict | None:
    """'debug system disk-smart-info disk-N' (smartctl -a) -> one row of SMART_COLS (NVMe or SATA)."""
    if "SMART" not in text:
        return None
    r = dict.fromkeys(SMART_COLS)
    r["disk"] = disk
    if m := re.search(r"^(?:Model Number|Device Model):\s+(.+?)\s*$", text, re.M):
        r["model"] = m.group(1)
    if m := re.search(r"self-assessment test result:\s+(\S+)", text):
        r["health"] = m.group(1)
    nvme = {  # 'Name:   value' lines of the NVMe health log
        "Critical Warning": ("critical_warning", lambda v: int(v, 16)),
        "Temperature": ("temp", lambda v: _int(v.split()[0])),
        "Warning  Comp. Temp. Threshold": ("temp_warn", lambda v: _int(v.split()[0])),
        "Critical Comp. Temp. Threshold": ("temp_crit", lambda v: _int(v.split()[0])),
        "Available Spare": ("spare", lambda v: _int(v.rstrip("%"))),
        "Available Spare Threshold": ("spare_min", lambda v: _int(v.rstrip("%"))),
        "Percentage Used": ("wear", lambda v: _int(v.rstrip("%"))),
        "Power On Hours": ("power_on_hours", _int),
        "Power Cycles": ("power_cycles", _int),
        "Unsafe Shutdowns": ("unsafe_shutdowns", _int),
        "Media and Data Integrity Errors": ("media_errors", _int),
    }
    for line in text.splitlines():
        name, _, val = line.partition(":")
        if name.strip() in nvme and val.strip():
            key, fn = nvme[name.strip()]
            try:
                r[key] = fn(val.strip())
            except ValueError:
                pass
    # SATA: ID# ATTRIBUTE_NAME FLAG VALUE WORST THRESH TYPE UPDATED WHEN_FAILED RAW_VALUE
    errs = None
    for m in re.finditer(r"^\s*\d+\s+(\S+)\s+0x\w+\s+(\d+)\s+\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+(\d+)", text, re.M):
        name, norm, raw = m.group(1), int(m.group(2)), int(m.group(3))
        if name in ("Reallocated_Sector_Ct", "Current_Pending_Sector", "Offline_Uncorrectable", "Reported_Uncorrect"):
            errs = (errs or 0) + raw
        elif name == "Power_Cycle_Count":
            r["power_cycles"] = raw
        elif name == "Power_On_Hours":
            r["power_on_hours"] = raw
        elif name in ("Temperature_Celsius", "Airflow_Temperature_Cel") and r["temp"] is None:
            r["temp"] = raw
        elif name in ("Unexpect_Power_Loss_Ct", "Unsafe_Shutdown_Count", "Power-Off_Retract_Count"):
            r["unsafe_shutdowns"] = raw
        elif name == "Percent_Lifetime_Remain":
            r["wear"] = 100 - norm
        elif name in ("Media_Wearout_Indicator", "Wear_Leveling_Count") and r["wear"] is None:
            r["wear"] = 100 - norm
    if errs is not None:
        r["media_errors"] = errs
    return r


def _fsck_runs(lines: list[str], when) -> list[dict]:
    """e2fsck output of one boot -> one row per file system (label as e2fsck prints it: panlogs, pancfg, ...)."""
    rows, cur, prev = {}, None, ""
    for line in lines:
        line = line.strip()
        if m := re.match(r"^([\w-]+)(?::| has been mounted)", line):
            if m.group(1) not in ("fsck", "e2fsck", "Pass", "Fix", "Free", "Setting", "Clearing", "printk"):
                cur = m.group(1)
                rows.setdefault(cur, dict(dict.fromkeys(FSCK_COLS), time=when, filesystem=cur, journal=False,
                                          forced=False, fixes=[], exit=0))
        r = rows.get(cur)
        if r is None:
            prev = line
            continue
        if "recovering journal" in line:
            r["journal"] = True
        elif "check forced" in line:
            r["forced"] = True
        elif line.startswith("Fix? yes") or line.endswith("Fix? yes"):
            r["fixes"].append(prev.rstrip(". "))
        elif m := re.search(r"(?:clean, )?(\d+)/(\d+) files", line):
            r["files_used"], r["files_total"] = int(m.group(1)), int(m.group(2))
        elif m := re.search(r"Fsck \S+: error (\d+)", line):
            r["exit"] = max(r["exit"], int(m.group(1)))
        prev = line
    out = list(rows.values())
    for r in out:
        r["harmless"] = all(HARMLESS_FIX.match(f) for f in r["fixes"])
        r["fixes"] = "; ".join(dict.fromkeys(r["fixes"]))
    return out


def fsck(panlogs_partition: Path | None, dmesg: Path | None, boot) -> pd.DataFrame:
    """File-system checks at boot: var/log/pan/panlogs-partition.log (panlogs, every boot it keeps) and
    var/log/dmesg (the other file systems, last boot only)."""
    rows = []
    if panlogs_partition and panlogs_partition.is_file():
        run, when = [], None
        for line in panlogs_partition.read_text(errors="replace").splitlines():
            if m := re.search(r"\+{5,}\s+\w{3} (\w{3} +\d+ [\d:]+ \d{4})\s+\+{5,}", line):
                if run:
                    rows += _fsck_runs(run, when)
                run = []
                try:
                    when = datetime.strptime(" ".join(m.group(1).split()), "%b %d %H:%M:%S %Y")
                except ValueError:
                    when = None
                continue
            run.append(re.sub(r"^\w{3} +\d+ [\d:]+ (DEBUG|ERROR|INFO|WARNING): ?", "", line))
        if run:
            rows += _fsck_runs(run, when)
        # the log is not always written in the firewall's time zone: shift it so its last run is the last boot
        if rows and boot is not None and rows[-1]["time"] is not None:
            off = boot - rows[-1]["time"]
            if abs(off) < timedelta(hours=26):
                off = timedelta(minutes=15 * round(off.total_seconds() / 900))
                for r in rows:
                    r["time"] = r["time"] + off if r["time"] is not None else None
    if dmesg and dmesg.is_file():
        lines = [re.sub(r"^\[\s*[\d.]+\]\s?", "", l) for l in dmesg.read_text(errors="replace").splitlines()]
        rows += [r for r in _fsck_runs(lines, boot)
                 if r["filesystem"] != "panlogs" and (r["files_total"] or r["journal"] or r["fixes"])]
    df = pd.DataFrame(rows, columns=FSCK_COLS)
    return df.sort_values("time", na_position="first", kind="stable").reset_index(drop=True)


def kernel_errors(files: list[Path]) -> pd.DataFrame:
    """Disk and file-system errors in var/log/dmesg and var/log/messages -> message, count, last."""
    seen: dict[str, list] = {}
    for f in files:
        if not f.is_file():
            continue
        for line in f.read_text(errors="replace").splitlines():
            if not KERNEL_ERR.search(line):
                continue
            stamp = m.group(1) if (m := re.match(r"^(\w{3} +\d+ [\d:]+)", line)) else ""
            msg = re.sub(r"^.*?\]\s*", "", line) if "]" in line[:60] else line
            key = re.sub(r"\b\d+\b", "N", msg)[:160]
            e = seen.setdefault(key, [msg[:160], 0, ""])
            e[1] += 1
            e[2] = stamp or e[2]
    return pd.DataFrame(seen.values(), columns=["message", "count", "last"])
