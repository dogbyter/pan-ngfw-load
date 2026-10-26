"""Configuration (INI, standard library only).

Location: $PAN_NGFW_LOAD_CONFIG, else ~/.config/pan-ngfw-load/pan-ngfw-load.ini. Example: see contrib/pan-ngfw-load.ini.example.

    [general]
    data_dir = ~/pan-ngfw-load/data            # samples, logs, extracted TSFs, state, pan-ngfw-load.log
    report_dir = ~/pan-ngfw-load/reports       # PDFs, charts, CSV tables, findings.json
    secrets_dir = ~/.config/pan-ngfw-load/keys # API keys + pinned TLS fingerprints (mode 700)
    sample_interval = 5m
    report_days = 7                   # time window of a scheduled report
    log_types = traffic               # traffic, threat (comma separated)
    log_initial = 1d                  # first incremental log export looks back this far
    retain_samples = 35d
    retain_logs = 90d
    retain_reports = 180d
    spike_threshold = 10              # core spike: points above the median of the other DP cores
    spike_min_duration = 15m          # ... sustained at least this long

    [device fw01]
    host = 192.0.2.10                 # management IP or FQDN
    key = fw01                        # -> <secrets_dir>/fw01.key and fw01.fingerprint
    diag_key = fw01-diag              # optional: key of an admin allowed to run pow performance
    sample_interval = 5m              # optional per-device override
"""

from __future__ import annotations

import configparser
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATH = Path(os.environ.get("PAN_NGFW_LOAD_CONFIG", "~/.config/pan-ngfw-load/pan-ngfw-load.ini")).expanduser()

DEFAULTS = {
    "data_dir": "~/pan-ngfw-load/data",
    "report_dir": "~/pan-ngfw-load/reports",
    "secrets_dir": "~/.config/pan-ngfw-load/keys",
    "sample_interval": "5m",
    "report_days": "7",
    "log_types": "traffic",
    "log_initial": "1d",
    "retain_samples": "35d",
    "retain_logs": "90d",
    "retain_reports": "180d",
    "spike_threshold": "10",
    "spike_min_duration": "15m",
}


def parse_duration(s: str) -> float:
    """'90', '90s', '5m', '24h', '7d' -> seconds."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhd]?)\s*", str(s))
    if not m:
        raise ValueError(f"bad duration {s!r} (examples: 300, 5m, 24h, 7d)")
    return float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


@dataclass
class Device:
    name: str
    host: str
    key: str
    diag_key: str | None
    sample_interval: float
    secrets_dir: Path

    @property
    def key_file(self) -> Path:
        return self.secrets_dir / f"{self.key}.key"

    @property
    def fingerprint_file(self) -> Path:
        return self.secrets_dir / f"{self.key}.fingerprint"

    @property
    def diag_key_file(self) -> Path | None:
        return self.secrets_dir / f"{self.diag_key}.key" if self.diag_key else None


@dataclass
class Config:
    path: Path
    data_dir: Path
    report_dir: Path
    secrets_dir: Path
    sample_interval: float
    report_days: float
    log_types: list[str]
    log_initial: float
    retain_samples: float
    retain_logs: float
    retain_reports: float
    spike_threshold: float = 10.0
    spike_min_duration: float = 900.0
    devices: dict[str, Device] = field(default_factory=dict)
    raw: configparser.ConfigParser | None = None

    def device_dir(self, name: str) -> Path:
        d = self.data_dir / "devices" / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def device(self, name: str | None) -> list[Device]:
        """One named device, or all if name is None."""
        if name is None:
            return list(self.devices.values())
        if name not in self.devices:
            raise SystemExit(f"unknown device {name!r} - configured: {', '.join(self.devices) or 'none'}")
        return [self.devices[name]]


def load(path: Path | None = None) -> Config:
    path = (path or DEFAULT_PATH).expanduser()
    cp = configparser.ConfigParser(inline_comment_prefixes=(";", "#"))
    cp["general"] = DEFAULTS
    if path.exists():
        cp.read(path)
    g = cp["general"]
    p = lambda k: Path(g.get(k)).expanduser()
    cfg = Config(
        path=path, data_dir=p("data_dir"), report_dir=p("report_dir"), secrets_dir=p("secrets_dir"),
        sample_interval=parse_duration(g.get("sample_interval")), report_days=float(g.get("report_days")),
        log_types=[x.strip() for x in g.get("log_types").split(",") if x.strip()],
        log_initial=parse_duration(g.get("log_initial")),
        retain_samples=parse_duration(g.get("retain_samples")), retain_logs=parse_duration(g.get("retain_logs")),
        retain_reports=parse_duration(g.get("retain_reports")),
        spike_threshold=float(g.get("spike_threshold")), spike_min_duration=parse_duration(g.get("spike_min_duration")),
        raw=cp,
    )
    for sec in cp.sections():
        m = re.fullmatch(r"device\s+(\S+)", sec)
        if not m:
            continue
        s = cp[sec]
        name = m.group(1)
        cfg.devices[name] = Device(
            name=name, host=s.get("host", ""), key=s.get("key", name), diag_key=s.get("diag_key") or None,
            sample_interval=parse_duration(s.get("sample_interval", g.get("sample_interval"))),
            secrets_dir=cfg.secrets_dir,
        )
    return cfg


def save(cfg: Config) -> None:
    cp = cfg.raw or configparser.ConfigParser()
    cfg.path.parent.mkdir(parents=True, exist_ok=True)
    with open(cfg.path, "w") as fh:
        fh.write("# pan-ngfw-load configuration - see 'pan-ngfw-load --help' and docs/SETUP.md\n")
        cp.write(fh)
    cfg.path.chmod(0o600)
