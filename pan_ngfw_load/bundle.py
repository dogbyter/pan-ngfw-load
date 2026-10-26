"""Locate the files of a tech support bundle (extracting a .tgz if needed)."""

from __future__ import annotations

import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path


def _rotation_key(p: Path) -> int:
    """'x.log.4' -> 4, 'x.log' -> 0. Higher number = older."""
    m = re.search(r"\.(\d+)$", p.name)
    return int(m.group(1)) if m else 0


def extract(tgz: Path, dest_root: Path) -> Path:
    """Extract tgz into dest_root/<stem>/ (once) and return that directory."""
    stem = tgz.name.split(".")[0]
    dest = dest_root / stem
    if dest.is_dir() and any(dest.iterdir()):
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tgz) as tf:
        if hasattr(tarfile, "data_filter"):
            tf.extractall(dest, filter="data")  # blocks absolute paths, links out of tree, devices
        else:  # pragma: no cover - very old Python
            tf.extractall(dest)
    return dest


@dataclass
class Bundle:
    root: Path
    name: str
    cli_dump: Path | None = None
    dp_monitor: list[Path] = field(default_factory=list)  # oldest first
    mp_monitor: list[Path] = field(default_factory=list)  # oldest first
    sar_text: list[Path] = field(default_factory=list)
    crashinfo: list[Path] = field(default_factory=list)

    @classmethod
    def open(cls, path: Path, extract_root: Path) -> "Bundle":
        path = path.resolve()
        if path.is_file():
            root = extract(path, extract_root)
            name = path.name.split(".")[0]
        else:
            root, name = path, path.name
        b = cls(root=root, name=name)
        dumps = sorted((root / "tmp/cli").glob("techsupport_*.txt"))
        b.cli_dump = dumps[-1] if dumps else None
        pan = root / "var/log/pan"
        b.dp_monitor = sorted(pan.glob("dp-monitor.log*"), key=_rotation_key, reverse=True)
        b.mp_monitor = sorted(pan.glob("mp-monitor.log*"), key=_rotation_key, reverse=True)
        b.sar_text = sorted((root / "var/log/sa").glob("sar[0-9]*"))
        b.crashinfo = sorted((root / "opt/panlogs/cores/crashinfo").glob("*"))
        return b

    def inventory(self) -> dict[str, str]:
        return {
            "CLI dump": self.cli_dump.name if self.cli_dump else "missing",
            "dp-monitor logs": str(len(self.dp_monitor)),
            "mp-monitor logs": str(len(self.mp_monitor)),
            "sar text files": str(len(self.sar_text)),
            "crashinfo files": str(len(self.crashinfo)),
        }
