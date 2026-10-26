"""Replace the device identity in a dataset before a report is written.

Replaced everywhere (meta data, every table cell, findings, output path and file names):
  hostname            -> alias (default 'firewall')
  serial number       -> 'SERIAL-REDACTED'
  management IP       -> 'MGMT-IP'
  interface IPs       -> 'DEVICE-IP-1', 'DEVICE-IP-2', ... (from 'show interface all' in a TSF)
  TSF file name       -> 'YYYYMMDD_HHMM_techsupport' unless it already has exactly that form
  IPsec tunnel names and VPN peer addresses (tunnel table) -> removed; only tunnel.N remains

Other addresses (clients, servers, peers) are not changed. The raw input (TSF / collected data)
is not touched - only the report output is anonymized.
"""

from __future__ import annotations

import re
from datetime import datetime

import pandas as pd

TSF_NAME_RE = re.compile(r"^\d{8}_\d{4}_techsupport$")
TSF_DATE_RE = re.compile(r"(?<!\d)(20\d{6})[_-]?(\d{4})(?!\d)")

SERIAL_LABEL = "SERIAL-REDACTED"
MGMT_LABEL = "MGMT-IP"


class Anonymizer:
    def __init__(self, meta: dict, alias: str = "firewall"):
        self.alias = alias
        self.host = (meta.get("hostname") or "").strip()
        self.serial = (meta.get("serial") or "").strip()
        ips: dict[str, str] = {}
        mgmt = (meta.get("ip") or "").strip()
        if _is_ip(mgmt):
            ips[mgmt] = MGMT_LABEL
        for i, ip in enumerate(x for x in meta.get("device_ips") or [] if _is_ip(x) and x not in ips):
            ips[ip] = f"DEVICE-IP-{i + 1}"
        self.ips = ips
        # longest first so 192.0.2.10 is not hit by a 192.0.2.1 rule (also guarded by the lookarounds)
        self._ip_res = [(re.compile(rf"(?<![\d.]){re.escape(ip)}(?![\d])"), lab)
                        for ip, lab in sorted(ips.items(), key=lambda kv: -len(kv[0]))]
        variants = {self.host, self.host.replace("-", ""), self.host.replace("-", "_")} - {""}
        self._host_res = [re.compile(rf"(?<![\w-]){re.escape(v)}(?![\w-])", re.I) for v in sorted(variants, key=len, reverse=True)]
        self._serial_re = re.compile(re.escape(self.serial)) if len(self.serial) >= 6 else None

    # --- strings --------------------------------------------------------------
    def text(self, s):
        if not isinstance(s, str) or not s:
            return s
        for rx, lab in self._ip_res:
            s = rx.sub(lab, s)
        if self._serial_re is not None:
            s = self._serial_re.sub(SERIAL_LABEL, s)
        for rx in self._host_res:
            s = rx.sub(self.alias, s)
        return s

    def name(self, s: str) -> str:
        """For file/directory names: same replacements, but without characters unsafe in paths."""
        return self.text(s).replace("/", "_")

    @staticmethod
    def bundle_name(name: str, when: datetime | None = None) -> str:
        """TSF name -> 'YYYYMMDD_HHMM_techsupport'. A name already in that form is kept; otherwise the
        date comes from a YYYYMMDD_HHMM inside the name, else from `when` (TSF time), else 'unknown'."""
        stem = name
        for ext in (".tgz", ".tar.gz", ".tar"):
            if stem.lower().endswith(ext):
                stem = stem[: -len(ext)]
        if TSF_NAME_RE.match(stem):
            return stem
        m = TSF_DATE_RE.search(stem)
        if m:
            try:
                datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M")
                return f"{m.group(1)}_{m.group(2)}_techsupport"
            except ValueError:
                pass
        if when is not None:
            return f"{when:%Y%m%d_%H%M}_techsupport"
        return "unknown_techsupport"

    # --- dataset ----------------------------------------------------------------
    def frame(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return df
        df = df.copy()
        for c in df.columns:
            if df[c].dtype == object:
                df[c] = df[c].map(self.text)
        return df

    def apply(self, ds) -> None:
        m = ds.meta
        m["hostname"] = self.alias
        if m.get("serial"):
            m["serial"] = SERIAL_LABEL
        if m.get("ip"):
            m["ip"] = MGMT_LABEL
        m["device_ips"] = list(self.ips.values())
        if m.get("bundle"):
            m["bundle"] = self.bundle_name(str(m["bundle"]), m.get("tsf_time"))
        m["anonymized"] = True
        # tunnel names / VPN peers identify partners of the device owner
        if "if_counters" in ds.t:
            ds.t["if_counters"] = ds.t["if_counters"].drop(columns=["ipsec_tunnel", "peer"], errors="ignore")
        if "vpn_tunnels" in ds.t:
            v = ds.t["vpn_tunnels"].drop(columns=["peer", "local"], errors="ignore")
            bases = {b: f"vpn-{i + 1}" for i, b in enumerate(dict.fromkeys(v.name.str.split(":").str[0]))}
            ds.t["vpn_tunnels"] = v.assign(name=[bases[n.split(":")[0]] + (":" + n.split(":", 1)[1] if ":" in n else "")
                                                 for n in v.name])
        for k, df in list(ds.t.items()):
            ds.t[k] = self.frame(df)

    def summary(self) -> str:
        n = len(self.ips)
        return (f"Device identity anonymized: hostname -> '{self.alias}', serial number and {n} device IP "
                f"address{'es' if n != 1 else ''} (management + interfaces) replaced. Other IP addresses are unchanged.")


def _is_ip(s: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", s or "")) or (":" in (s or "") and len(s) > 2)


def interface_ips(text: str) -> list[str]:
    """IPs from the 'logical interfaces' table of 'show interface all' (address column, prefix removed)."""
    out = []
    for line in text.splitlines():
        for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})/\d{1,2}\b", line):
            out.append(m.group(1))
    return list(dict.fromkeys(out))
