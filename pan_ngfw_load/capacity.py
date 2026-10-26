"""Model capacity values (datasheet limits) from local CSV files - nothing is built in.

Files are configured with `capacity_files` (comma-separated paths, directories or globs). Format, one value per row
(see contrib/capacity.example.csv):

    model,metric,value,unit,panos_version,text
    PA-EXAMPLE,threat_appmix_gbps,1.5,gbps,11.2.0,
    PA-EXAMPLE,security_rules,1500,,11.2.0,

`text` holds a note or a non-numeric value. Several files for different PAN-OS versions can be loaded at the same
time; for a firewall the version closest to its own PAN-OS is used. A `[capacity MODEL]` block in the config file
overrides single values.
"""

from __future__ import annotations

import csv
import glob
import re
from functools import lru_cache
from pathlib import Path

# config-block keys of earlier versions -> metric names
ALIASES = {"firewall_gbps": "fw_appmix_gbps", "threat_gbps": "threat_appmix_gbps"}

# metric -> (label, unit hint); the order is the order of the report table
METRICS = {
    "fw_appmix_gbps": ("Firewall throughput (App-ID, appmix)", "Gbit/s"),
    "threat_appmix_gbps": ("Threat prevention throughput (appmix)", "Gbit/s"),
    "ipsec_gbps": ("IPsec VPN throughput", "Gbit/s"),
    "cps": ("New sessions per second", "/s"),
    "sessions": ("Sessions", ""),
    "security_rules": ("Security rules", ""),
    "nat_rules": ("NAT rules", ""),
    "decryption_rules": ("Decryption rules", ""),
    "pbf_rules": ("Policy-based forwarding rules", ""),
    "app_override_rules": ("Application override rules", ""),
    "dos_rules": ("DoS protection rules", ""),
    "qos_rules": ("QoS rules", ""),
    "address_objects": ("Address objects", ""),
    "address_groups": ("Address groups", ""),
    "service_objects": ("Service objects", ""),
    "service_groups": ("Service groups", ""),
    "dag_ips": ("Registered IPs (dynamic address groups)", ""),
    "edl_lists": ("External dynamic lists", ""),
    "url_custom_categories": ("Custom URL categories", ""),
    "zones": ("Security zones", ""),
    "virtual_routers": ("Virtual / logical routers", ""),
    "interfaces": ("Logical interfaces", ""),
    "vlan_tags": ("802.1q tags (sub-interfaces)", ""),
    "aggregates": ("Aggregate groups", ""),
    "arp_entries": ("ARP table", ""),
    "ndp_entries": ("IPv6 neighbor table", ""),
    "mac_entries": ("MAC table", ""),
    "fib_total": ("Forwarding table (routes)", ""),
    "ipsec_tunnels": ("IPsec tunnels (SA pairs)", ""),
    "gp_users": ("GlobalProtect users", ""),
    "userid_mappings_mp": ("User-ID mappings", ""),
}


def _version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3]) or (0,)


@lru_cache(maxsize=8)
def _load(paths: tuple[str, ...]) -> tuple[tuple, ...]:
    rows = []
    for spec in paths:
        p = Path(spec).expanduser()
        files = sorted(p.glob("*.csv")) if p.is_dir() else [Path(x) for x in sorted(glob.glob(str(p)))]
        for f in files:
            try:
                with open(f, newline="", encoding="utf-8") as fh:
                    for r in csv.DictReader(fh):
                        rows.append((r.get("model", "").strip(), r.get("metric", "").strip(), r.get("value", "").strip(),
                                     r.get("unit", "").strip(), r.get("panos_version", "").strip(),
                                     r.get("text", "").strip()))
            except OSError:
                continue
    return tuple(rows)


def for_model(paths, model: str, sw_version: str = "") -> tuple[dict, dict, str]:
    """-> ({metric: value}, {metric: note}, panos_version of the values used) for one model."""
    if not paths or not model:
        return {}, {}, ""
    rows = [r for r in _load(tuple(str(p) for p in paths)) if r[0].lower() == model.lower()]
    if not rows:
        return {}, {}, ""
    versions = sorted({r[4] for r in rows}, key=_version_tuple)
    want = _version_tuple(sw_version)
    best = min(versions, key=lambda v: (abs(_version_tuple(v)[0] - want[0]) * 1000
                                        + abs((_version_tuple(v) + (0, 0))[1] - (want + (0, 0))[1])))
    vals, notes = {}, {}
    for m, metric, value, _u, ver, text in rows:
        if ver != best:
            continue
        if value:
            try:
                vals[metric] = float(value)
            except ValueError:
                pass
        if text:
            notes[metric] = text
    return vals, notes, best


def limits(settings: dict, model: str, sw_version: str) -> tuple[dict, dict, str]:
    """Datasheet values for this firewall: capacity files plus [capacity MODEL] overrides from the config."""
    vals, notes, ver = for_model(settings.get("capacity_files") or [], model, sw_version)
    over = (settings.get("capacity") or {}).get(model, {})
    for k, v in over.items():
        if v:
            vals[ALIASES.get(k, k)] = float(v)
    return vals, notes, ver
