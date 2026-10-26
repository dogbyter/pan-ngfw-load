"""Model limits (datasheet values) from the public product comparison on paloaltonetworks.com - the only source.

`pan-ngfw-load capacity update` fetches it once into a local CSV (fetch_public). Nothing is built in and nothing is
fetched automatically. Where the public data has no value for a model or an item, the report says so and that item
is not compared against a datasheet value (limits the firewall reports itself are still used).
"""

from __future__ import annotations

import csv
import json
import re
import urllib.request
from datetime import date
from functools import lru_cache
from pathlib import Path

PUBLIC_DIR = "~/.config/pan-ngfw-load/capacity"
PUBLIC_FILE = "public-product-comparison.csv"
PUBLIC_SOURCE = "paloaltonetworks.com product comparison"
PUBLIC_DATA_URL = ("https://www.paloaltonetworks.com/apps/pan/public/solr/proxy?corename=productcompare&q=*:*"
                   "&fq=language:%22en_US%22&rows=500&start=0&wt=json")
PUBLIC_FEATURES_URL = "https://www.paloaltonetworks.com/apps/productcompare/getfeatures?lang=en_US"

# field id of the public product comparison -> metric
PUBLIC_FIELDS = {
    "5-0-6-1_dfi": "fw_appmix_gbps", "5-0-8-1_dfi": "threat_appmix_gbps", "5-0-10-1_dfi": "ipsec_gbps",
    "5-0-11-1_dfi": "cps", "14-0-15-1_dfi": "sessions", "18-0-19-1_dfi": "nat_rules", "18-0-20-1_dfi": "security_rules",
    "18-0-22-1_dfi": "decryption_rules", "18-0-23-1_dfi": "app_override_rules", "18-0-25-1_dfi": "sdwan_rules",
    "18-0-26-1_dfi": "pbf_rules", "18-0-28-1_dfi": "dos_rules", "30-0-31-1_dfi": "zones",
    "33-0-34-1_dfi": "address_objects", "33-0-35-1_dfi": "address_groups", "33-0-36-1_dfi": "address_group_members",
    "33-0-37-1_dfi": "service_objects", "33-0-38-1_dfi": "service_groups", "33-0-40-1_dfi": "fqdn_objects",
    "33-0-41-1_dfi": "dag_ips", "44-0-45-1_dfi": "security_profiles", "52-0-53-1_dfi": "userid_mappings_mp",
    "52-0-54-1_dfi": "userid_mappings_dp", "52-0-55-1_dfi": "userid_groups", "52-0-58-1_dfi": "userid_servers",
    "61-0-62-1_dfi": "ssl_inbound_certs", "61-0-64-1_dfi": "ssl_decrypt_sessions",
    "69-0-70-1_dfi": "url_custom_entries", "69-0-71-1_dfi": "url_custom_categories", "76-0-77-1_dfi": "edl_lists",
    "76-0-78-1_dfi": "edl_ips", "76-0-79-1_dfi": "edl_domains", "76-0-80-1_dfi": "edl_urls",
    "83-0-102-1_dfi": "vlan_tags", "83-0-103-1_dfi": "vlan_tags_per_port", "83-0-104-1_dfi": "interfaces",
    "83-0-105-1_dfi": "aggregates", "117-0-118-1_dfi": "virtual_routers", "123-0-125-1_dfi": "vsys",
    "127-0-130-1_dfi": "fib_v4", "127-0-131-1_dfi": "fib_v6", "127-0-132-1_dfi": "fib_total",
    "127-0-133-1_dfi": "routing_peers", "127-0-135-1_dfi": "bfd_sessions", "137-0-138-1_dfi": "arp_entries",
    "137-0-139-1_dfi": "ndp_entries", "137-0-140-1_dfi": "mac_entries", "158-0-163-1_dfi": "cluster_devices",
    "166-0-167-1_dfi": "qos_rules", "173-0-174-1_dfi": "ike_peers", "173-0-175-1_dfi": "ipsec_tunnels",
    "178-0-179-1_dfi": "gp_users", "184-0-186-1_dfi": "multicast_routes_v4",
}

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


def parse_value(raw: str) -> tuple[float | None, str]:
    """'14.0 Gbps' / '1.5 Tbps' / '145,000' / '512K' / '16000 (PAN-123)' -> (number, unit); text -> (None, '')."""
    s = (raw or "").strip().replace("\u00a0", " ")
    m = re.fullmatch(r"([\d.,]+)\s*(tbps|gbps|mbps)", s, re.I)
    if m:
        return float(m.group(1).replace(",", "")) * {"tbps": 1000, "gbps": 1, "mbps": 0.001}[m.group(2).lower()], "gbps"
    m = re.fullmatch(r"([\d.,]+)\s*([kKmM])?\+?(?:\s*\(PAN-\d+\))?", s)
    if m and re.search(r"\d", m.group(1)):
        try:
            return float(m.group(1).replace(",", "")) * {"k": 1e3, "m": 1e6}.get((m.group(2) or "").lower(), 1), ""
        except ValueError:
            return None, ""
    return None, ""


def _get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "pan-ngfw-load (+https://github.com/dogbyter/pan-ngfw-load)"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", errors="replace")


COLUMNS = ["model", "metric", "value", "unit", "panos_version", "text", "source", "listed"]


def fetch_public(dest_dir: str = PUBLIC_DIR) -> tuple[Path, int, int, list[str]]:
    """Download the public product comparison and merge it into the local file.
    The page drops models once they reach end of sale / end of life - their last known values stay in the file,
    marked 'no longer listed since <date>'. Values the page still has are replaced; values a listed model lost are
    kept the same way. The previous file is kept as <file>.prev.
    -> (file, models on the page, values on the page, models kept from earlier retrievals)."""
    raw = _get(PUBLIC_DATA_URL)
    docs = json.loads(raw[raw.index("{"):].rstrip().rstrip(";"))["response"]["docs"]
    try:
        labels = {f["value"]: f["text"].split(" (")[0] for f in json.loads(_get(PUBLIC_FEATURES_URL))}
    except (ValueError, OSError, KeyError):
        labels = {}
    today = f"{date.today():%Y-%m-%d}"
    src = f"{PUBLIC_SOURCE}, retrieved {today}"
    rows = []
    for d in docs:
        model = (d.get("product_name") or "").strip()
        for field, raw_val in d.items():
            if not field.endswith("_dfi") or not isinstance(raw_val, str) or not raw_val.strip():
                continue
            if "FACET" in labels.get(field, ""):
                continue  # filter ranges of the web page, not values
            metric = PUBLIC_FIELDS.get(field) or "other:" + re.sub(r"[^a-z0-9]+", "_", labels.get(field, field).lower()).strip("_")
            val, unit = parse_value(raw_val)
            if metric.endswith("_gbps") and val is not None:
                unit = "gbps"
            rows.append([model, metric, "" if val is None else f"{val:g}", unit, "",
                         "" if val is not None else raw_val.strip(), src, "yes"])
    if not rows:
        raise ValueError("the product comparison returned no data - the existing file was left unchanged")
    out = Path(dest_dir).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    f = out / PUBLIC_FILE
    # keep what the page no longer shows
    on_page = {r[0] for r in rows}
    fresh = {(r[0], r[1]) for r in rows}
    kept_models = set()
    if f.exists():
        with open(f, newline="", encoding="utf-8") as fh:
            for old in csv.DictReader(fh):
                key = (old.get("model", ""), old.get("metric", ""))
                if key in fresh or not key[0]:
                    continue
                listed = old.get("listed") or "yes"
                if listed == "yes":
                    listed = f"no longer listed since {today}"
                rows.append([old.get(c) or "" for c in COLUMNS[:-1]] + [listed])
                if key[0] not in on_page:
                    kept_models.add(key[0])
    tmp = f.with_suffix(".tmp")
    with open(tmp, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(COLUMNS)
        w.writerows(sorted(rows, key=lambda r: (r[0], r[1])))
    if f.exists():
        f.replace(f.with_suffix(f.suffix + ".prev"))
    tmp.replace(f)
    _load.cache_clear()
    return f, len(on_page), sum(1 for r in rows if r[2] and r[7] == "yes"), sorted(kept_models)


def public_file(settings: dict) -> Path:
    return Path(settings.get("capacity_dir") or PUBLIC_DIR).expanduser() / PUBLIC_FILE


@lru_cache(maxsize=4)
def _load(path: str, mtime: float) -> tuple[tuple, ...]:
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            rows.append((r.get("model", "").strip(), r.get("metric", "").strip(), r.get("value", "").strip(),
                         r.get("text", "").strip(), (r.get("source") or "").strip(), (r.get("listed") or "yes").strip()))
    return tuple(rows)


def load(settings: dict) -> tuple[tuple, ...]:
    f = public_file(settings)
    if not f.exists():
        return ()
    return _load(str(f), f.stat().st_mtime)


def limits(settings: dict, model: str) -> tuple[dict, dict, str, str]:
    """Public datasheet values for one model.
    -> ({metric: value}, {metric: note}, source description, status 'ok' | 'no_data' | 'no_model')."""
    rows = load(settings)
    if not rows:
        return {}, {}, "", "no_data"
    mine = [r for r in rows if r[0].lower() == (model or "").lower()]
    if not mine:
        return {}, {}, rows[0][4], "no_model"
    vals, notes = {}, {}
    for _m, metric, value, text, _src, _listed in mine:
        if value:
            try:
                vals[metric] = float(value)
            except ValueError:
                pass
        if text:
            notes[metric] = text
    # source text: newest retrieval for this model; say so when the page no longer lists the model
    srcs = sorted({r[4] for r in mine})
    desc = srcs[-1]
    gone = sorted({r[5] for r in mine if r[5] != "yes"})
    if gone and all(r[5] != "yes" for r in mine):
        desc += f" - the model is {gone[0]} there (end of sale/life); these are its last published values"
    elif gone:
        desc += "; some values are from an earlier retrieval because the page no longer shows them"
    return vals, notes, desc, "ok"


def missing(vals: dict, keys) -> list[str]:
    """Labels of the given metrics that have no public value."""
    return [METRICS[k][0] for k in keys if k in METRICS and k not in vals]


def hint(model: str, status: str, missing_labels: list[str]) -> str:
    """One sentence for the report about what the public data doesn't cover."""
    if status == "no_data":
        return ("The public product comparison has not been fetched on this computer (run 'pan-ngfw-load capacity "
                "update'), so only limits the firewall reports itself are compared.")
    if status == "no_model":
        return (f"The {model} is not in the public product comparison, so only limits the firewall reports itself "
                "are compared.")
    if missing_labels:
        return ("No public value for: " + ", ".join(missing_labels) + " - these items are shown without a "
                "datasheet limit.")
    return ""
