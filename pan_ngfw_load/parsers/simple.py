"""Small table parsers: session info, global counters, app statistics, session list, pow status,
interface counters, IPsec tunnel names from the saved config."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd


def _strip(text: str) -> list[str]:
    return [l[1:] if l.startswith(":") else l for l in text.splitlines()]


def session_info(text: str) -> dict[str, float]:
    """'show session info' -> numeric fields (only the first target-dp block)."""
    keys = {
        "Number of sessions supported": "sessions_supported",
        "Number of allocated sessions": "sessions_allocated",
        "Number of active TCP sessions": "sessions_tcp",
        "Number of active UDP sessions": "sessions_udp",
        "Number of active ICMP sessions": "sessions_icmp",
        "Session table utilization": "session_util_pct",
        "Number of sessions created since bootup": "sessions_created_total",
        "Packet rate": "pps",
        "Throughput": "kbps",
        "New connection establish rate": "cps",
    }
    out: dict[str, float] = {}
    for line in _strip(text):
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        if k in keys and keys[k] not in out:
            m = re.search(r"-?\d+(\.\d+)?", v)
            if m:
                out[keys[k]] = float(m.group(0))
    return out


COUNTER_COLS = ["name", "value", "rate", "severity", "category", "aspect", "description"]


def global_counters(text: str, block: int = 0) -> tuple[float | None, pd.DataFrame]:
    """'show counter global' -> (elapsed_s, DataFrame[name, value, rate, severity, category, aspect, description])
    of the n-th block. Short format (name value rate) leaves the extra columns empty."""
    blocks, cur, elapsed, in_tbl = [], None, None, False
    for line in _strip(text):
        s = line.strip()
        if s.startswith("Global counters"):
            cur, elapsed, in_tbl = [], None, False
            continue
        if cur is None:
            continue
        m = re.match(r"Elapsed time since last sampling: ([\d.]+)", s)
        if m:
            elapsed = float(m.group(1))
            continue
        if s.startswith("name") and "value" in s:
            in_tbl = True
            continue
        if not in_tbl or s.startswith("---"):
            continue
        if s.startswith("Total counters shown"):
            blocks.append((elapsed, pd.DataFrame(cur, columns=COUNTER_COLS)))
            cur, in_tbl = None, False
            continue
        toks = s.split(None, 6)
        if len(toks) >= 3 and toks[1].isdigit():
            rate = float(toks[2]) if toks[2].isdigit() else float("nan")
            extra = (toks[3:] + ["", "", "", ""])[:4] if len(toks) > 3 else ["", "", "", ""]
            cur.append((toks[0], float(toks[1]), rate, *extra))
    if not blocks or block >= len(blocks):
        return None, pd.DataFrame(columns=COUNTER_COLS)
    return blocks[block]


def app_statistics(text: str) -> pd.DataFrame:
    """'show running application statistics' -> DataFrame[vsys, app, sessions, packets, bytes, app_changed, threats]."""
    rows, vsys = [], None
    for line in text.splitlines():
        m = re.match(r"Vsys: (\S+)", line)
        if m:
            vsys = m.group(1)
            continue
        m = re.match(r"^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", line)
        if m and m.group(1) != "Total":
            rows.append([vsys, m.group(1), *(int(x) for x in m.groups()[1:])])
    return pd.DataFrame(rows, columns=["vsys", "app", "sessions", "packets", "bytes", "app_changed", "threats"])


SESS_RE = re.compile(
    r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:([A-Z]+)\s+)?([^\s\[]+)\[(\d+)\]/(\S+)/(\d+)\s+\((\S+)\[(\d+)\]\)"
)
SESS2_RE = re.compile(r"^(\S+)\s+(\S+)\[(\d+)\]/(\S+)\s+\((\S+)\[(\d+)\]\)")


def session_list(text: str) -> pd.DataFrame:
    """'show session all' -> one row per session."""
    rows, pending = [], None
    for line in text.splitlines():
        m = SESS_RE.match(line)
        if m:
            g = m.groups()
            pending = dict(id=int(g[0]), app=g[1], state=g[2], type=g[3], flag=g[4], src=g[5],
                           sport=int(g[6]), from_zone=g[7], proto=int(g[8]), xsrc=g[9])
            continue
        m = SESS2_RE.match(line)
        if m and pending:
            g = m.groups()
            pending.update(vsys=g[0], dst=g[1], dport=int(g[2]), to_zone=g[3], xdst=g[4])
            rows.append(pending)
            pending = None
    return pd.DataFrame(rows)


POW_THREAD_RE = re.compile(r"^thread (\d+) rcv_tot (\d+)")
POW_IO_RE = re.compile(r"^io: rcv num (\d+)")
POW_GRP_RE = re.compile(r"^grp: (.*)$")


def pow_status(text: str) -> pd.DataFrame:
    """'debug dataplane pow status' -> per worker thread (= DP core): work items received (rcv_tot),
    packets taken from the port receive queues (io_rcv) and the work groups it serves - all since boot."""
    rows, cur, grp = [], None, ""
    for line in text.splitlines():
        line = line.strip()
        if (m := POW_GRP_RE.match(line)):
            grp = m.group(1).strip()
        elif (m := POW_THREAD_RE.match(line)):
            cur = dict(core=int(m.group(1)), rcv_tot=int(m.group(2)), io_rcv=None, groups=grp)
            rows.append(cur)
        elif (m := POW_IO_RE.match(line)) and cur is not None and cur["io_rcv"] is None:
            cur["io_rcv"] = int(m.group(1))
    return pd.DataFrame(rows, columns=["core", "rcv_tot", "io_rcv", "groups"])


IF_COUNTERS = {"bytes received": "rx_bytes", "bytes transmitted": "tx_bytes",
               "packets received": "rx_pkts", "packets transmitted": "tx_pkts",
               "receive errors": "rx_errors", "receive discarded": "rx_discards", "packets dropped": "drops",
               "packets dropped by flow state check": "flow_state_drops", "forwarding errors": "fwd_errors",
               "no route": "no_route", "arp not found": "arp_not_found", "neighbor not found": "neighbor_not_found",
               "mac not found": "mac_not_found"}


def interface_counters(text: str) -> pd.DataFrame:
    """'show counter interface all' -> bytes/packets since boot per interface (the dataplane's
    'read from CPU' values; the first block of each interface)."""
    rows, cur = {}, None
    for line in text.splitlines():
        if (m := re.match(r"^Interface: (\S+)", line)):
            cur = rows.setdefault(m.group(1), {"interface": m.group(1)})
            continue
        m = re.match(r"^(" + "|".join(re.escape(k) for k in IF_COUNTERS) + r")\s+(\d+)\s*$", line)
        if m and cur is not None and IF_COUNTERS[m.group(1)] not in cur:
            cur[IF_COUNTERS[m.group(1)]] = int(m.group(2))
    return pd.DataFrame(list(rows.values()), columns=["interface", *IF_COUNTERS.values()])


def ipsec_tunnels(config_xml: Path) -> pd.DataFrame:
    """Saved running config -> tunnel interface, IPsec tunnel name and peer address."""
    try:
        root = ET.parse(config_xml).getroot()
    except (OSError, ET.ParseError):
        return pd.DataFrame(columns=["interface", "ipsec_tunnel", "peer"])
    addr = {}  # peer addresses may be address objects
    for a in root.iter("address"):
        for e in a.findall("entry"):
            v = e.findtext("ip-netmask") or e.findtext("fqdn")
            if v:
                addr[e.get("name")] = v.removesuffix("/32")
    peers = {}
    for gw in root.iter("gateway"):
        for e in gw.findall("entry"):
            ip = e.findtext("peer-address/ip") or e.findtext("peer-address/fqdn") or ""
            peers[e.get("name")] = addr.get(ip, ip)
    rows = []
    for ipsec in root.iter("ipsec"):
        for e in ipsec.findall("entry"):
            ti = e.findtext("tunnel-interface")
            if not ti:
                continue
            gws = [g.get("name") for g in e.findall("auto-key/ike-gateway/entry")]
            rows.append(dict(interface=ti, ipsec_tunnel=e.get("name"), peer=", ".join(peers.get(g, "") for g in gws)))
    return pd.DataFrame(rows, columns=["interface", "ipsec_tunnel", "peer"]).drop_duplicates("interface")


def interface_hw(text: str) -> pd.DataFrame:
    """'show interface all' hardware table -> interface, speed (Mbit/s), duplex, state."""
    rows = []
    for line in text.splitlines():
        m = re.match(r"^(ethernet\S+|ae\d+)\s+\d+\s+(\S+/\S+)\s", line)
        if m:
            parts = m.group(2).split("/")  # speed/duplex/state[/fec]
            if len(parts) >= 3:
                rows.append(dict(interface=m.group(1), speed=float(parts[0]) if parts[0].isdigit() else float("nan"),
                                 duplex=parts[1], state=parts[2].split("(")[0]))
    return pd.DataFrame(rows, columns=["interface", "speed", "duplex", "state"]).drop_duplicates("interface")


def ha_status(text: str) -> pd.DataFrame:
    """'show high-availability all' -> key/value rows (enabled, mode, local/peer state, sync, links)."""
    if "HA not enabled" in text:
        return pd.DataFrame([("enabled", "no")], columns=["key", "value"])
    rows, section, link = [("enabled", "yes")], "", ""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Local Information"):
            section = "local"
        elif s.startswith("Peer Information"):
            section = "peer"
        elif s.startswith(("Configuration Synchronization", "Link Monitoring", "Path Monitoring")):
            section = ""
        if (m := re.match(r"^(HA\d[\w ]*?) (?:Link|Control Link) Information", s)):
            link = m.group(1)
        if (m := re.match(r"^Mode: (.+)$", s)) and not any(k == "mode" for k, _ in rows):
            rows.append(("mode", m.group(1)))
        elif (m := re.match(r"^State: (.+)$", s)) and section:
            rows.append((f"{section} state", m.group(1)))
        elif (m := re.match(r"^Priority: (\d+)", s)) and section:
            rows.append((f"{section} priority", m.group(1)))
        elif (m := re.match(r"^State Synchronization: (.+)$", s)):
            rows.append(("state synchronization", m.group(1)))
        elif (m := re.match(r"^Running Configuration: (.+)$", s)):
            rows.append(("running configuration", m.group(1)))
        elif (m := re.match(r"^Link State: (\w+)", s)) and section == "local" and link:
            rows.append((f"{link} link", m.group(1)))
        elif (m := re.match(r"^Build Release: (.+)$", s)) and section:
            rows.append((f"{section} software", m.group(1)))
    return pd.DataFrame(rows, columns=["key", "value"]).drop_duplicates("key")


def environmentals(text: str) -> pd.DataFrame:
    """'show system environmentals' -> kind (thermal/fan/power), description, alarm, value, min, max."""
    rows, kind = [], ""
    for line in text.splitlines():
        if (m := re.match(r"^-+(\w+)-+$", line.strip())):
            kind = m.group(1).lower()
            continue
        m = re.match(r"^\s*S\d+\s+(.+?)\s+(True|False)\s+([\d.]+)\s+([\d.]+)(?:\s+([\d.]+))?\s*$", line)
        if m and kind:
            rows.append(dict(kind=kind, description=m.group(1), alarm=m.group(2) == "True", value=float(m.group(3)),
                             min=float(m.group(4)), max=float(m.group(5)) if m.group(5) else float("nan")))
    return pd.DataFrame(rows, columns=["kind", "description", "alarm", "value", "min", "max"])


def disk_space(text: str) -> pd.DataFrame:
    """'show system disk-space' (df -h) -> mount, size, used, avail, use_pct."""
    rows = []
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%\s+(/\S*)\s*$", line)
        if m and m.group(1) not in ("none", "cgroup_root"):
            rows.append(dict(filesystem=m.group(1), mount=m.group(6), size=m.group(2), used=m.group(3),
                             avail=m.group(4), use_pct=float(m.group(5))))
    return pd.DataFrame(rows, columns=["filesystem", "mount", "size", "used", "avail", "use_pct"])


def software_status(text: str) -> pd.DataFrame:
    """'show system software status' -> type (Group/Process), name, state."""
    rows = []
    for line in text.splitlines():
        m = re.match(r"^(Group|Process)\s+(\S+)\s+(\S+)", line)
        if m:
            rows.append(dict(type=m.group(1), name=m.group(2), state=m.group(3)))
    return pd.DataFrame(rows, columns=["type", "name", "state"])


def crashinfo(files: list[Path]) -> pd.DataFrame:
    """Crash summaries in opt/panlogs/cores/crashinfo -> process, time, PAN-OS version."""
    rows = []
    for f in files:
        if not f.is_file():
            continue
        try:
            head = f.read_text(encoding="utf-8", errors="replace")[:4000]
        except OSError:
            continue
        m = re.search(r"Process (\S+): \w+, (\d+ \w+ \d{4} [\d:]+)", head)
        when = pd.to_datetime(m.group(2), format="%d %b %Y %H:%M:%S", errors="coerce") if m else pd.NaT
        v = re.search(r"cfg\.panos\.version: (\S+)", head)
        rows.append(dict(process=m.group(1) if m else f.name.split("-")[0], time=when,
                         version=v.group(1) if v else ""))
    return pd.DataFrame(rows, columns=["process", "time", "version"])


def vpn_flow(text: str) -> pd.DataFrame:
    """'show vpn flow' -> tunnel id, name, state, local, peer."""
    rows = []
    for line in text.splitlines():
        m = re.match(r"^(\d+)\s+(\S+)\s+(active|init|inactive|down|\w+)\s+(on|off)\s+(\S+)\s+(\S+)", line)
        if m:
            rows.append(dict(tunnel_id=int(m.group(1)), name=m.group(2), state=m.group(3), local=m.group(5),
                             peer=m.group(6)))
    return pd.DataFrame(rows, columns=["tunnel_id", "name", "state", "local", "peer"])


def ipsec_sa(text: str) -> pd.DataFrame:
    """'show vpn ipsec-sa' -> tunnel id and algorithm (e.g. ESP/A256/SHA256, ESP/G256)."""
    rows = []
    for line in text.splitlines():
        m = re.match(r"^\S+\s+(\d+)\s+\S+\s+\S+\s+(ESP/\S+|AH/\S+)", line)
        if m:
            rows.append(dict(tunnel_id=int(m.group(1)), algorithm=m.group(2)))
    return pd.DataFrame(rows, columns=["tunnel_id", "algorithm"]).drop_duplicates("tunnel_id")


def interface_logical(text: str) -> pd.DataFrame:
    """'show interface all' logical table -> interface, zone, router, tag, addresses. Read by column position
    (router names contain spaces); continuation lines add more addresses. Zone names are cut at 16 characters
    by PAN-OS - see interface_zones() for the full names."""
    rows, cols, cur = [], None, None
    for line in text.splitlines():
        if line.startswith("name") and " forwarding " in line and " tag " in line:
            hdr = line
            cols = {k: hdr.index(k) for k in ("id", "vsys", "zone", "forwarding", "tag", "address")}
            continue
        if cols is None or line.startswith("---") or not line.strip():
            continue
        if line.startswith("total configured") or line.startswith("name "):
            cols = None
            continue
        if line[0] != " ":
            name = line[:cols["id"]].strip()
            cut = lambda a, b: line[cols[a]:cols[b] if b else None].strip()
            cur = dict(interface=name, zone=cut("zone", "forwarding"), router=cut("forwarding", "tag"),
                       tag=cut("tag", "address"), address=cut("address", None))
            rows.append(cur)
        elif cur is not None and line.strip():
            cur["address"] = (cur["address"] + ", " + line.strip()).strip(", ")
    df = pd.DataFrame(rows, columns=["interface", "zone", "router", "tag", "address"])
    df["router"] = df.router.str.replace(r"^vr:", "", regex=True)
    df["address"] = df.address.replace({"N/A": ""})
    return df.drop_duplicates("interface")


def interface_zones(config_xml: Path) -> dict[str, str]:
    """Saved running config -> {interface: zone} with the full zone names."""
    try:
        root = ET.parse(config_xml).getroot()
    except (OSError, ET.ParseError):
        return {}
    out = {}
    for zones in root.iter("zone"):
        for z in zones.findall("entry"):
            for m in z.iterfind("network/*/member"):
                if m.text:
                    out[m.text] = z.get("name")
    return out


def ae_members(config_xml: Path) -> dict[str, str]:
    """Saved running config -> {physical port: aggregate group}."""
    try:
        root = ET.parse(config_xml).getroot()
    except (OSError, ET.ParseError):
        return {}
    return {e.get("name"): e.findtext("aggregate-group") for e in root.iter("entry")
            if e.get("name", "").startswith("ethernet") and e.findtext("aggregate-group")}


def lacp(text: str) -> pd.DataFrame:
    """'show lacp aggregate-ethernet all' -> per member: ae, interface, bundled, rx/mux/selection state, mode, rate."""
    rows, ae, in_members, mode, rate = [], None, False, "", ""
    for line in text.splitlines():
        s = line.strip()
        if (m := re.match(r"^AE group: (\S+)", s)):
            ae, in_members, mode, rate = m.group(1), False, "", ""
            continue
        if s.startswith("Members:"):
            in_members = True
            continue
        if in_members:
            m = re.match(r"^(ethernet\S+)\s+(yes|no)\s+(\S+)\s+(\S+)\s+(\S+)", s)
            if m:
                rows.append(dict(ae=ae, interface=m.group(1), bundled=m.group(2), rx_state=m.group(3),
                                 mux_state=m.group(4), selection=m.group(5), mode="", rate=""))
                continue
            in_members = False
        if (m := re.match(r"^Mode:\s+(\S+)", s)) and ae:
            for r in rows:
                if r["ae"] == ae:
                    r["mode"] = m.group(1)
        if (m := re.match(r"^Rate:\s+(\S+)", s)) and ae:
            for r in rows:
                if r["ae"] == ae:
                    r["rate"] = m.group(1)
    return pd.DataFrame(rows, columns=["ae", "interface", "bundled", "rx_state", "mux_state", "selection", "mode", "rate"])


def config_file(root: Path) -> Path | None:
    """The configuration to count from: the merged one (local + pushed by Panorama) when the TSF has it."""
    for rel in ("opt/pancfg/mgmt/tmp/panorama_pushed/mergesp.xml", "opt/pancfg/mgmt/saved-configs/running-config.xml"):
        f = root / rel
        if f.exists() and f.stat().st_size > 200:
            return f
    return None


def config_scale(config_xml: Path) -> dict[str, int]:
    """Counts of configured objects and rules (shared + every vsys)."""
    try:
        root = ET.parse(config_xml).getroot()
    except (OSError, ET.ParseError):
        return {}
    scopes = root.findall("shared") + root.findall("devices/entry/vsys/entry")
    n = lambda path: sum(len(s.findall(path)) for s in scopes)
    rb = lambda kind: sum(len(s.findall(f"rulebase/{kind}/rules/entry")) + len(s.findall(f"pre-rulebase/{kind}/rules/entry"))
                          + len(s.findall(f"post-rulebase/{kind}/rules/entry")) for s in scopes)
    net = root.findall("devices/entry/network")
    are = (root.findtext(".//deviceconfig/setting/advance-routing") or "").strip() == "yes"
    return {
        "address_objects": n("address/entry"), "address_groups": n("address-group/entry"),
        "service_objects": n("service/entry"), "service_groups": n("service-group/entry"),
        "edl_lists": n("external-list/entry"), "url_custom_categories": n("profiles/custom-url-category/entry"),
        "zones": n("zone/entry"),
        # only the routers of the active routing engine count (the config can hold both kinds)
        "virtual_routers": sum(len(x.findall("logical-router/entry" if are else "virtual-router/entry")) for x in net),
        "security_rules": rb("security"), "nat_rules": rb("nat"), "decryption_rules": rb("decryption"),
        "pbf_rules": rb("pbf"), "app_override_rules": rb("application-override"), "dos_rules": rb("dos"),
        "qos_rules": rb("qos"),
        "panorama_managed": int(root.find(".//deviceconfig/system/panorama") is not None or _pushed(config_xml)),
    }


def _pushed(config_xml: Path) -> bool:
    """True when the TSF holds configuration actually pushed by Panorama (lastsp.xml is a stub otherwise)."""
    last = config_xml.parent / "lastsp.xml"
    return config_xml.name == "mergesp.xml" and last.exists() and last.stat().st_size > 200


def running_rules(text: str) -> int:
    """'show running security-policy' / nat-policy / ... -> number of rules in effect."""
    return len(re.findall(r'; index: \d+" \{', text))


def table_usage(text: str, kind: str) -> tuple[int | None, int | None]:
    """'show arp all' / 'show neighbor interface all' / 'show mac all' -> (entries in table, maximum supported)."""
    mx = re.search(r"maximum of entries supported\s*:\s*(\d+)", text)
    tot = re.search(rf"total {kind} entries in table\s*:\s*(\d+)", text)
    return (int(tot.group(1)) if tot else None), (int(mx.group(1)) if mx else None)


def fib_usage(text: str) -> tuple[int | None, int | None]:
    """'show routing fib' / 'show advanced-routing fib' -> (fib entries of the device, maximum for the device)."""
    mx = re.search(r"maximum of fib entries for device:\s*(\d+)", text)
    used = re.search(r"number of fib entries for device:\s*(\d+)", text)
    return (int(used.group(1)) if used else None), (int(mx.group(1)) if mx else None)


def total_count(text: str) -> int | None:
    """'Total: 12 users' / 'Total: 0 registered addresses' / 'Total Current Users: 3' -> the number."""
    m = re.search(r"Total(?: Current Users)?:\s*(\d+)", text or "")
    return int(m.group(1)) if m else None
