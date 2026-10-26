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


def global_counters(text: str, block: int = 0) -> tuple[float | None, pd.DataFrame]:
    """'show counter global' -> (elapsed_s, DataFrame[name, value, rate]) of the n-th block."""
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
            blocks.append((elapsed, pd.DataFrame(cur, columns=["name", "value", "rate"])))
            cur, in_tbl = None, False
            continue
        toks = s.split()
        if len(toks) == 3 and toks[1].isdigit():
            cur.append((toks[0], float(toks[1]), float(toks[2])))
        elif len(toks) >= 3 and toks[1].isdigit():  # detailed format with severity/category
            cur.append((toks[0], float(toks[1]), float(toks[2]) if toks[2].isdigit() else float("nan")))
    if not blocks or block >= len(blocks):
        return None, pd.DataFrame(columns=["name", "value", "rate"])
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
               "packets received": "rx_pkts", "packets transmitted": "tx_pkts"}


def interface_counters(text: str) -> pd.DataFrame:
    """'show counter interface all' -> bytes/packets since boot per interface (the dataplane's
    'read from CPU' values; the first block of each interface)."""
    rows, cur = {}, None
    for line in text.splitlines():
        if (m := re.match(r"^Interface: (\S+)", line)):
            cur = rows.setdefault(m.group(1), {"interface": m.group(1)})
            continue
        m = re.match(r"^(bytes received|bytes transmitted|packets received|packets transmitted)\s+(\d+)\s*$", line)
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
