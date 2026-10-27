"""Domain knowledge: what the pow-performance groups/functions mean.

The mapping of function names to features is inferred from the function names
(PAN-OS does not document them). Edit here when we learn more - every report
section uses these tables.
"""

from __future__ import annotations

import re

# --- top-level work groups -------------------------------------------------
GROUPS = {
    "flow_lookup": ("Established traffic", "Session lookup for arriving packets"),
    "flow_np": ("Established traffic", "Packet receive from the network ports"),
    "flow_fastpath": ("Established traffic", "Packets of existing sessions, incl. App-ID and content inspection"),
    "flow_forwarding": ("Established traffic", "Egress forwarding / packet rewrite"),
    "send_out": ("Established traffic", "Packet transmit"),
    "flow_slowpath": ("New sessions", "First packet of a session: policy, NAT, route lookup, session setup"),
    "flow_ctrl": ("Control & housekeeping", "Timers, session ageing, control messages"),
    "flow_mgmt": ("Control & housekeeping", "Session management"),
    "module_internal": ("Internal messaging", "Messages between DP modules (proxy, cloud DNS/URL replies, ...)"),
    "flow_host": ("Management-plane traffic", "Packets to/from the management plane (host-bound)"),
    "send_host": ("Management-plane traffic", "Transmit to the management plane"),
    "pktlog_forwarding": ("Logging", "Log / packet-capture forwarding to the management plane"),
    "nac_result": ("Offload results", "Results from the NAC engine"),
    "dfa_result": ("Offload results", "Results from the DFA pattern-match engine"),
    "aho_result": ("Offload results", "Results from the Aho-Corasick pattern-match engine"),
    "zip_result": ("Offload results", "Results from the (de)compression engine"),
    "qat_result": ("Offload results", "Results from the QAT crypto engine"),
}

STAGE_ORDER = [
    "Established traffic", "New sessions", "Control & housekeeping", "Internal messaging",
    "Management-plane traffic", "Logging", "Offload results", "Other",
]


def group_stage(name: str) -> str:
    return GROUPS.get(name, ("Other", ""))[0]


def group_desc(name: str) -> str:
    return GROUPS.get(name, ("", ""))[1]


# --- functions -> feature categories ----------------------------------------
# Functions that measure waiting time (latency), not CPU time. Excluded from CPU shares.
NOT_CPU = re.compile(r"latency|^poll_delay")
# Groups that measure waiting for an offload engine, not CPU time: on PA-7500 qat_result accumulates seconds per
# item, more than all DP cores together could work since boot. Left out of every CPU share.
NOT_CPU_GROUPS = {"qat_result"}

FEATURES = [
    ("App-ID & protocol decoders", r"^(appid_|detector_run|sml_vm|cad_appsig|http2_)"),
    ("Threat & content inspection", r"^(ctd_|dfa_match|regex_|reg_expr|hs_|raven_|cad_threatsig|mlav_|ldl_|zip_|brotli_|netinsp|netdec|devid_)"),
    ("Decryption & crypto", r"^(ssl_|rsa_|ecdhe_|ecdsa_|dhe_|eckey_|bn_mod_exp|cipher_|qat_)"),
    ("URL filtering", r"^urlcache_"),
    ("Policy & User-ID", r"^(policy_lookup|user_group_policy|get_gid|userid_)"),
    ("Session lifecycle", r"^session_"),
    ("Internal messaging (mi_*)", r"^mi_"),
    ("Timers & ageing", r"^(tim_check|age_)"),
    ("Tunnels / VPN / SD-WAN", r"^(tunnel_|vpn_|flow_fec|sdwan_|inline_switch)"),
    ("DoS protection", r"^dos_"),
    ("Logging", r"^pktlog_"),
    ("Offload / misc", r"^(offload_|memseg_|module_|stack_trace|receive_pkt|pkt_rewrite|prl_|gtp_|sctp_)"),
]
_FEATURE_RE = [(n, re.compile(p)) for n, p in FEATURES]


def func_feature(name: str) -> str | None:
    """Feature category of a function, or None if it is not CPU time."""
    if NOT_CPU.search(name):
        return None
    for feat, rx in _FEATURE_RE:
        if rx.search(name):
            return feat
    return "Other"


FEATURE_HELP = {
    "App-ID & protocol decoders": "Identifying applications and decoding protocols (sml_vm = decoder VM, detector_run = heuristics).",
    "Threat & content inspection": "Signature / regex / DFA matching for threat prevention, file and data inspection.",
    "Decryption & crypto": "SSL/TLS decryption and key exchange done in software or offloaded (QAT).",
    "URL filtering": "URL cache lookups / updates for URL filtering.",
    "Policy & User-ID": "Security policy lookups, incl. user/group matching.",
    "Session lifecycle": "Installing, ageing and deleting sessions - grows with connections per second.",
    "Internal messaging (mi_*)": "Messages between DP modules, e.g. proxy timers, cloud DNS and URL replies.",
    "Timers & ageing": "Timer wheel checks and ARP/route ageing - mostly fixed background cost.",
}


# --- global counters (show counter global) used to explain load changes -----
COUNTER_HELP = {
    "pkt_recv": "Packets received",
    "pkt_sent": "Packets sent",
    "pkt_runtc_np": "Packets handled by the receive stage",
    "pkt_recv_zero": "Packets received on the default queue",
    "pkt_sent_lo": "Packets sent, low-priority queue",
    "pkt_sent_hi": "Packets sent, high-priority queue",
    "flow_tunnel_ipsec_esp_decap": "IPsec ESP packets decrypted (inbound tunnel traffic)",
    "flow_tunnel_ipsec_esp_encap": "IPsec ESP packets encrypted (outbound tunnel traffic)",
    "flow_tunnel_encap_resolve": "Tunnel lookups for outbound packets",
    "flow_tunnel_encap_resolve_mt": "Tunnel lookups for outbound packets",
    "flow_tunnel_cache_resolve": "Tunnel cache lookups",
    "flow_ip_cksm_sw_validation": "IP checksums checked in software",
    "flow_tcp_cksm_sw_validation": "TCP checksums checked in software",
    "flow_udp_cksm_sw_validation": "UDP checksums checked in software",
    "session_allocated": "New sessions",
    "session_installed": "New sessions installed",
    "session_freed": "Sessions closed",
    "ha_msg_sent": "HA messages sent to the peer",
    "ha_session_update_msg_sent": "HA session updates sent to the peer",
    "ha_ipsec_update_msg_sent": "HA IPsec sequence-number updates sent",
    "ctd_pkt_slowpath": "Packets inspected by content inspection (slow path)",
    "appid_proc": "Packets processed by App-ID",
    "flow_ipfrag_recv": "IP fragments received",
    "flow_gre_tunnel_decap": "GRE packets decapsulated",
    "flow_policy_deny": "Packets denied by policy",
    "flow_dos_drop": "Packets dropped by DoS protection",
}


def counter_desc(name: str) -> str:
    if name in COUNTER_HELP:
        return COUNTER_HELP[name]
    if name.startswith("pkt_recv_qos"):
        return "Packets received on QoS class " + name.rsplit("_", 1)[-1]
    return ""


FUNC_HELP = {
    "tunnel_decap": "IPsec decryption (tunnel decapsulation)",
    "tunnel_esp_decap": "IPsec ESP decryption",
    "tunnel_encap": "IPsec encryption (tunnel encapsulation)",
    "tunnel_esp": "IPsec ESP encryption",
    "tunnel_fwd": "Forwarding into a tunnel",
    "tim_check": "Timer checks",
    "sml_vm": "App-ID / protocol decoder",
    "ctd_token": "Content inspection tokenizer",
    "session_ager": "Session ageing",
}


# --- dataplane resources (show running resource-monitor, "Resource utilization") ---------
# What the counters mean, in plain words. PAN-OS doesn't document them in detail; the texts
# describe how they behave and what a high value means in practice.
RESOURCES = {
    "packet buffer": (
        "Packet buffers",
        "Memory that holds the content of packets while the dataplane works on them - from arrival until they "
        "are sent or dropped. The value is the share of the buffer pool in use.",
        "High values mean packets arrive faster than the cores finish them, or are held back (reassembly, "
        "inspection, a slow egress port). At 100% new packets are dropped. Packet Buffer Protection (zone setting) "
        "can drop the sessions that hog buffers before that happens.",
    ),
    "packet descriptor": (
        "Packet descriptors",
        "Small bookkeeping entries, one per packet in flight, that point to the buffer and carry the packet's "
        "metadata. Each packet needs one, whatever its size.",
        "Many small packets (VoIP, DNS, floods) use descriptors faster than buffers. If descriptors run out, "
        "packets are dropped even with buffers left.",
    ),
    "sw tags descriptor": (
        "Software tag descriptors",
        "Work items waiting in the dataplane's software scheduler. Packets of one session carry the same tag so "
        "they are processed in order; the descriptors track this queued work.",
        "High values mean work piles up faster than the cores take it: traffic bursts, or many packets of a few "
        "large sessions that have to be handled one after another. Short peaks are normal; sustained high values "
        "go along with latency and, at the limit, drops.",
    ),
    "session": (
        "Session table",
        "Share of the session table in use: allocated sessions compared with the maximum this model supports.",
        "When it is full, new connections fail. Long timeouts, scans and floods (many half-open sessions) fill it "
        "faster than real traffic does.",
    ),
}

# Counters that show a resource ran out (shown with the resource section when non-zero)
RESOURCE_COUNTERS = re.compile(
    r"^(pkt_alloc_failure|flow_dos_pbp_\w+|flow_session_alloc_fail\w*|session_alloc_fail\w*|"
    r"\w*_buf\w*_alloc_failure|\w*(desc|descriptor)\w*(fail|drop|full)\w*|flow_rcv_\w*nobuf\w*)$")
# Lost logs (health section)
LOG_LOSS_COUNTERS = re.compile(r"^log_\w*loss\w*$")


# --- management-plane processes (names as shown by 'top', may be cut at 9 characters + '+') -----
# Meaning inferred from the process names and common PAN-OS knowledge.
PROCESSES = {
    "pan_task": "Dataplane worker threads (on platforms where DP and MP share the CPU)",
    "pan_logdb": "Log database: stores and indexes logs on the local disk",
    "pan_logdb_index": "Log database indexing",
    "pan_reportd": "Report generation (scheduled and on-demand reports, ACC)",
    "genindex": "Builds search indexes for the log database",
    "logrcvr": "Receives logs from the dataplane and writes them to the log database",
    "mgmtsrvr": "Management server: configuration, commits, web UI and API backend",
    "configd": "Configuration daemon",
    "devsrvr": "Device server: URL categories, User-ID group mapping, dynamic lists",
    "useridd": "User-ID daemon: IP-to-user mappings",
    "distributord": "Distributes User-ID and other mappings between processes and devices",
    "identityclient": "Cloud Identity Engine client",
    "authd": "Authentication of admins and users (LDAP, RADIUS, SAML, ...)",
    "sysd": "System daemon: shared state database between processes",
    "brdagent": "Board agent: hardware and dataplane interface monitoring",
    "pan_comm": "Communication between management plane and dataplane",
    "gpsvc": "GlobalProtect service",
    "wifclient": "WildFire client: uploads files for analysis",
    "dnsproxyd": "DNS proxy",
    "routed": "Routing (legacy engine)",
    "sslmgr": "Certificate manager: OCSP/CRL checks",
    "cryptod": "Cryptographic operations (keys, certificates)",
    "ikemgr": "IKE negotiation for IPsec VPNs",
    "keymgr": "IPsec key management",
    "snmpd": "SNMP agent",
    "ntpd": "Time synchronisation",
    "top": "The 'top' command used by mp-monitor itself",
    "kni_single": "Kernel thread passing packets between dataplane and management plane",
    "varrcvr": "Receives files and data from the dataplane (WildFire, data filtering)",
    "md_batch": "Batch jobs of the management daemons",
    "rcs": "Background service on the management plane (exact role undocumented)",
}


def process_desc(name: str) -> str:
    n = name.rstrip("+").rstrip(".")
    if n in PROCESSES:
        return PROCESSES[n]
    for k, v in PROCESSES.items():  # 'top' truncates long names: pan_repor+ -> pan_reportd
        if name.endswith("+") and k.startswith(n):
            return v
    return ""
