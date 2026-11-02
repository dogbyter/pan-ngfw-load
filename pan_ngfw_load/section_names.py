"""Section names for -s/--sections and their titles - kept light (no imports), so the help can list them without
loading the report code. sections/__init__.py checks that it matches SECTIONS."""

NAMES = {
    "coverage": "Data coverage - how far back can we look?",
    "dp_load": "Dataplane CPU load",
    "core_spikes": "Core spikes - single DP cores above the rest",
    "dp_resources": "Dataplane resources - buffers, descriptors, session table",
    "drops": "Drops and errors",
    "dp_breakdown": "What consumes dataplane CPU",
    "traffic": "Traffic that drives the load",
    "interfaces": "Interfaces",
    "vpn": "IPsec VPN",
    "decryption": "TLS and Decryption",
    "sessions": "Sessions",
    "capacity": "Capacity - how much headroom is left",
    "scale": "Configuration against model limits",
    "mp": "Management plane - CPU, processes, memory",
    "health": "Health and stability",
    "logs": "Traffic logs - who generates the load (live reports only)",
    "method": "Appendix - method and caveats",
}
UNLISTED = {"cluster", "dp_compare"}  # accepted, not in the help


def parse(value: str) -> list[str]:
    """'-s a,b' -> ['a', 'b']; raises ValueError naming the unknown ones."""
    names = [n.strip() for n in value.split(",") if n.strip()]
    unknown = [n for n in names if n not in NAMES and n not in UNLISTED]
    if unknown or not names:
        raise ValueError(f"unknown section(s): {', '.join(unknown) or '(none given)'} - known: {', '.join(NAMES)}")
    return list(dict.fromkeys(names))


def help_text() -> str:
    w = max(map(len, NAMES))
    return "sections for -s/--sections (comma-separated):\n" + "\n".join(f"  {k:<{w}}  {t}" for k, t in NAMES.items())
