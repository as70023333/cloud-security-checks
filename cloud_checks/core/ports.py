"""Which network ports matter when a firewall rule is open to the whole internet."""

from __future__ import annotations

import ipaddress

# Remote administration: the classic brute-force and exploit targets.
ADMIN_PORTS: dict[int, str] = {22: "SSH", 3389: "RDP"}

# Services that should never face the internet directly.
SENSITIVE_PORTS: dict[int, str] = {
    21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB", 1433: "SQL Server", 1521: "Oracle",
    2375: "Docker API", 2379: "etcd", 3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
    5985: "WinRM", 5986: "WinRM", 6379: "Redis", 6443: "Kubernetes API", 9200: "Elasticsearch",
    10250: "Kubelet", 11211: "Memcached", 27017: "MongoDB",
}

ALL_PORTS = (0, 65535)
ANY_IPV4 = "0.0.0.0/0"
ANY_IPV6 = "::/0"


def is_internet(cidr: str) -> bool:
    """True for 0.0.0.0/0, ::/0 and the wildcard spellings the three clouds use."""
    value = (cidr or "").strip().lower()
    if value in ("*", "any", "internet"):
        return True
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return network.prefixlen == 0


def parse_port_range(value: object) -> tuple[int, int] | None:
    """'22' -> (22, 22); '1000-2000' -> (1000, 2000); '*' or '' -> all ports; invalid -> None."""
    if value is None:
        return ALL_PORTS
    text = str(value).strip()
    if text in ("", "*", "all", "any", "-1"):
        return ALL_PORTS
    low, sep, high = text.partition("-")
    try:
        start = int(low)
        end = int(high) if sep else start
    except ValueError:
        return None
    if start > end or start < 0 or end > 65535:
        return None
    return start, end


def is_all_ports(start: int, end: int) -> bool:
    return start <= 1 and end >= 65535


def matched(ports: dict[int, str], start: int, end: int) -> list[str]:
    """Names of the listed ports that fall inside start..end, e.g. ['SSH (22)']."""
    return [f"{name} ({port})" for port, name in sorted(ports.items()) if start <= port <= end]


def exposure(protocol: str, start: int | None, end: int | None) -> dict[str, object]:
    """What a rule open to the internet exposes: {'all': bool, 'admin': [...], 'sensitive': [...]}.

    Only TCP, UDP and "all protocols" rules expose ports; ICMP and others return nothing.
    """
    proto = (protocol or "").lower()
    if proto in ("all", "*", "-1", "any"):
        if start is None or end is None or is_all_ports(start, end):
            return {"all": True, "admin": [], "sensitive": []}
    elif proto not in ("tcp", "udp", "6", "17"):
        return {"all": False, "admin": [], "sensitive": []}
    if start is None or end is None:
        start, end = ALL_PORTS
    if is_all_ports(start, end):
        return {"all": True, "admin": [], "sensitive": []}
    return {"all": False, "admin": matched(ADMIN_PORTS, start, end), "sensitive": matched(SENSITIVE_PORTS, start, end)}
