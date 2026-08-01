"""Discover devices on a local network using only the standard library.

No root, no nmap, no scapy. The trick is that the OS already keeps an ARP
table: sending any packet to an address on the local segment forces the kernel
to resolve its MAC first. So we send a throwaway UDP datagram to every address
in the subnet, wait a moment, then read the ARP cache back.

This sees any device that answers ARP, including ones that drop ICMP and would
be invisible to a ping sweep. It does not see devices on other segments, and a
device that is powered off during the sweep is simply absent - which is the
point, since absence is a change worth reporting.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

# Port 9 is "discard": nothing listens, nothing is harmed, and the kernel still
# has to ARP for the address before it can send.
NUDGE_PORT = 9
ARP_SETTLE_SECONDS = 1.0

# ARP does not cross routers, so a subnet larger than this is not a broadcast
# segment - it is a typo, or someone pointing the tool at 10.0.0.0/8 to see what
# happens. That is 16.7M addresses materialised as strings before a single
# packet moves, so refuse it up front rather than swapping to death.
MAX_HOSTS = 65536

# Concurrency for per-device work. Each worker is blocked on a socket timeout,
# not on the CPU, so the useful number is set by how long we are willing to wait
# rather than by core count.
SCAN_WORKERS = 32

# `arp -an` on macOS/BSD/Linux: "? (192.168.1.1) at ab:cd:ef:12:34:56 on en0"
_ARP_LINE = re.compile(
    r"\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]{11,17})"
)
# `ip neigh` on Linux: "192.168.1.1 dev eth0 lladdr ab:cd:ef:12:34:56 REACHABLE"
_NEIGH_LINE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+(?P<mac>[0-9a-fA-F:]{11,17})"
)

INCOMPLETE = {"incomplete", "(incomplete)"}

# Ports we speak HTTP to rather than waiting for a greeting. Shared with the
# audit rules, which need the same list to know a challenge arrived over
# cleartext rather than TLS.
HTTP_PORTS = (80, 81, 591, 5000, 8000, 8008, 8080, 8081, 8888)


@dataclass(frozen=True)
class Device:
    """One device as observed in a single scan."""

    mac: str
    ip: str
    vendor: str = ""
    hostname: str = ""
    services: str = ""
    ports: tuple[int, ...] = field(default=())

    def key(self) -> str:
        """Identity across scans.

        The MAC is the identity, not the IP: a device that gets a new DHCP
        lease is the same device, and reporting it as "one left, one arrived"
        would bury the actual signal.
        """
        return self.mac


def normalise_mac(mac: str) -> str:
    """Canonical lower-case colon form, zero-padded.

    macOS prints `a:b:c:1:2:3`, Linux prints `0a:0b:0c:01:02:03`. Without
    padding the same device would look like two different devices depending on
    which machine ran the scan.
    """
    parts = mac.strip().lower().split(":")
    if len(parts) != 6:
        return mac.strip().lower()
    return ":".join(p.rjust(2, "0") for p in parts)


def parse_arp_output(text: str) -> dict[str, str]:
    """Map IP -> MAC from `arp -an` or `ip neigh` output."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        if any(token in line.lower() for token in INCOMPLETE):
            continue
        match = _ARP_LINE.search(line) or _NEIGH_LINE.search(line)
        if match:
            found[match.group("ip")] = normalise_mac(match.group("mac"))
    return found


def read_arp_table(runner=subprocess.run) -> dict[str, str]:
    """Read the system ARP cache, trying each known command in turn."""
    for cmd in (["arp", "-an"], ["ip", "neigh"]):
        try:
            proc = runner(cmd, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            table = parse_arp_output(proc.stdout)
            if table:
                return table
    return {}


def nudge(hosts, workers: int = 128) -> None:
    """Provoke ARP resolution for every host by sending it a UDP datagram."""

    def ping_one(ip: str) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.2)
                sock.sendto(b"", (ip, NUDGE_PORT))
        except OSError:
            # Unreachable hosts are the normal case, not an error worth raising.
            pass

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(ping_one, hosts))


def scan_ports(ip: str, ports, timeout: float = 0.3) -> tuple[int, ...]:
    """TCP connect scan. Open means the handshake completed, nothing more."""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except OSError:
            continue
    return tuple(sorted(open_ports))


def grab_banners(pairs, timeout: float = 2.0) -> dict:
    """Banner for each (ip, port), gathered concurrently.

    Sequentially this is the slowest thing the audit does: every port that is
    open but silent - a TLS port never greets - costs the full timeout, one
    after another.
    """
    pairs = list(pairs)
    if not pairs:
        return {}
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        banners = pool.map(lambda pair: grab_banner(*pair, timeout=timeout), pairs)
        return dict(zip(pairs, banners))


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Read what a service volunteers about itself.

    Most plaintext protocols greet you before they authenticate you, so
    connecting and listening is the whole technique. HTTP is the exception - it
    says nothing until asked - so we send HEAD, which requests headers and no
    body and is the smallest thing we can ask for.

    This never sends credentials and never writes anything a server would
    store. A banner is what the service tells everyone who connects.
    """
    probe = b"HEAD / HTTP/1.0\r\n\r\n" if port in HTTP_PORTS else b""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) != 0:
                return ""
            if probe:
                sock.sendall(probe)
            return sock.recv(2048).decode("utf-8", "replace").strip()
    except OSError:
        return ""


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def discover(
    subnet: str,
    ports=(),
    lookup_vendor=None,
    settle: float = ARP_SETTLE_SECONDS,
    resolve_names: bool = True,
    services=None,
) -> list[Device]:
    """Scan `subnet` (CIDR) and return the devices found, sorted by IP.

    `services` is an optional IP -> description map from `mdns.discover()`,
    collected by the caller. Passing it in rather than gathering it here keeps
    this module to the one discovery technique it is about, and keeps the map a
    plain dict that a test can hand over without a socket.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    if network.num_addresses > MAX_HOSTS:
        raise ValueError(
            f"{subnet} holds {network.num_addresses} addresses; "
            f"netdiff scans one broadcast segment, up to {MAX_HOSTS}"
        )
    hosts = [str(h) for h in network.hosts()]
    nudge(hosts)
    time.sleep(settle)

    table = read_arp_table()
    in_subnet = {
        ip: mac for ip, mac in table.items() if ipaddress.ip_address(ip) in network
    }

    def observe(item):
        ip, mac = item
        return Device(
            mac=mac,
            ip=ip,
            vendor=lookup_vendor(mac) if lookup_vendor else "",
            hostname=resolve_hostname(ip) if resolve_names else "",
            services=(services or {}).get(ip, ""),
            ports=scan_ports(ip, ports) if ports else (),
        )

    # Reverse DNS and the port scan are both waits, not work, and neither depends
    # on any other device. Sequentially the scan took the sum of every timeout on
    # the network; concurrently it takes the worst single device.
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        devices = list(pool.map(observe, in_subnet.items()))
    return sorted(devices, key=lambda d: ipaddress.ip_address(d.ip))
