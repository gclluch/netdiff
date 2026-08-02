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

# The port scan is flat - every (ip, port) at once rather than a pool of devices
# each walking its own list - so `--ports top100` costs one timeout rather than
# a hundred of them per device. Same reasoning as SCAN_WORKERS, more of it.
PORT_WORKERS = 256

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

# The ports worth checking when you only want to know a device is alive and
# roughly what it is. Deliberately small: this is the default because most runs
# are a change check, not an inventory, and every port added here reports itself
# as `port-opened` on everyone's next scan.
DEFAULT_PORTS = (22, 80, 443, 445, 554, 1883, 3389, 5000, 8080, 8443)

# nmap's top 100 TCP ports, in numeric order. Not a guess - it is the published
# frequency ranking from internet-wide scanning, which is exactly the question
# "which ports are worth the timeout" already answered by someone with data.
# fmt: off
TOP_100_PORTS = (
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
    6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
    32768, 49152, 49153, 49154, 49155, 49156, 49157
)
# fmt: on

PORT_SETS = {"default": DEFAULT_PORTS, "top100": TOP_100_PORTS}


def resolve_ports(values) -> tuple[int, ...]:
    """Turn what someone typed after `--ports` into port numbers.

    Accepts a set name or a list of numbers, and mixing them, because
    `--ports top100 32400` is the obvious thing to want and refusing it would
    only be pedantry.
    """
    ports = set()
    for value in values:
        text = str(value)
        if text in PORT_SETS:
            ports.update(PORT_SETS[text])
            continue
        if not text.isdigit() or not 0 < int(text) < 65536:
            known = ", ".join(sorted(PORT_SETS))
            raise ValueError(f"{text!r} is not a port number or a set ({known})")
        ports.add(int(text))
    return tuple(sorted(ports))


# A packet's TTL is set by the sender and decremented per hop; on one broadcast
# segment there are no hops, so what arrives is what the OS started with. These
# are the three common starting values, and only an exact match earns a name -
# a TTL of 32 is not "nearly 64", it is a device doing something else, and
# rounding it into the nearest family would be a confident sentence about
# nothing. Even an exact match is a hint: any of these can be reconfigured.
TTL_ORIGINS = {64: "Linux, macOS or BSD", 128: "Windows", 255: "network gear"}

_TTL = re.compile(r"ttl[=\s](\d+)", re.I)


@dataclass(frozen=True)
class Device:
    """One device as observed in a single scan."""

    mac: str
    ip: str
    vendor: str = ""
    hostname: str = ""
    services: str = ""
    ports: tuple[int, ...] = field(default=())
    os_hint: str = ""

    def key(self) -> str:
        """Identity across scans.

        The MAC is the identity, not the IP: a device that gets a new DHCP
        lease is the same device, and reporting it as "one left, one arrived"
        would bury the actual signal.
        """
        return self.mac


# The address and mask of the interface we would actually use, in the three
# shapes the usual commands print them: `ip -o -4 addr` gives a CIDR, macOS
# ifconfig gives a hex mask, Linux ifconfig gives a dotted one.
_INET_CIDR = re.compile(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)")
_MASK_HEX = re.compile(r"netmask\s+0x([0-9a-fA-F]{8})")
_MASK_DOTTED = re.compile(r"netmask\s+(\d+\.\d+\.\d+\.\d+)")


def local_address() -> str:
    """Our own address on the network we would actually route through.

    A UDP socket that is `connect`ed sends nothing - the kernel just picks the
    route and binds a source address, which is exactly the question being asked.
    The destination is TEST-NET-1, which is reserved and routed nowhere, so this
    stays true even if it were ever to send.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("192.0.2.1", NUDGE_PORT))
        return sock.getsockname()[0]


def _prefix_length(text: str, ip: str):
    """Mask width for `ip`, from whichever command's output this is."""
    for line in text.splitlines():
        if ip not in line:
            continue
        cidr = _INET_CIDR.search(line)
        if cidr and cidr.group(1) == ip:
            return int(cidr.group(2))
        hexmask = _MASK_HEX.search(line)
        if hexmask:
            return bin(int(hexmask.group(1), 16)).count("1")
        dotted = _MASK_DOTTED.search(line)
        if dotted:
            return sum(bin(int(o)).count("1") for o in dotted.group(1).split("."))
    return None


def local_subnet(runner=subprocess.run) -> str:
    """The CIDR of the network this machine is on.

    So that walking into somewhere new and running `netdiff scan` works without
    first having to go and read your own IP settings. Guessing /24 would be right
    most of the time, which is exactly the kind of nearly-true this tool refuses
    elsewhere - if the mask cannot be read, say so and ask for one.
    """
    ip = local_address()
    for cmd in (["ip", "-o", "-4", "addr"], ["ifconfig"]):
        try:
            proc = runner(cmd, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0 and proc.stdout:
            prefix = _prefix_length(proc.stdout, ip)
            if prefix:
                return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    raise ValueError(
        f"could not work out the subnet for {ip} - pass one explicitly, "
        f"e.g. netdiff scan {ip.rsplit('.', 1)[0]}.0/24"
    )


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


def _port_open(ip: str, port: int, timeout: float = 0.3) -> bool:
    """TCP connect. Open means the handshake completed, nothing more."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


def scan_ports_many(pairs, timeout: float = 0.3) -> set:
    """Every (ip, port) at once; returns the pairs that are open.

    Flat rather than a pool of devices each walking its own port list. With ten
    ports the difference was academic; with `top100` a device that drops packets
    would otherwise cost a hundred consecutive timeouts, and the scan would take
    the length of the port list rather than the length of one timeout.
    """
    pairs = list(pairs)
    if not pairs:
        return set()
    with ThreadPoolExecutor(max_workers=min(PORT_WORKERS, len(pairs))) as pool:
        results = pool.map(lambda pair: _port_open(*pair, timeout=timeout), pairs)
        return {pair for pair, is_open in zip(pairs, results) if is_open}


def scan_ports(ip: str, ports, timeout: float = 0.3) -> tuple[int, ...]:
    """The open ports of one device."""
    found = scan_ports_many([(ip, port) for port in ports], timeout=timeout)
    return tuple(sorted(port for _, port in found))


def os_family(ttl: int) -> str:
    """The OS family a starting TTL suggests, phrased as the guess it is.

    An unrecognised TTL is reported as the number alone. It is still an
    observation worth keeping - two devices with the same odd TTL are probably
    the same kind of thing - but it is not a family, so it does not get a name.
    """
    if not 0 < ttl <= 255:
        return ""
    name = TTL_ORIGINS.get(ttl)
    return f"{name}? (TTL {ttl})" if name else f"TTL {ttl}"


def ttl_hint(ip: str, runner=subprocess.run) -> str:
    """OS family guessed from the TTL of one ping reply, or '' if it did not answer.

    This is the only honest OS detection available without root: real
    fingerprinting needs crafted packets and a raw socket. A TTL narrows it to a
    family and nothing more, so the output says "Windows?" and quotes the number
    it inferred that from. A device that drops ICMP - plenty of IoT gear does -
    simply has no hint, which is the normal case rather than an error.
    """
    try:
        proc = runner(
            ["ping", "-c", "1", ip], capture_output=True, text=True, timeout=3
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    match = _TTL.search(proc.stdout or "")
    return os_family(int(match.group(1))) if match else ""


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

    open_ports: dict[str, list[int]] = {}
    for ip, port in scan_ports_many([(ip, p) for ip in in_subnet for p in ports]):
        open_ports.setdefault(ip, []).append(port)

    def observe(item):
        ip, mac = item
        return Device(
            mac=mac,
            ip=ip,
            vendor=lookup_vendor(mac) if lookup_vendor else "",
            hostname=resolve_hostname(ip) if resolve_names else "",
            services=(services or {}).get(ip, ""),
            ports=tuple(sorted(open_ports.get(ip, ()))),
            os_hint=ttl_hint(ip),
        )

    # Reverse DNS and the ping are both waits, not work, and neither depends on
    # any other device. Sequentially the scan took the sum of every timeout on
    # the network; concurrently it takes the worst single device.
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        devices = list(pool.map(observe, in_subnet.items()))
    return sorted(devices, key=lambda d: ipaddress.ip_address(d.ip))
