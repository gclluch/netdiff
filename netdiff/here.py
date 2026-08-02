"""What this network does to you, rather than what is on it.

Every other command in netdiff asks *what is here*. On a cafe or hotel network
that is the wrong question and an impolite one: those are not your devices, and
the README's scope section rules out scanning them. So this inverts it. Not
*what is on this network* but *what does this network do to me* - does it read
my TLS, does it lie about DNS, does its ARP add up, and which of my own ports
answer from where I am sitting. Every question is about you or about the
infrastructure you were handed; none is about the stranger at the next table.
The one thing that touches other people's devices is the empty datagram that
provokes ARP, which `scan` already sends and which asks nothing of them.

The same split as everywhere else: this module opens the sockets and parses the
bytes, `audit.py` decides what any of it means. `observe()` returns a plain dict
and the rules are pure functions over it, so every one of them is tested without
a network - which matters more here than anywhere, because the interesting cases
are hostile networks that are difficult to arrange on purpose.

Read-only, same as the rest. What this sends, in full: one DNS query for a name
under `.invalid`, one for `example.com`, one HTTP GET to `example.com`, one TLS
handshake to `example.com` that is completed and abandoned, the same empty UDP
datagrams `scan` uses to provoke ARP, and TCP handshakes to your own address.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from .mdns import decode_name
from .probe import DNS_ID, dns_query
from .scan import (
    ARP_SETTLE_SECONDS,
    MAX_HOSTS,
    local_address,
    nudge,
    read_arp_table,
    scan_ports,
)

# RFC 2606 reserves `.invalid` so that it can never be registered by anyone. A
# resolver that returns an address for a name underneath it is not resolving,
# it is inventing - there is no lookup that could have produced an answer.
NXDOMAIN_PROBE = "netdiff-does-not-exist.invalid"
NXDOMAIN = 3

# RFC 2606 reserves this one too, for documentation and examples, which is why
# the rest of the tool already uses it. It has a stable public address and no
# reason to redirect anybody, so anything other than a plain answer is the
# network talking rather than the host.
PUBLIC_PROBE = "example.com"

# A MAC holding this many addresses on one segment is worth mentioning. Two is
# ordinary - a router with a second address, a bridged VM, a host with an alias.
# Three starts to look like something answering ARP for addresses it does not
# own, which is what reading someone else's traffic requires.
SUSPICIOUS_CLAIMS = 3

# Long enough for a captive portal or an interfering middlebox to answer, short
# enough that a network with no internet at all does not hang the command. Every
# probe runs concurrently, so this is the cost of the slowest one, not the sum.
PROBE_TIMEOUT = 5.0


# ---------------------------------------------------------------- the network's own settings


# `netstat -rn -f inet`: "default   192.168.1.1  UGScg  en0"
# `ip route`:            "default via 192.168.1.1 dev eth0 ..."
_DEFAULT_ROUTE = re.compile(r"^default\s+(?:via\s+)?(\d+\.\d+\.\d+\.\d+)")
# `/etc/resolv.conf` and `scutil --dns` disagree on everything except this.
_NAMESERVER = re.compile(r"nameserver(?:\[\d+\])?\s*:?\s+(\d+\.\d+\.\d+\.\d+)")


def default_gateway(runner=subprocess.run) -> str:
    """The router this network told us to send everything through, or ''.

    Same `runner` seam as `scan.local_subnet`, for the same reason: the parsing
    is the part that can be wrong, and it is only testable if the command is
    something a test can hand over.
    """
    for cmd in (["netstat", "-rn", "-f", "inet"], ["ip", "route"]):
        try:
            proc = runner(cmd, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode != 0 or not proc.stdout:
            continue
        for line in proc.stdout.splitlines():
            match = _DEFAULT_ROUTE.match(line.strip())
            if match:
                return match.group(1)
    return ""


def system_resolvers(runner=subprocess.run, path="/etc/resolv.conf") -> tuple:
    """Every resolver this machine is currently configured to ask.

    Which one you use is handed to you by the network over DHCP unless you have
    overridden it, so on someone else's wifi this is *their* resolver by
    default - which is the whole reason it is worth asking questions of.

    macOS keeps its real configuration in `scutil --dns` and leaves
    `/etc/resolv.conf` as a note saying so, so both are read and the results
    merged. Order is preserved and duplicates dropped.
    """
    found = []
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        text = ""
    for line in text.splitlines():
        if line.strip().startswith("nameserver"):
            match = _NAMESERVER.search(line)
            if match:
                found.append(match.group(1))
    try:
        proc = runner(["scutil", "--dns"], capture_output=True, text=True, timeout=10)
        if proc.returncode == 0 and proc.stdout:
            found.extend(_NAMESERVER.findall(proc.stdout))
    except (OSError, subprocess.SubprocessError):
        pass
    return tuple(dict.fromkeys(found))


# ---------------------------------------------------------------- DNS


def parse_dns_answers(data: bytes):
    """(rcode, addresses) from a reply to our query, or None if it is not one.

    Pure over bytes, like the parsers in `probe.py` and for the same reason: a
    resolver that lies is the case worth testing and it is not one you can
    arrange on a desk. Names in the answer section may be compressed, so
    `mdns.decode_name` walks them - it already refuses pointer loops.
    """
    if len(data) < 12:
        return None
    ident, flags, questions, answers, _, _ = struct.unpack("!HHHHHH", data[:12])
    if ident != DNS_ID or not flags & 0x8000:
        return None
    offset = 12
    for _ in range(questions):
        _, offset = decode_name(data, offset)
        offset += 4
    addresses = []
    for _ in range(answers):
        if offset >= len(data):
            break
        _, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlen > len(data):
            # The record claims to be longer than the packet carrying it, so the
            # slice would come back short and a truncated address still parses.
            break
        if rtype == 1 and rdlen == 4:
            addresses.append(".".join(str(b) for b in data[offset : offset + rdlen]))
        offset += rdlen
    return flags & 0x000F, tuple(addresses)


def dns_answers(resolver: str, name: str, timeout: float = PROBE_TIMEOUT):
    """Ask one resolver for one name. None if it did not answer at all."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((resolver, 53))
            sock.send(dns_query(name))
            return parse_dns_answers(sock.recv(2048))
    except OSError:
        return None


def is_private(address: str) -> bool:
    """Would an answer of this address mean the network kept you inside it?

    `0.0.0.0` and `127.0.0.1` are the two answers that look private and are not
    a redirection: both are how a filtering resolver says *no*, and every
    school, guest and pi-hole network uses one of them. Steering you somewhere
    and refusing to answer are opposite acts, and calling a block "the network
    is collecting your credentials" would be the worst false positive here.

    `is_private` already covers loopback and link-local, so those need no clause
    of their own - only the two exclusions do.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if parsed.is_unspecified or parsed.is_loopback:
        return False
    return parsed.is_private


# ---------------------------------------------------------------- HTTP and TLS


_STATUS = re.compile(r"^HTTP/\d\.\d\s+(\d{3})")


def parse_http_head(head: str):
    """(status, location) from the head of a response, or None if it is not one."""
    lines = head.splitlines()
    if not lines:
        return None
    match = _STATUS.match(lines[0].strip())
    if not match:
        return None
    location = ""
    for line in lines[1:]:
        if line.lower().startswith("location:"):
            location = line.split(":", 1)[1].strip()
            break
    return int(match.group(1)), location


def http_get(host: str, port: int = 80, timeout: float = PROBE_TIMEOUT):
    """Ask a known host for its front page, following nothing.

    Redirects are refused by construction rather than by configuration - there
    is no code here that could follow one - which is the same property
    `upnp._NoRedirect` buys the other HTTP path in this project. The point is
    the redirect itself: it is the answer, not something in the way of one.
    """
    request = (
        f"GET / HTTP/1.1\r\nHost: {host}\r\n"
        "User-Agent: netdiff\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )
    try:
        with socket.create_connection((host, port), timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request.encode("ascii"))
            return parse_http_head(sock.recv(2048).decode("utf-8", "replace"))
    except OSError:
        return None


def tls_verified(host: str, port: int = 443, timeout: float = PROBE_TIMEOUT):
    """'' if the certificate verified, the reason if it did not, None if unreachable.

    Verification is left **on**, which is the exact opposite of
    `probe.tls_certificate` and for the opposite reason. There, a failed check is
    the ordinary case and refusing the handshake would mean learning nothing.
    Here it is the finding: this is a public host with a certificate from a
    public authority, and the only thing between you and it is the network.

    Only a verification failure counts. A connection that never completed means
    no internet, and a TLS error that is not about the certificate means a
    middlebox or a bad link - neither is evidence of interception, and saying so
    anyway would be the confident-sentence-about-nothing failure this project
    exists as a reaction to.

    A machine with no trust store is the same failure wearing a disguise, and it
    is the one that would have shipped. `unable to get local issuer certificate`
    is byte-for-byte what an interception CA produces *and* what a python.org
    build whose `Install Certificates.command` was never run produces on every
    network it will ever join. An empty store is a fact about this computer, so
    the question is unanswerable here rather than answered wrongly.
    """
    context = ssl.create_default_context()
    if not context.cert_store_stats()["x509_ca"]:
        return None
    try:
        with socket.create_connection((host, port), timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return ""
    except ssl.SSLCertVerificationError as exc:
        return exc.verify_message or str(exc.reason)
    except (ssl.SSLError, OSError):
        return None


# ---------------------------------------------------------------- collection


def observe(
    subnet: str, ports=(), runner=subprocess.run, timeout=PROBE_TIMEOUT
) -> dict:
    """Everything `netdiff here` looks at, gathered into plain data.

    Interpretation happens in `audit.here_findings`, which opens no socket. The
    probes run concurrently because each one is a wait rather than work, and on
    a network with no internet at all every one of them costs its full timeout -
    serially that is a minute of dead air for a command you run while standing
    up.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    if network.num_addresses > MAX_HOSTS:
        # Same guard as `scan.discover`, and it has to be repeated rather than
        # inherited because this reaches `nudge` by a different route.
        raise ValueError(
            f"{subnet} holds {network.num_addresses} addresses; "
            f"netdiff scans one broadcast segment, up to {MAX_HOSTS}"
        )
    us = local_address()
    gateway = default_gateway(runner)
    resolvers = system_resolvers(runner) or ((gateway,) if gateway else ())

    # The two addresses in a subnet that are not devices. macOS caches the
    # broadcast address as ff:ff:ff:ff:ff:ff after any broadcast traffic, and
    # counting that as a neighbour turns "this network isolates its clients"
    # into "1 device is reachable from here" - a flipped verdict, not a stray row.
    edges = {str(network.network_address), str(network.broadcast_address)}

    def sweep():
        nudge([str(host) for host in network.hosts()])
        time.sleep(ARP_SETTLE_SECONDS)
        table = read_arp_table()
        return {
            ip: mac
            for ip, mac in table.items()
            if ip not in edges and ipaddress.ip_address(ip) in network
        }

    jobs = {
        "neighbours": sweep,
        "own_ports": lambda: scan_ports(us, ports),
        "tls": lambda: tls_verified(PUBLIC_PROBE, timeout=timeout),
        "http": lambda: http_get(PUBLIC_PROBE, timeout=timeout),
        "nxdomain": lambda: {
            r: dns_answers(r, NXDOMAIN_PROBE, timeout=timeout) for r in resolvers
        },
        "public_name": lambda: {
            r: dns_answers(r, PUBLIC_PROBE, timeout=timeout) for r in resolvers
        },
    }
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        values = dict(zip(jobs, pool.map(lambda job: job(), jobs.values())))

    # What was asked travels with the answers. The rules render the name and the
    # threshold into their findings, and a report that says "a name under
    # .invalid resolved" without naming which one is not evidence of anything.
    return dict(
        values,
        us=us,
        gateway=gateway,
        resolvers=resolvers,
        subnet=subnet,
        host=PUBLIC_PROBE,
        invalid_name=NXDOMAIN_PROBE,
        arp_threshold=SUSPICIOUS_CLAIMS,
    )
