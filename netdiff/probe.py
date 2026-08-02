"""Ask four specific questions of a service that a port number cannot answer.

`scan.py` finds out what is here and which ports accept a connection.
`audit.py` decides what that means. This module is the layer between: it speaks
just enough of TLS, SMB, DNS and SSH to turn "port 445 is open" into "this
server accepted the 1996 version of SMB", which is a different kind of claim.

Every probe here obeys the same contract as the rest of the tool. It sends the
opening move of a protocol and reads the reply that any client would get. It
sends no credentials, writes nothing a server would store, and asks for nothing
beyond what the handshake volunteers before authentication happens at all.

The parsers are separated from the sockets on purpose - `parse_certificate`,
`parse_smb_negotiate`, `parse_kexinit` and `parse_dns_reply` are pure functions
over bytes, so the fiddly part is tested against captured shapes rather than
against a live host that happens to be on this desk today.
"""

from __future__ import annotations

import socket
import ssl
import struct
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .mdns import encode_name
from .scan import SCAN_WORKERS

# ---------------------------------------------------------------- TLS

# Ports where a TLS handshake is the expected greeting. Any other open port that
# stayed silent when spoken to is also tried, because silence is what a TLS port
# sounds like to a plaintext banner grab.
TLS_PORTS = (443, 465, 563, 636, 853, 989, 990, 993, 995, 8443, 8883, 9443)


@dataclass(frozen=True)
class Certificate:
    """The three things about a certificate that can be judged without a CA."""

    subject: str
    issuer: str
    not_before: str
    not_after: str

    @property
    def self_signed(self) -> bool:
        return bool(self.subject) and self.subject == self.issuer


# A DER certificate is nested TLV. Rather than carry an ASN.1 parser for the two
# fields that matter, both are found by their shape:
#
#   validity - the first SEQUENCE holding two adjacent time values. Times appear
#   nowhere else in the structure before it, and the sequence is short enough
#   that its length is always a single byte.
#
#   commonName - the OID 2.5.4.3 followed by its string. Issuer precedes subject
#   in a certificate, so the first two are the issuer's and the subject's.
#
# ponytail: shape-matching, not parsing. It reads the two fields nothing else
# can produce; it cannot read a third. Wanting key size or the SAN list is the
# day to write the real walker.
_UTC_TIME, _GENERALIZED_TIME = 0x17, 0x18
_TIME_LENGTHS = {_UTC_TIME: 13, _GENERALIZED_TIME: 15}
_CN_OID = b"\x06\x03\x55\x04\x03"
_STRING_TAGS = (0x0C, 0x13, 0x14, 0x16, 0x1E)


def _read_time(der: bytes, at: int):
    """(iso date, offset after it) if a time value starts at `at`, else None."""
    if at + 2 > len(der):
        return None
    tag, length = der[at], der[at + 1]
    if _TIME_LENGTHS.get(tag) != length or at + 2 + length > len(der):
        return None
    text = der[at + 2 : at + 2 + length].decode("ascii", "replace")
    if not text[:-1].isdigit():
        return None
    if tag == _UTC_TIME:
        # RFC 5280: a two-digit year below 50 means the 2000s.
        year = int(text[:2])
        year += 2000 if year < 50 else 1900
        rest = text[2:]
    else:
        year, rest = int(text[:4]), text[4:]
    return f"{year:04d}-{rest[0:2]}-{rest[2:4]}", at + 2 + length


def _common_names(der: bytes) -> list[str]:
    names = []
    at = der.find(_CN_OID)
    while at != -1:
        tag, length = der[at + 5 : at + 6], der[at + 6 : at + 7]
        if tag and length and tag[0] in _STRING_TAGS and length[0] < 128:
            start = at + 7
            names.append(der[start : start + length[0]].decode("utf-8", "replace"))
        at = der.find(_CN_OID, at + 5)
    return names


def parse_certificate(der: bytes):
    """Subject, issuer and validity from a DER certificate, or None."""
    validity = None
    for at in range(len(der) - 4):
        if der[at] != 0x30:  # SEQUENCE
            continue
        first = _read_time(der, at + 2)
        second = _read_time(der, first[1]) if first else None
        if second:
            validity = (first[0], second[0])
            break
    if validity is None:
        return None
    names = _common_names(der)
    return Certificate(
        subject=names[1] if len(names) > 1 else "",
        issuer=names[0] if names else "",
        not_before=validity[0],
        not_after=validity[1],
    )


def tls_certificate(ip: str, port: int, timeout: float = 3.0, server_name: str = ""):
    """The certificate a port presents, or None if it does not speak TLS.

    Verification is off deliberately. Nearly every certificate on a home network
    is self-signed and would fail a check against the system trust store, and
    refusing the handshake would mean learning nothing about the most common
    case. The certificate is read and judged on its own contents instead - which
    is also why the DER is parsed here rather than trusting `getpeercert()`, as
    that returns an empty dict for exactly the certificates worth looking at.

    `server_name` is sent as SNI when there is one. A server hosting several
    names on one port refuses a handshake that does not say which was wanted,
    and a reverse-DNS name is the best guess available - it costs nothing when
    wrong, since the name is not checked against the certificate either way.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout) as raw:
            with context.wrap_socket(raw, server_hostname=server_name or None) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError):
        return None
    return parse_certificate(der) if der else None


# ---------------------------------------------------------------- SMB

# An SMB1 NEGOTIATE PROTOCOL request offering exactly one dialect: the one from
# 1996 that WannaCry travelled over. Offering it alone is the whole technique -
# a server that also speaks SMB2 would answer any wider offer with SMB2 and hide
# whether SMB1 is still enabled, so the question has to be asked on its own.
_SMB1_DIALECT = b"NT LM 0.12"
# Exactly 32 bytes, and `parse_smb_negotiate` reads the reply's word count at
# offset 32 on that basis - so SMB_HEADER_SIZE is asserted rather than trusted.
SMB_HEADER_SIZE = 32
_SMB_HEADER = (
    b"\xffSMB"  # 4  protocol id
    b"\x72"  # 1  SMB_COM_NEGOTIATE
    b"\x00\x00\x00\x00"  # 4  status
    b"\x18"  # 1  flags: canonical paths, case sensitive
    b"\x01\x28"  # 2  flags2: long names, extended security
    + b"\x00" * 2  # 2  pid high
    + b"\x00" * 8  # 8  security signature
    + b"\x00\x00"  # 2  reserved
    + b"\x00\x00"  # 2  tree id
    + b"\xff\xfe"  # 2  process id
    + b"\x00\x00"  # 2  user id
    + b"\x00\x00"  # 2  multiplex id
)


def smb1_negotiate_request() -> bytes:
    dialects = b"\x02" + _SMB1_DIALECT + b"\x00"
    body = b"\x00" + struct.pack("<H", len(dialects)) + dialects
    message = _SMB_HEADER + body
    # NetBIOS session service: one zero byte, then a 24-bit length.
    return b"\x00" + len(message).to_bytes(3, "big") + message


def parse_smb_negotiate(data: bytes) -> str:
    """The dialect the server accepted, or '' if it refused SMBv1.

    A server with SMBv1 disabled either drops the connection or answers with
    dialect index 0xFFFF, which is the protocol's way of saying "none of those".
    """
    body = data[4:]
    if not body.startswith(b"\xffSMB") or len(body) < SMB_HEADER_SIZE + 3:
        return ""
    if body[4] != 0x72 or int.from_bytes(body[5:9], "little") != 0:
        return ""
    at = SMB_HEADER_SIZE
    if body[at] == 0:  # word count: an error reply carries no dialect
        return ""
    index = int.from_bytes(body[at + 1 : at + 3], "little")
    return "" if index == 0xFFFF else _SMB1_DIALECT.decode()


def smb_dialect(ip: str, port: int = 445, timeout: float = 3.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(smb1_negotiate_request())
            return parse_smb_negotiate(sock.recv(1024))
    except OSError:
        return ""


# ---------------------------------------------------------------- DNS

# A name reserved by IANA for exactly this: examples and tests. Resolving it
# tells the same story as resolving anything else and leaks nothing about who
# is asking.
DNS_PROBE_NAME = "example.com"
# Fixed rather than random: it only has to match our own reply on a socket we
# connected ourselves. Randomising it would be cargo-culted cache-poisoning
# defence for a query whose answer is thrown away.
_DNS_ID = 0x1D1F


def dns_query(name: str = DNS_PROBE_NAME) -> bytes:
    """One A query with the recursion-desired bit set."""
    header = struct.pack("!HHHHHH", _DNS_ID, 0x0100, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", 1, 1)


def parse_dns_reply(data: bytes) -> str:
    """Evidence that this host resolves internet names for strangers, or ''."""
    if len(data) < 12:
        return ""
    ident, flags, _, answers, _, _ = struct.unpack("!HHHHHH", data[:12])
    if ident != _DNS_ID or not flags & 0x8000:
        return ""
    if flags & 0x000F or not flags & 0x0080 or not answers:
        # rcode must be 0, the recursion-available bit must be set, and there
        # has to be an actual answer. A referral is not recursion.
        return ""
    return (
        f"answered a query for {DNS_PROBE_NAME} with {answers} record(s), "
        f"recursion-available bit set"
    )


def dns_recursion(ip: str, timeout: float = 2.0) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, 53))
            sock.send(dns_query())
            return parse_dns_reply(sock.recv(2048))
    except OSError:
        return ""


# ---------------------------------------------------------------- SSH

_KEXINIT = 20
# A KEXINIT carries ten name-lists: key exchange, host keys, ciphers each way,
# MACs each way, compression each way, languages each way. Only the first six
# are read. Compression is where every server in existence offers `none`, and
# `none` is a real finding in a cipher list and the default in a compression
# one - reading both and forgetting which was which would flag every SSH server
# on earth, which is the failure mode this project is a reaction to.
_KEXINIT_LISTS = 6


def parse_kexinit(data: bytes) -> tuple:
    """The algorithms an SSH server offered to negotiate with.

    Deduplicated: a server offers the same cipher list in both directions, and
    "offers RC4, and also offers RC4" is not two facts.
    """
    if len(data) < 6:
        return ()
    length, padding = int.from_bytes(data[:4], "big"), data[4]
    payload = data[5 : 4 + length]
    if padding:
        payload = payload[:-padding]
    if not payload or payload[0] != _KEXINIT:
        return ()
    at = 1 + 16  # message type, then the cookie
    names = []
    for _ in range(_KEXINIT_LISTS):
        if at + 4 > len(payload):
            break
        size = int.from_bytes(payload[at : at + 4], "big")
        at += 4
        chunk = payload[at : at + size].decode("ascii", "replace")
        at += size
        names.extend(name for name in chunk.split(",") if name)
    return tuple(dict.fromkeys(names))


def ssh_algorithms(ip: str, port: int = 22, timeout: float = 3.0) -> tuple:
    """What an SSH server offers to negotiate with.

    A server sends its KEXINIT unprompted as soon as version strings have been
    swapped, so the entire exchange is: read its banner, send ours, read the
    list. Nothing is attempted against authentication, which matters - a failed
    auth is the usual way of grabbing this and it lands you in the target's log
    and in fail2ban.
    """
    try:
        with socket.create_connection((ip, port), timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(512)
            if not banner.startswith(b"SSH-"):
                return ()
            sock.sendall(b"SSH-2.0-netdiff\r\n")
            return parse_kexinit(sock.recv(8192))
    except OSError:
        return ()


# ---------------------------------------------------------------- collection


def collect(devices, banners=None, workers: int = SCAN_WORKERS) -> dict:
    """Run every applicable probe across the network at once.

    Returns the plain dict `audit()` reads, keyed the same way `banners` is:
    per (ip, port) for the ones that are about a service, per ip for DNS, which
    is asked over UDP of every device because a UDP port never appears in a TCP
    port scan.
    """
    banners = banners or {}
    jobs: list = []

    for device in devices:
        jobs.append(("dns", device.ip, lambda ip=device.ip: dns_recursion(ip)))
        for port in device.ports:
            pair = (device.ip, port)
            if port in TLS_PORTS or not banners.get(pair, "").strip():
                name = device.hostname
                jobs.append(
                    (
                        "certs",
                        pair,
                        lambda p=pair, n=name: tls_certificate(*p, server_name=n),
                    )
                )
            if port == 445:
                jobs.append(("smb", pair, lambda p=pair: smb_dialect(*p)))
            if banners.get(pair, "").startswith("SSH-"):
                jobs.append(("ssh", pair, lambda p=pair: ssh_algorithms(*p)))

    results: dict = {"certs": {}, "smb": {}, "dns": {}, "ssh": {}}
    if not jobs:
        return results
    with ThreadPoolExecutor(max_workers=min(workers, len(jobs))) as pool:
        for (kind, key, _), value in zip(jobs, pool.map(lambda j: j[2](), jobs)):
            if value:
                results[kind][key] = value
    return results
