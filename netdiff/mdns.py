"""Ask the network what each device calls itself.

A MAC vendor tells you who *made* a thing - "Espressif" covers a smart plug, a
doorbell and a hobby project equally. What you actually want to know is what the
thing *is*, and most consumer hardware will simply tell you: Chromecasts,
printers, Sonos, HomeKit gear and Apple devices all announce their services over
multicast DNS, unprompted, to anyone on the segment.

That makes the identification evidence rather than inference. The alternative -
guessing device types from open port numbers - is what the tool this replaced
did, and it produced "Managed Web Server" for a printer.

Read-only: this asks the standard DNS-SD question every phone on the network
asks continuously, and reads the answer.

Joins the multicast group on 5353 where the OS allows it, sharing the port with
the resolver that already owns it (mDNSResponder on macOS, avahi on Linux) via
SO_REUSEPORT. Where that is refused it falls back to an ephemeral port and the
QU unicast-reply bit, which works but sees less: measured on a live network, the
fallback missed a device that answers only to multicast.
"""

from __future__ import annotations

import socket
import struct
import time

MDNS_ADDRESS = ("224.0.0.251", 5353)

# Records we can do something with. AAAA/NSEC are parsed past, not read.
TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_SRV = 33

# The DNS-SD meta-query: "list every service type on this network". Responders
# answer it with PTRs naming their own types, which is how a device we have no
# entry for still shows up as something.
SERVICE_ENUM = "_services._dns-sd._udp.local"

# What a service type means in words. Keyed by the type label as announced.
SERVICE_LABELS = {
    "_googlecast": "Chromecast",
    "_androidtvremote2": "Android TV",
    "_amzn-wplay": "Amazon Fire TV",
    "_roku-rcp": "Roku",
    "_airplay": "AirPlay",
    "_raop": "AirPlay speaker",
    "_mediaremotetv": "Apple TV",
    "_touch-able": "Apple TV",
    "_companion-link": "Apple device",
    "_sleep-proxy": "Apple device",
    "_sonos": "Sonos",
    "_spotify-connect": "Spotify Connect",
    "_hap": "HomeKit accessory",
    "_hue": "Philips Hue bridge",
    "_esphomelib": "ESPHome device",
    "_shelly": "Shelly device",
    "_miio": "Xiaomi device",
    "_ipp": "Printer",
    "_ipps": "Printer",
    "_printer": "Printer",
    "_pdl-datastream": "Printer",
    "_scanner": "Scanner",
    "_uscan": "Scanner",
    "_smb": "File sharing (SMB)",
    "_afpovertcp": "Apple file sharing",
    "_nfs": "File sharing (NFS)",
    "_rfb": "Screen sharing (VNC)",
    "_workstation": "Computer",
    "_ssh": "SSH",
    "_sftp-ssh": "SFTP",
    "_http": "Web interface",
    "_nvstream": "NVIDIA GameStream",
    "_daap": "Music library",
    "_homekit": "HomeKit",
}

# Queried explicitly as well as via SERVICE_ENUM: some responders answer a
# direct question for their own type but ignore the meta-query.
COMMON_SERVICES = (
    "_googlecast._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_hap._tcp.local",
    "_spotify-connect._tcp.local",
    "_sonos._tcp.local",
    "_workstation._tcp.local",
    "_device-info._tcp.local",
    "_smb._tcp.local",
    "_ssh._tcp.local",
    "_http._tcp.local",
    "_esphomelib._tcp.local",
)


def encode_name(name: str) -> bytes:
    """Length-prefixed labels, null terminated."""
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("utf-8")[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def encode_query(names, unicast: bool = True) -> bytes:
    """One DNS query carrying a question per name.

    QCLASS gets the top bit set to ask for a unicast reply, which is what lets
    us listen on an ephemeral port instead of fighting the OS for 5353.
    """
    qclass = 0x8001 if unicast else 0x0001
    header = struct.pack("!HHHHHH", 0, 0, len(names), 0, 0, 0)
    body = b"".join(
        encode_name(n) + struct.pack("!HH", TYPE_PTR, qclass) for n in names
    )
    return header + body


def decode_name(data: bytes, offset: int):
    """Read a possibly compressed name. Returns (name, offset after it).

    Compression pointers can point anywhere, including backwards into a loop, so
    the jump budget is a hard stop rather than a guess.
    """
    labels = []
    jumps = 0
    after = None
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # pointer
            if offset + 1 >= len(data):
                break
            jumps += 1
            if jumps > 32:  # a pointer loop is malformed input, not a name
                break
            if after is None:
                after = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (after if after is not None else offset)


def parse_records(data: bytes):
    """Every resource record in a message, as (name, rtype, rdata) triples.

    Malformed or truncated input yields what was read so far - a device that
    answers badly should cost us one device, not the scan.
    """
    records = []
    try:
        _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    except struct.error:
        return records
    offset = 12
    for _ in range(qd):
        _, offset = decode_name(data, offset)
        offset += 4
    for _ in range(an + ns + ar):
        if offset >= len(data):
            break
        name, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlen > len(data):
            # The record says it is longer than the packet holding it. Slicing
            # would quietly hand back a short buffer, and a 4-byte address
            # truncated to one byte still parses - as the address "192".
            break
        rdata = data[offset : offset + rdlen]
        if rtype in (TYPE_PTR, TYPE_SRV):
            # The target may be compressed, so it has to be read against the
            # whole message rather than the rdata slice alone.
            start = offset + 6 if rtype == TYPE_SRV else offset
            rdata, _ = decode_name(data, start)
        elif rtype == TYPE_TXT:
            rdata = _decode_txt(rdata)
        elif rtype == TYPE_A and rdlen == 4:
            rdata = ".".join(str(b) for b in rdata)
        records.append((name, rtype, rdata))
        offset += rdlen
    return records


def _decode_txt(rdata: bytes) -> dict:
    """TXT rdata is a run of length-prefixed key=value strings."""
    out = {}
    i = 0
    while i < len(rdata):
        length = rdata[i]
        chunk = rdata[i + 1 : i + 1 + length].decode("utf-8", "replace")
        key, _, value = chunk.partition("=")
        if key:
            out[key.lower()] = value
        i += 1 + length
    return out


def service_label(service: str) -> str:
    """'_googlecast._tcp.local' -> 'Chromecast', or '' if we have no word."""
    head = service.lstrip(".").split(".")[0]
    return SERVICE_LABELS.get(head, "")


def describe(records) -> str:
    """Turn one device's records into a short human label.

    Prefers the model the device states outright, then the services it offers.
    """
    model = ""
    services = []
    for name, rtype, rdata in records:
        if rtype == TYPE_TXT and isinstance(rdata, dict):
            model = model or rdata.get("model") or rdata.get("md") or ""
        if rtype == TYPE_PTR:
            # The answer to the meta-query names a type; the answer to a type
            # query names an instance of it. Both identify the device.
            for candidate in (rdata, name):
                word = service_label(candidate)
                if word and word not in services:
                    services.append(word)
    parts = []
    if model:
        parts.append(model)
    parts.extend(s for s in services if s != model)
    return ", ".join(parts[:3])


def discover(timeout: float = 2.5, sender=None) -> dict:
    """Map IP -> short description for everything that answers DNS-SD.

    The datagram's source address is what attributes records to a device: mDNS
    responders answer for themselves, so the sender is the subject.
    """
    if sender is not None:
        replies = sender(timeout)
    else:
        replies = _query(timeout)
    by_ip: dict = {}
    for ip, payload in replies:
        by_ip.setdefault(ip, []).extend(parse_records(payload))
    return {ip: describe(recs) for ip, recs in by_ip.items() if describe(recs)}


def _open_socket():
    """Prefer joining the group on 5353; fall back to an ephemeral port.

    Measured on a live network: joining the group sees devices that the
    ephemeral-port route misses, because a responder that ignores the QU bit
    answers only to multicast. SO_REUSEPORT is what lets us sit on 5353
    alongside the OS resolver that already owns it. Where that is refused - some
    Linux setups, restricted environments - the QU query still works and simply
    finds less, which beats finding nothing.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("", MDNS_ADDRESS[1]))
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            struct.pack("4sL", socket.inet_aton(MDNS_ADDRESS[0]), socket.INADDR_ANY),
        )
        return sock, False
    except OSError:
        sock.close()
        return socket.socket(socket.AF_INET, socket.SOCK_DGRAM), True


def _query(timeout: float):
    """Send the DNS-SD questions and collect raw (ip, payload) replies."""
    replies = []
    try:
        sock, unicast = _open_socket()
        with sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(timeout)
            sock.sendto(
                encode_query((SERVICE_ENUM, *COMMON_SERVICES), unicast=unicast),
                MDNS_ADDRESS,
            )
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(9000)
                except socket.timeout:
                    break
                replies.append((addr[0], data))
    except OSError:
        # No multicast route is a network without mDNS, not an error.
        return []
    return replies
