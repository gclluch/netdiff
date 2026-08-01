"""Ask the router what it forwards from the internet into your LAN.

Most home users assume NAT is a firewall: nothing outside can reach inside
unless they set it up deliberately. UPnP quietly breaks that assumption. Any
device on the LAN - a console, a torrent client, a camera, a compromised smart
bulb - can ask the router to open a hole from the internet straight to itself,
with no prompt and no record anyone ever looks at. The holes outlive the
software that asked for them.

So we ask the router to list them. That is a plain SOAP call the router already
answers for anything on the LAN, which is precisely the problem worth showing.

Read-only by construction: this module calls `GetGenericPortMappingEntry` and
nothing else. There is deliberately no `AddPortMapping` code path here.

Trust boundary: SSDP replies are unauthenticated UDP, so any host on the
segment can forge one and point us at a URL of its choosing. We therefore only
follow a LOCATION whose host is a literal private IP inside the subnet being
audited, and we cap every body we read.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass

SSDP_ADDRESS = ("239.255.255.250", 1900)
IGD_SEARCH_TARGET = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"

# Routers expose the port-mapping table under one of these two, depending on
# whether the WAN link is plain IP or PPPoE. Both answer the same SOAP action.
WAN_SERVICES = (
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)

# The router is not trusted input. Cap every read.
# ponytail: a flat byte cap, not a streaming parser - raise it if some router
# legitimately ships a description larger than this.
MAX_BODY_BYTES = 64 * 1024

# Enumeration ends when the router says "no such index", but a router that
# answers wrongly must not spin us forever.
MAX_MAPPINGS = 128

SSDP_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    f"ST: {IGD_SEARCH_TARGET}\r\n"
    "\r\n"
).encode()

SOAP_BODY = (
    '<?xml version="1.0"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
    ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    "<s:Body>"
    '<u:GetGenericPortMappingEntry xmlns:u="{service}">'
    "<NewPortMappingIndex>{index}</NewPortMappingIndex>"
    "</u:GetGenericPortMappingEntry>"
    "</s:Body></s:Envelope>"
)


@dataclass(frozen=True)
class Mapping:
    """One port forward, as the router reports it."""

    external_port: int
    protocol: str
    internal_client: str
    internal_port: int
    description: str = ""
    enabled: bool = True
    remote_host: str = ""

    def __str__(self) -> str:
        source = self.remote_host or "*"
        label = f" ({self.description})" if self.description else ""
        return (
            f"{source}:{self.external_port}/{self.protocol.lower()}"
            f" -> {self.internal_client}:{self.internal_port}{label}"
        )


@dataclass(frozen=True)
class Gateway:
    """The router's UPnP control endpoint and the forwards it admits to."""

    control_url: str
    service_type: str
    mappings: tuple[Mapping, ...] = ()


def _localname(tag: str) -> str:
    """Strip the XML namespace.

    Vendors disagree about namespaces far more than they disagree about element
    names, so matching on the local name is what actually survives contact with
    real routers.
    """
    return tag.rsplit("}", 1)[-1]


def _to_int(text: str) -> int:
    try:
        return int(text)
    except (TypeError, ValueError):
        return 0


def parse_location(response: str) -> str:
    """Pull the LOCATION header out of an SSDP reply."""
    for line in response.splitlines():
        name, _, value = line.partition(":")
        if name.strip().lower() == "location":
            return value.strip()
    return ""


def is_safe_location(url: str, network) -> bool:
    """Reject a LOCATION we should not fetch.

    Anyone on the LAN can forge an SSDP reply, so an unchecked LOCATION is an
    attacker-chosen URL that we would fetch on their behalf. Requiring a
    literal private address inside the audited subnet keeps that to a host that
    is already on the network and already in the report.
    """
    try:
        host = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # A hostname could resolve anywhere, including off-network. Literal
        # private IPs only.
        return False
    return address.is_private and address in network


def parse_service(description: str, base_url: str):
    """Find the WAN connection service in a device description. Pure."""
    try:
        root = ET.fromstring(description)
    except ET.ParseError:
        return None
    for element in root.iter():
        if _localname(element.tag) != "service":
            continue
        fields = {_localname(c.tag): (c.text or "").strip() for c in element}
        control = fields.get("controlURL", "")
        if fields.get("serviceType") in WAN_SERVICES and control:
            return urllib.parse.urljoin(base_url, control), fields["serviceType"]
    return None


def parse_mapping(response: str):
    """Turn one GetGenericPortMappingEntry response into a Mapping. Pure.

    Returns None for a SOAP fault, which is also how enumeration learns it has
    reached the end of the table.
    """
    try:
        root = ET.fromstring(response)
    except ET.ParseError:
        return None
    fields = {_localname(e.tag): (e.text or "").strip() for e in root.iter()}
    if not fields.get("NewExternalPort") or not fields.get("NewInternalClient"):
        return None
    return Mapping(
        external_port=_to_int(fields["NewExternalPort"]),
        protocol=fields.get("NewProtocol", ""),
        internal_client=fields["NewInternalClient"],
        internal_port=_to_int(fields.get("NewInternalPort", "")),
        description=fields.get("NewPortMappingDescription", ""),
        enabled=fields.get("NewEnabled", "1") != "0",
        remote_host=fields.get("NewRemoteHost", ""),
    )


def ssdp_search(timeout: float = 3.0) -> list[str]:
    """Multicast an M-SEARCH and collect whatever replies before `timeout`."""
    replies = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(timeout)
            sock.sendto(SSDP_SEARCH, SSDP_ADDRESS)
            while True:
                try:
                    data, _ = sock.recvfrom(MAX_BODY_BYTES)
                except socket.timeout:
                    break
                replies.append(data.decode("utf-8", "replace"))
    except OSError:
        # No multicast route, or no router that speaks UPnP. Not an error:
        # a network with no IGD is a network with no UPnP forwards.
        return []
    return replies


def _http_get(url: str, timeout: float) -> str:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.read(MAX_BODY_BYTES).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return ""


def soap_post(control_url: str, service_type: str, index: int, timeout: float) -> str:
    """POST one GetGenericPortMappingEntry. Returns the body, fault or not."""
    action = f"{service_type}#GetGenericPortMappingEntry"
    body = SOAP_BODY.format(service=service_type, index=index).encode()
    request = urllib.request.Request(
        control_url,
        data=body,
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{action}"',
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read(MAX_BODY_BYTES).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        # The end of the table arrives as HTTP 500 carrying a SOAP fault, so
        # the body is the answer rather than the failure.
        return exc.read(MAX_BODY_BYTES).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return ""


def port_mappings(control_url, service_type, timeout=5.0, poster=soap_post):
    """Walk the mapping table until the router runs out of entries."""
    mappings = []
    for index in range(MAX_MAPPINGS):
        mapping = parse_mapping(poster(control_url, service_type, index, timeout))
        if mapping is None:
            break
        mappings.append(mapping)
    return mappings


def probe_gateway(subnet: str, timeout: float = 3.0, search=ssdp_search):
    """Find the IGD on `subnet` and read its port-mapping table.

    Returns None when there is no reachable UPnP gateway, which is a good
    result rather than a failure - a network with no IGD has no UPnP forwards.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    for reply in search(timeout):
        location = parse_location(reply)
        if not location or not is_safe_location(location, network):
            continue
        service = parse_service(_http_get(location, timeout), location)
        if service is None:
            continue
        control_url, service_type = service
        return Gateway(
            control_url=control_url,
            service_type=service_type,
            mappings=tuple(port_mappings(control_url, service_type, timeout)),
        )
    return None
