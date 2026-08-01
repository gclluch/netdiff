"""UPnP parsing and the trust boundary in front of it.

The XML here is shaped like what real routers actually return (MiniUPnPd, which
is what most consumer firmware ships), captured as constants so none of this
needs a network - the same approach as the ARP fixtures in
test_scan_and_store.py.
"""

import http.server
import ipaddress
import threading

from netdiff import upnp

SSDP_REPLY = """HTTP/1.1 200 OK
CACHE-CONTROL: max-age=120
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1
USN: uuid:8bd6a1f1-7cd6-4a41-9f1a-000000000001::urn:schemas-upnp-org:device:InternetGatewayDevice:1
EXT:
SERVER: Linux/3.4.11 UPnP/1.0 MiniUPnPd/1.9
LOCATION: http://192.168.1.1:5000/rootDesc.xml

"""

DESCRIPTION = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <specVersion><major>1</major><minor>0</minor></specVersion>
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <friendlyName>Home Router</friendlyName>
  <deviceList>
   <device>
    <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
    <serviceList>
     <service>
      <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
      <controlURL>/ctl/CommonIfCfg</controlURL>
     </service>
    </serviceList>
    <deviceList>
     <device>
      <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
      <serviceList>
       <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
        <controlURL>/ctl/IPConn</controlURL>
        <eventSubURL>/evt/IPConn</eventSubURL>
        <SCPDURL>/WANIPCn.xml</SCPDURL>
       </service>
      </serviceList>
     </device>
    </deviceList>
   </device>
  </deviceList>
 </device>
</root>
"""

MAPPING_RESPONSE = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
 s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetGenericPortMappingEntryResponse
 xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>32400</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>32400</NewInternalPort>
<NewInternalClient>192.168.1.23</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>Plex Media Server</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:GetGenericPortMappingEntryResponse>
</s:Body></s:Envelope>
"""

# How the router says "that index does not exist" - i.e. the end of the table.
FAULT_713 = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body><s:Fault>
<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>
<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
<errorCode>713</errorCode>
<errorDescription>SpecifiedArrayIndexInvalid</errorDescription>
</UPnPError></detail>
</s:Fault></s:Body></s:Envelope>
"""

NETWORK = ipaddress.ip_network("192.168.1.0/24")


def test_location_is_read_from_the_ssdp_reply():
    assert upnp.parse_location(SSDP_REPLY) == "http://192.168.1.1:5000/rootDesc.xml"


def test_location_header_name_is_case_insensitive():
    assert (
        upnp.parse_location("Location: http://10.0.0.1/d.xml")
        == "http://10.0.0.1/d.xml"
    )


def test_a_reply_without_a_location_yields_empty_string():
    assert upnp.parse_location("HTTP/1.1 200 OK\nST: something\n") == ""


# --- the trust boundary -----------------------------------------------------
# SSDP is unauthenticated UDP: anything on the segment can forge a reply and
# choose the URL we fetch next. These tests are the whole reason that check
# exists.


def test_a_private_address_inside_the_subnet_is_followed():
    assert upnp.is_safe_location("http://192.168.1.1:5000/rootDesc.xml", NETWORK)


def test_a_public_address_is_refused():
    assert not upnp.is_safe_location("http://93.184.216.34/rootDesc.xml", NETWORK)


def test_a_private_address_outside_the_audited_subnet_is_refused():
    assert not upnp.is_safe_location("http://10.9.9.9/rootDesc.xml", NETWORK)


def test_a_hostname_is_refused_because_it_could_resolve_anywhere():
    assert not upnp.is_safe_location("http://evil.example.com/d.xml", NETWORK)
    assert not upnp.is_safe_location("http://localhost/d.xml", NETWORK)


def test_garbage_locations_are_refused_rather_than_raising():
    for url in ("", "not a url", "http://", "file:///etc/passwd"):
        assert not upnp.is_safe_location(url, NETWORK)


# --- description parsing ----------------------------------------------------


def test_the_wan_connection_service_is_found_however_deeply_nested():
    control_url, service_type = upnp.parse_service(
        DESCRIPTION, "http://192.168.1.1:5000/rootDesc.xml"
    )
    assert control_url == "http://192.168.1.1:5000/ctl/IPConn"
    assert service_type == "urn:schemas-upnp-org:service:WANIPConnection:1"


def test_the_wrong_service_is_not_mistaken_for_the_right_one():
    """WANCommonInterfaceConfig appears first and does not serve mappings."""
    control_url, _ = upnp.parse_service(DESCRIPTION, "http://192.168.1.1:5000/d.xml")
    assert "CommonIfCfg" not in control_url


def test_an_absolute_control_url_is_left_alone():
    xml = DESCRIPTION.replace(
        "<controlURL>/ctl/IPConn</controlURL>",
        "<controlURL>http://192.168.1.1:49152/ctl</controlURL>",
    )
    control_url, _ = upnp.parse_service(xml, "http://192.168.1.1:5000/d.xml")
    assert control_url == "http://192.168.1.1:49152/ctl"


def test_a_description_with_no_wan_service_yields_none():
    assert upnp.parse_service("<root><device/></root>", "http://192.168.1.1/") is None


def test_malformed_xml_yields_none_rather_than_raising():
    assert upnp.parse_service("<root><unclosed>", "http://192.168.1.1/") is None
    assert upnp.parse_mapping("}{ not xml at all") is None


def test_an_entity_declaration_does_not_get_expanded():
    """The router is not trusted input; a billion-laughs body must not run."""
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]>'
        "<root><device><serviceList><service>"
        "<serviceType>&a;</serviceType><controlURL>&a;</controlURL>"
        "</service></serviceList></device></root>"
    )
    assert upnp.parse_service(bomb, "http://192.168.1.1/") is None


# --- mapping parsing --------------------------------------------------------


def test_a_port_mapping_is_parsed_in_full():
    m = upnp.parse_mapping(MAPPING_RESPONSE)
    assert m.external_port == 32400
    assert m.internal_client == "192.168.1.23"
    assert m.internal_port == 32400
    assert m.protocol == "TCP"
    assert m.description == "Plex Media Server"
    assert m.enabled is True


def test_a_disabled_mapping_reports_itself_as_disabled():
    m = upnp.parse_mapping(MAPPING_RESPONSE.replace("<NewEnabled>1", "<NewEnabled>0"))
    assert m.enabled is False


def test_a_fault_is_not_a_mapping():
    assert upnp.parse_mapping(FAULT_713) is None


def test_a_mapping_renders_as_the_forward_it_describes():
    assert str(upnp.parse_mapping(MAPPING_RESPONSE)) == (
        "*:32400/tcp -> 192.168.1.23:32400 (Plex Media Server)"
    )


def test_non_numeric_ports_degrade_to_zero_rather_than_raising():
    m = upnp.parse_mapping(
        MAPPING_RESPONSE.replace("<NewInternalPort>32400", "<NewInternalPort>abc")
    )
    assert m.internal_port == 0


# --- enumeration ------------------------------------------------------------


def test_enumeration_stops_at_the_first_fault():
    responses = [MAPPING_RESPONSE, MAPPING_RESPONSE, FAULT_713, MAPPING_RESPONSE]

    def poster(control_url, service_type, index, timeout):
        return responses[index]

    assert len(upnp.port_mappings("http://x/ctl", "svc", poster=poster)) == 2


def test_a_router_that_never_faults_is_still_bounded():
    """A misbehaving router must not spin us forever."""

    def poster(control_url, service_type, index, timeout):
        return MAPPING_RESPONSE

    mappings = upnp.port_mappings("http://x/ctl", "svc", poster=poster)
    assert len(mappings) == upnp.MAX_MAPPINGS


def test_an_unreachable_router_yields_no_mappings():
    def poster(control_url, service_type, index, timeout):
        return ""

    assert upnp.port_mappings("http://x/ctl", "svc", poster=poster) == []


def test_the_soap_action_asks_only_for_the_mapping_table():
    """Read-only contract: there is no AddPortMapping path in this module."""
    source = (upnp.SOAP_BODY + upnp.soap_post.__doc__).lower()
    assert "getgenericportmappingentry" in source
    assert "addportmapping" not in source


# --- end to end against a real socket ---------------------------------------
# The parsers above are tested in isolation; this covers the glue between them,
# which is where the wiring bugs actually live. A throwaway HTTP server on
# loopback stands in for the router - no LAN, no multicast, still real sockets.


ENTRY = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetGenericPortMappingEntryResponse
 xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost><NewExternalPort>{ext}</NewExternalPort>
<NewProtocol>TCP</NewProtocol><NewInternalPort>{internal}</NewInternalPort>
<NewInternalClient>{client}</NewInternalClient><NewEnabled>1</NewEnabled>
<NewPortMappingDescription>{label}</NewPortMappingDescription>
</u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>"""


class _FakeIGD(http.server.BaseHTTPRequestHandler):
    entries = [
        {"ext": 32400, "internal": 32400, "client": "127.0.0.1", "label": "Plex"},
        {"ext": 8080, "internal": 80, "client": "127.0.0.9", "label": "webcam"},
    ]

    def log_message(self, *args):
        pass

    def _send(self, body, code=200):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self._send(DESCRIPTION)

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        index = int(body.split("<NewPortMappingIndex>")[1].split("<")[0])
        if index >= len(self.entries):
            self._send(FAULT_713, 500)  # how a real router ends the table
            return
        self._send(ENTRY.format(**self.entries[index]))


def test_probe_gateway_walks_description_then_soap_over_real_sockets():
    server = http.server.HTTPServer(("127.0.0.1", 0), _FakeIGD)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    reply = f"HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:{port}/rootDesc.xml\r\n\r\n"
    try:
        gateway = upnp.probe_gateway("127.0.0.0/8", search=lambda timeout: [reply])
    finally:
        server.shutdown()

    assert gateway.control_url == f"http://127.0.0.1:{port}/ctl/IPConn"
    assert [m.external_port for m in gateway.mappings] == [32400, 8080]
    assert gateway.mappings[1].internal_client == "127.0.0.9"


def test_probe_gateway_ignores_a_forged_reply_pointing_off_network():
    """The spoofing case, end to end: nothing is fetched, nothing is returned."""
    reply = "HTTP/1.1 200 OK\r\nLOCATION: http://93.184.216.34/rootDesc.xml\r\n\r\n"
    assert upnp.probe_gateway("192.168.1.0/24", search=lambda timeout: [reply]) is None


def test_no_ssdp_replies_means_no_gateway_not_an_error():
    assert upnp.probe_gateway("192.168.1.0/24", search=lambda timeout: []) is None
