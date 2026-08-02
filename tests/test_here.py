"""What this network does to you - the checks behind `netdiff here`.

Nothing here touches a real network. The interesting cases are all hostile
networks - a resolver that invents answers, a box terminating your TLS, a MAC
answering for addresses it does not own - and those are exactly the ones you
cannot arrange on a desk, which is why the parsers are pure over bytes and the
rules are pure over a dict.

Half of this file asserts that something is **not** reported. `here` runs on
networks belonging to other people and hands its reader a verdict about whether
to trust the place they are sitting; the failure mode that matters is not a
missed finding, it is a confident accusation against a network that was fine.

The DNS packets are assembled by local helpers rather than by anything in
`netdiff`, for the same reason `test_mdns.py` does it: a decoder tested against
its own encoder agrees with itself however wrong both are.
"""

import contextlib
import http.server
import socket
import ssl
import struct
import threading

import pytest

from netdiff import audit, cli, here
from netdiff.probe import DNS_ID

# --- DNS packet builders -----------------------------------------------------


def name(text):
    """A DNS name: each label length-prefixed, terminated by a zero byte."""
    out = b""
    for label in text.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def reply(question, addresses=(), rcode=0, ident=DNS_ID, recursion=True):
    """A reply to our own A query, with an answer per address.

    The recursion-desired bit is echoed back from the query, as a real server
    does - so a captured reply and one of these have the same flags word.
    """
    flags = 0x8000 | 0x0100 | (0x0080 if recursion else 0) | rcode
    header = struct.pack("!HHHHHH", ident, flags, 1, len(addresses), 0, 0)
    body = name(question) + struct.pack("!HH", 1, 1)
    for address in addresses:
        body += (
            b"\xc0\x0c"  # a pointer back to the question's name, as real servers send
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + bytes(int(o) for o in address.split("."))
        )
    return header + body


def test_the_wire_format_is_what_we_think_it_is():
    """Pins the builders against bytes, so everything below rests on those.

    Without this the rest of the file only proves the helpers and the parser
    agree with each other, which they would even if both were wrong.
    """
    data = reply("a.invalid", ["10.0.0.1"])
    assert data[:2] == b"\x1d\x1f", "our query id, echoed back"
    assert data[2:4] == b"\x81\x80", "QR and recursion-available set, rcode 0"
    assert data[12:] == (
        b"\x01a\x07invalid\x00"  # the question's name
        b"\x00\x01\x00\x01"  # type A, class IN
        b"\xc0\x0c"  # answer name: pointer to offset 12
        b"\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"  # A, IN, ttl 60, 4 bytes
        b"\x0a\x00\x00\x01"  # 10.0.0.1
    )


# --- parsing a reply ---------------------------------------------------------


def test_an_answer_yields_its_rcode_and_addresses():
    assert here.parse_dns_answers(reply("example.com", ["93.184.216.34"])) == (
        0,
        ("93.184.216.34",),
    )


def test_nxdomain_yields_the_code_and_nothing_else():
    assert here.parse_dns_answers(reply("a.invalid", rcode=3)) == (3, ())


def test_a_reply_to_somebody_elses_query_is_not_ours():
    """A stray datagram on the socket must not be read as our answer."""
    assert (
        here.parse_dns_answers(reply("example.com", ["1.2.3.4"], ident=0x4242)) is None
    )


def test_a_question_is_not_an_answer():
    """The QR bit is the only thing separating them."""
    question = struct.pack("!HHHHHH", DNS_ID, 0x0100, 1, 0, 0, 0) + name("example.com")
    assert here.parse_dns_answers(question) is None


def test_a_record_longer_than_its_packet_is_dropped_not_truncated():
    data = bytearray(reply("example.com", ["93.184.216.34"]))
    data[-6:-4] = struct.pack("!H", 64)  # rdlen now claims 64 bytes, 4 remain
    assert here.parse_dns_answers(bytes(data)) == (0, ())


def test_a_reply_carrying_no_answer_section_is_still_read():
    assert here.parse_dns_answers(reply("example.com")) == (0, ())


@pytest.mark.parametrize("data", [b"", b"\x1d\x1f", b"\xff" * 11])
def test_bytes_that_are_not_a_reply_produce_nothing(data):
    assert here.parse_dns_answers(data) is None


# --- what the network told us about itself -----------------------------------

NETSTAT = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
127                127.0.0.1          UCS                   lo0
"""

IP_ROUTE = """default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.55 metric 100
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.55
"""

SCUTIL = """DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 8.8.8.8
  flags    : Request A records
"""


def runner_for(output, ok=("netstat", "ip", "scutil")):
    """Stub `subprocess.run`: the listed commands succeed with `output`."""

    class Result:
        def __init__(self, returncode, stdout):
            self.returncode, self.stdout = returncode, stdout

    def run(cmd, **kwargs):
        return Result(0, output) if cmd[0] in ok else Result(1, "")

    return run


def test_the_gateway_is_read_from_bsd_and_linux_alike():
    assert here.default_gateway(runner_for(NETSTAT)) == "192.168.1.1"
    assert here.default_gateway(runner_for(IP_ROUTE)) == "10.0.0.1"


def test_no_default_route_is_no_gateway_rather_than_a_guess():
    assert here.default_gateway(runner_for("Destination Gateway Flags")) == ""
    assert here.default_gateway(runner_for("", ok=())) == ""


def test_resolvers_come_from_resolv_conf_and_scutil_together(tmp_path):
    """macOS keeps the real configuration in scutil and leaves a note in the file."""
    conf = tmp_path / "resolv.conf"
    conf.write_text("# macOS Notice\nnameserver 1.1.1.1\n")
    found = here.system_resolvers(runner_for(SCUTIL), path=str(conf))
    assert found == ("1.1.1.1", "192.168.1.1", "8.8.8.8")


def test_a_resolver_named_twice_is_one_resolver(tmp_path):
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver 192.168.1.1\n")
    assert here.system_resolvers(runner_for(SCUTIL), path=str(conf)) == (
        "192.168.1.1",
        "8.8.8.8",
    )


def test_no_resolv_conf_and_no_scutil_is_empty_not_an_error(tmp_path):
    assert (
        here.system_resolvers(runner_for("", ok=()), path=str(tmp_path / "nope")) == ()
    )


# --- HTTP --------------------------------------------------------------------


@pytest.mark.parametrize(
    "head, expect",
    [
        ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n", (200, "")),
        (
            "HTTP/1.1 302 Found\r\nLocation: http://10.0.0.1/login\r\n\r\n",
            (302, "http://10.0.0.1/login"),
        ),
        ("HTTP/1.0 511 Network Authentication Required\r\n\r\n", (511, "")),
        # Header names are case-insensitive and middleboxes are careless with them.
        ("HTTP/1.1 307 x\r\nLOCATION: /portal\r\n\r\n", (307, "/portal")),
    ],
)
def test_a_status_line_and_its_location_are_read(head, expect):
    assert here.parse_http_head(head) == expect


@pytest.mark.parametrize("head", ["", "not http at all\r\n\r\n", "\r\n"])
def test_something_that_is_not_a_response_produces_nothing(head):
    assert here.parse_http_head(head) is None


class _Redirector(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://10.0.0.1/login")
        self.end_headers()

    def log_message(self, *args):
        pass


@contextlib.contextmanager
def _serving(handler):
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()


def test_a_redirect_is_read_off_a_real_socket_and_not_followed():
    """End to end over loopback: the request we build, the reply we parse.

    Not following it is the whole point - the redirect is the answer, not
    something in the way of one.
    """
    with _serving(_Redirector) as port:
        assert here.http_get("127.0.0.1", port=port) == (302, "http://10.0.0.1/login")


def test_a_host_that_does_not_answer_is_not_a_portal():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        closed = sock.getsockname()[1]
    assert here.http_get("127.0.0.1", port=closed, timeout=1.0) is None


# --- TLS ---------------------------------------------------------------------
#
# Only the mapping from exception to verdict is pinned here. Standing up a real
# TLS server would mean committing a private key to a public repository, and the
# thing that can actually be wrong is this ordering: SSLCertVerificationError is
# a subclass of SSLError, which is a subclass of OSError, so catching them in
# the wrong order silently turns "intercepted" into "unreachable".


def _raising(exc):
    def create_connection(*args, **kwargs):
        raise exc

    return create_connection


def test_a_certificate_that_does_not_verify_is_reported(monkeypatch):
    error = ssl.SSLCertVerificationError("bad")
    error.verify_message = "self signed certificate in certificate chain"
    monkeypatch.setattr(here.socket, "create_connection", _raising(error))
    assert (
        here.tls_verified("example.com")
        == "self signed certificate in certificate chain"
    )


def test_a_network_we_cannot_reach_is_not_an_interception(monkeypatch):
    """No internet is not a man in the middle, and must not be printed as one."""
    monkeypatch.setattr(here.socket, "create_connection", _raising(OSError("no route")))
    assert here.tls_verified("example.com") is None


def test_a_tls_error_that_is_not_about_the_certificate_says_nothing(monkeypatch):
    monkeypatch.setattr(here.socket, "create_connection", _raising(ssl.SSLError("eof")))
    assert here.tls_verified("example.com") is None


def test_a_machine_with_no_trust_store_accuses_nobody(monkeypatch):
    """The false positive that would have shipped, and the loudest one possible.

    A python.org build whose `Install Certificates.command` was never run has an
    empty store, and every handshake it makes fails with `unable to get local
    issuer certificate` - byte for byte what an interception CA produces. Left
    alone, this reports `high: this network is reading your encrypted traffic`
    on every network that machine will ever join.
    """
    monkeypatch.setattr(
        here.ssl,
        "create_default_context",
        lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
    )
    monkeypatch.setattr(
        here.socket,
        "create_connection",
        _raising(AssertionError("must not reach the network")),
    )
    assert here.tls_verified("example.com") is None


# --- the rules ---------------------------------------------------------------
#
# Pure functions over what `observe()` gathered. Each one has its negative case
# beside it, because on a network that is fine every one of these must be silent.


def test_a_failed_verification_is_an_interception():
    found = audit.rule_tls_intercepted("example.com", "self signed certificate")
    assert found.severity == "high"
    assert "self signed certificate" in found.evidence


@pytest.mark.parametrize("reason", ["", None])
def test_a_clean_or_unreachable_handshake_is_not(reason):
    assert audit.rule_tls_intercepted("example.com", reason) is None


@pytest.mark.parametrize("status", [302, 307, 511])
def test_anything_but_an_answer_from_the_host_is_a_portal(status):
    found = audit.rule_captive_portal("example.com", (status, "http://10.0.0.1/"))
    assert found and "10.0.0.1" in found.evidence


@pytest.mark.parametrize("response", [(200, ""), (404, ""), (500, ""), None])
def test_a_site_answering_for_itself_is_not_a_portal(response):
    assert audit.rule_captive_portal("example.com", response) is None


def test_an_address_for_a_reserved_name_is_invention():
    found = audit.rule_dns_invented("10.0.0.1", "a.invalid", (0, ("10.0.0.53",)))
    assert found and "10.0.0.53" in found.evidence


@pytest.mark.parametrize("answer", [(3, ()), (0, ()), (2, ()), None])
def test_a_resolver_that_admits_the_name_does_not_exist_is_correct(answer):
    """NXDOMAIN, an empty answer, SERVFAIL and silence are all honest replies."""
    assert audit.rule_dns_invented("10.0.0.1", "a.invalid", answer) is None


def test_a_public_name_answered_with_a_private_address_is_a_redirect():
    found = audit.rule_dns_redirected(
        "10.0.0.1", "example.com", (0, ("192.168.1.1",)), here.is_private
    )
    assert found and "192.168.1.1" in found.evidence


@pytest.mark.parametrize(
    "answer",
    [(0, ("93.184.216.34",)), (0, ("23.192.228.80", "23.215.0.136")), (3, ()), None],
)
def test_a_public_address_or_no_answer_is_not_a_redirect(answer):
    """Two different public addresses for one name is a CDN, not a hijack."""
    assert (
        audit.rule_dns_redirected("1.1.1.1", "example.com", answer, here.is_private)
        is None
    )


@pytest.mark.parametrize("blocked", ["0.0.0.0", "127.0.0.1"])
def test_a_resolver_refusing_to_answer_is_not_a_resolver_steering_you(blocked):
    """Both look private to `ipaddress` and neither is a redirection.

    They are how a filtering resolver says no - school wifi, guest wifi, a
    pi-hole. Refusing to answer and steering you somewhere are opposite acts,
    and this rule tells its reader the network may be collecting credentials.
    """
    assert not here.is_private(blocked)
    assert (
        audit.rule_dns_redirected(
            "10.0.0.1", "example.com", (0, (blocked,)), here.is_private
        )
        is None
    )


def test_one_mac_answering_for_many_addresses_is_reported():
    neighbours = {
        "10.0.0.1": "aa:bb:cc:00:00:01",
        "10.0.0.2": "aa:bb:cc:00:00:01",
        "10.0.0.3": "aa:bb:cc:00:00:01",
        "10.0.0.9": "aa:bb:cc:00:00:02",
    }
    found = audit.rule_arp_claims(neighbours, threshold=3)
    assert len(found) == 1
    assert found[0].device == "aa:bb:cc:00:00:01"
    assert "10.0.0.1, 10.0.0.2, 10.0.0.3" in found[0].evidence


def test_a_router_with_a_second_address_is_not_reported():
    """Two is ordinary - an alias, a bridge, a router holding a second address."""
    neighbours = {"10.0.0.1": "aa:bb:cc:00:00:01", "10.0.0.2": "aa:bb:cc:00:00:01"}
    assert audit.rule_arp_claims(neighbours, threshold=3) == []


def test_other_devices_answering_means_isolation_is_off():
    found = audit.rule_client_isolation({"10.0.0.7", "10.0.0.8"}, "10.0.0.1")
    assert found.rule == "here-client-isolation-off"
    assert found.severity == "info", "reachable neighbours are normal, not a problem"


def test_only_the_gateway_answering_is_reported_as_the_good_result():
    """The good news has to be printed, or it cannot be told from a check that
    did not run - and on a network you are deciding whether to trust, those are
    opposite answers."""
    found = audit.rule_client_isolation(set(), "10.0.0.1")
    assert found.rule == "here-client-isolation-on"


def test_isolation_says_nothing_when_we_have_no_gateway():
    """No default route means the sweep proves nothing either way."""
    assert audit.rule_client_isolation(set(), "") is None


@pytest.mark.parametrize(
    "neighbours",
    [
        {},  # neither `arp -an` nor `ip neigh` parsed
        {"10.0.0.7": "aa:bb:cc:00:00:07"},  # a VPN: the route points off-segment
    ],
)
def test_a_gateway_that_did_not_answer_cannot_be_evidence_that_it_did(neighbours):
    """`only the gateway answered` must not be printed about an empty table.

    Two ordinary ways to get there: a machine where the ARP command did not
    parse, and a VPN, where the default route is a tunnel peer that was never on
    this segment. Both used to hand the reader "Nothing. This is the good
    result." about a check that had not run.
    """
    findings = audit.here_findings(
        observation(neighbours=neighbours, gateway="10.8.0.1"), here.is_private
    )
    assert not [f for f in findings if f.rule.startswith("here-client-isolation")]


def test_our_own_open_ports_are_reported_with_the_address_they_answered_on():
    found = audit.rule_own_ports_exposed("10.0.0.55", (22, 445))
    assert found and "10.0.0.55" in found.evidence and "22, 445" in found.evidence


def test_a_machine_with_nothing_listening_is_not_a_finding():
    assert audit.rule_own_ports_exposed("10.0.0.55", ()) is None


# --- assembling them ---------------------------------------------------------


def observation(**overrides):
    """A clean network: nothing here should produce a single finding."""
    return dict(
        {
            "subnet": "10.0.0.0/24",
            "us": "10.0.0.55",
            "gateway": "10.0.0.1",
            "resolvers": ("10.0.0.1",),
            "neighbours": {"10.0.0.1": "aa:bb:cc:00:00:01"},
            "own_ports": (),
            "tls": "",
            "http": (200, ""),
            "nxdomain": {"10.0.0.1": (3, ())},
            "public_name": {"10.0.0.1": (0, ("93.184.216.34",))},
            "host": "example.com",
            "invalid_name": "a.invalid",
            "arp_threshold": 3,
        },
        **overrides,
    )


HERE_RULES = {rule for rule in audit.RULES if rule.startswith("here-")}


def test_a_network_that_behaves_produces_only_the_isolation_note():
    findings = audit.here_findings(observation(), here.is_private)
    assert [f.rule for f in findings] == ["here-client-isolation-on"]


def test_every_here_rule_in_the_teaching_table_can_actually_fire():
    """The other half of `test_audit.py`'s assertion, for this command's rules.

    A rule id with teaching text and no code path is a lesson nobody can ever
    be shown, and nothing else in the suite would notice.
    """
    fired = {f.rule for f in audit.here_findings(observation(), here.is_private)}
    fired |= {f.rule for f in audit.here_findings(hostile(), here.is_private)}
    assert fired == HERE_RULES


def hostile(**overrides):
    """One network doing every single thing this command looks for."""
    return observation(
        tls="self signed certificate in certificate chain",
        http=(302, "http://10.0.0.1/login"),
        nxdomain={"10.0.0.1": (0, ("10.0.0.53",))},
        public_name={"10.0.0.1": (0, ("10.0.0.53",))},
        neighbours={
            "10.0.0.1": "aa:bb:cc:00:00:01",
            "10.0.0.2": "aa:bb:cc:00:00:01",
            "10.0.0.3": "aa:bb:cc:00:00:01",
        },
        own_ports=(22,),
        **overrides,
    )


def test_a_hostile_network_produces_all_of_it_worst_first():
    findings = audit.here_findings(
        observation(
            tls="self signed certificate in certificate chain",
            http=(302, "http://10.0.0.1/login"),
            nxdomain={"10.0.0.1": (0, ("10.0.0.53",))},
            public_name={"10.0.0.1": (0, ("10.0.0.53",))},
            neighbours={
                "10.0.0.1": "aa:bb:cc:00:00:01",
                "10.0.0.2": "aa:bb:cc:00:00:01",
                "10.0.0.3": "aa:bb:cc:00:00:01",
            },
            own_ports=(22,),
        ),
        here.is_private,
    )
    assert findings[0].rule == "here-tls-intercepted"
    assert [f.severity for f in findings] == sorted(
        (f.severity for f in findings), key=audit.SEVERITY_ORDER.get
    )
    assert {f.rule for f in findings} >= {
        "here-tls-intercepted",
        "here-captive-portal",
        "here-dns-invented",
        "here-dns-redirected",
        "here-arp-claims",
        "here-own-ports-exposed",
    }


def test_every_resolver_is_asked_and_each_one_answers_for_itself():
    findings = audit.here_findings(
        observation(
            resolvers=("10.0.0.1", "10.0.0.2"),
            nxdomain={"10.0.0.1": (0, ("10.0.0.53",)), "10.0.0.2": (3, ())},
        ),
        here.is_private,
    )
    invented = [f for f in findings if f.rule == "here-dns-invented"]
    assert [f.device for f in invented] == ["10.0.0.1"], "only the one that lied"


# --- gathering ---------------------------------------------------------------


def test_observe_returns_exactly_the_keys_the_rules_read(monkeypatch):
    """The seam between the two halves, and nothing else was testing it.

    `here_findings` reads its keys with no defaults, on purpose. But the only
    dict it was ever run against was this file's hand-written fixture, which
    duplicates the key set - so renaming a key in `observe` left every test
    green and the command raising KeyError on its first real run. This drives
    the real `observe` with stubbed collectors and feeds the result straight in.

    It also pins the `zip(jobs, pool.map(...))` pairing: each stub returns a
    distinguishable marker, so a result landing under the wrong key shows up.
    """
    monkeypatch.setattr(here, "local_address", lambda: "10.0.0.55")
    monkeypatch.setattr(here, "default_gateway", lambda runner: "10.0.0.1")
    monkeypatch.setattr(here, "system_resolvers", lambda runner: ("10.0.0.1",))
    monkeypatch.setattr(here, "nudge", lambda hosts: None)
    monkeypatch.setattr(here.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(
        here,
        "read_arp_table",
        lambda: {"10.0.0.1": "aa:bb:cc:00:00:01", "10.0.0.255": "ff:ff:ff:ff:ff:ff"},
    )
    monkeypatch.setattr(here, "scan_ports", lambda ip, ports: (22,))
    monkeypatch.setattr(here, "tls_verified", lambda host, timeout: "")
    monkeypatch.setattr(here, "http_get", lambda host, timeout: (200, ""))
    monkeypatch.setattr(
        here,
        "dns_answers",
        lambda resolver, name, timeout: (
            (3, ()) if name.endswith(".invalid") else (0, ("93.184.216.34",))
        ),
    )

    observed = here.observe("10.0.0.0/24", ports=(22,))

    assert observed["us"] == "10.0.0.55"
    assert observed["own_ports"] == (22,)
    assert observed["tls"] == "" and observed["http"] == (200, "")
    assert observed["nxdomain"] == {"10.0.0.1": (3, ())}
    assert observed["public_name"] == {"10.0.0.1": (0, ("93.184.216.34",))}
    assert observed["host"] == here.PUBLIC_PROBE
    assert observed["invalid_name"] == here.NXDOMAIN_PROBE
    assert observed["arp_threshold"] == here.SUSPICIOUS_CLAIMS
    assert observed["neighbours"] == {"10.0.0.1": "aa:bb:cc:00:00:01"}, (
        "the broadcast address is not a device, and counting it as one would "
        "turn an isolated network into one with a neighbour"
    )
    # The real contract: this dict is what the rules consume.
    assert [f.rule for f in audit.here_findings(observed, here.is_private)] == [
        "here-own-ports-exposed",
        "here-client-isolation-on",
    ]


def test_a_subnet_too_big_to_be_one_segment_is_refused():
    """The same guard `scan.discover` has - `here 10.0.0.0/8` would materialise
    16.7M strings before a packet moved. `cli.main` turns this into exit 2."""
    with pytest.raises(ValueError, match="one broadcast segment"):
        here.observe("10.0.0.0/8")


# --- the command -------------------------------------------------------------


@pytest.fixture
def here_output(monkeypatch, capsys):
    """Run `netdiff here` against a canned observation, return its stdout."""

    def run(*flags, **overrides):
        monkeypatch.setattr(here, "observe", lambda *a, **k: observation(**overrides))
        assert cli.main(["here", "10.0.0.0/24", *flags]) == 0
        return capsys.readouterr().out

    return run


def test_the_default_view_is_one_line_per_finding(here_output):
    out = here_output(own_ports=(22, 445))
    assert "    medium " in out and "    info " in out
    assert "    evidence " not in out, "the lesson is something you ask for"
    assert "    fix " not in out


def test_verbose_carries_every_field(here_output):
    out = here_output("-v", own_ports=(22, 445))
    for field in ("evidence", "why", "fix", "verify"):
        assert field in out


def test_both_views_report_the_same_findings(here_output):
    """Brevity may drop detail. It may never drop a finding."""
    assert here_output(own_ports=(22,)).count("here-") == here_output(
        "-v", own_ports=(22,)
    ).count("here-")
    brief = here_output(own_ports=(22,))
    assert "1 medium, 1 info" in brief


def test_the_gateway_and_resolvers_are_named(here_output):
    """A verdict about a network has to say which network it is about."""
    out = here_output()
    assert "10.0.0.1" in out and "10.0.0.0/24" in out


def test_here_records_nothing(monkeypatch, capsys, tmp_path):
    """A network you are passing through does not belong in your history.

    Recording one would put strangers' MAC addresses in `netdiff inventory` and
    make the next scan at home report a wall of appeared/vanished.
    """
    db = tmp_path / "history.db"
    monkeypatch.setattr(here, "observe", lambda *a, **k: observation())
    assert cli.main(["--db", str(db), "here", "10.0.0.0/24"]) == 0
    capsys.readouterr()
    assert not db.exists(), "here opened the history database"


def test_json_carries_every_field_and_what_was_asked(monkeypatch, capsys):
    import json

    monkeypatch.setattr(here, "observe", lambda *a, **k: observation(own_ports=(22,)))
    assert cli.main(["here", "10.0.0.0/24", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["gateway"] == "10.0.0.1"
    assert payload["resolvers"] == ["10.0.0.1"]
    assert {f["rule"] for f in payload["findings"]} == {
        "here-own-ports-exposed",
        "here-client-isolation-on",
    }


def test_an_inferred_subnet_is_announced_without_landing_in_the_json(
    monkeypatch, capsys
):
    """The notice is a diagnostic, not data, so it goes to stderr.

    It has to be said - a report whose target was guessed must show its target -
    but on stdout it lands inside the document, and `--json` with no subnet
    emitted something no parser would accept. Shared by scan and audit too.
    """
    import json

    monkeypatch.setattr(here, "observe", lambda *a, **k: observation())
    monkeypatch.setattr(cli, "local_subnet", lambda: "10.0.0.0/24")
    assert cli.main(["here", "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["subnet"] == "10.0.0.0/24"
    assert "no subnet given" in captured.err


def test_every_here_rule_can_be_explained_without_scanning(capsys):
    """`--explain` reads the same table these findings are built from."""
    for rule in [r for r in audit.RULES if r.startswith("here-")]:
        assert cli.main(["audit", "--explain", rule]) == 0
        assert "{" not in capsys.readouterr().out, f"{rule} leaked a placeholder"
