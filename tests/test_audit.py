"""The rules, exercised without a network.

That this file can exist at all is the point of the design. The tool this
replaced fused its security logic to its sockets, so no check could run without
a live host, so none ever did - and nine of them raised on their first line for
months without anyone noticing.

Half of these tests assert that something is *not* reported. Those are the
important half.
"""

from netdiff.audit import RULES, audit, headline, summarise
from netdiff.probe import Certificate
from netdiff.scan import Device
from netdiff.upnp import Gateway, Mapping

EXPIRED_SELF_SIGNED = Certificate(
    subject="nas.local",
    issuer="nas.local",
    not_before="2015-01-01",
    not_after="2016-01-01",
)


def dev(ip="192.168.1.10", mac="aa:bb:cc:00:00:01", ports=(), hostname="", vendor=""):
    return Device(mac=mac, ip=ip, hostname=hostname, vendor=vendor, ports=tuple(ports))


def gw(mappings=(), control_url="http://192.168.1.1:5000/ctl"):
    return Gateway(
        control_url=control_url,
        service_type="urn:schemas-upnp-org:service:WANIPConnection:1",
        mappings=tuple(mappings),
    )


def mapping(external=8080, client="192.168.1.10", internal=8080, **kw):
    return Mapping(
        external_port=external,
        protocol="TCP",
        internal_client=client,
        internal_port=internal,
        **kw,
    )


def rules_fired(findings):
    return [f.rule for f in findings]


def one(findings, rule):
    """The single finding of a rule, failing loudly if it fired twice or not at all."""
    hits = [f for f in findings if f.rule == rule]
    assert len(hits) == 1, f"{rule} fired {len(hits)} times"
    return hits[0]


# --- the anti-theater tests: presence is not vulnerability -------------------


def test_an_open_port_alone_is_not_a_finding():
    """The failure mode this whole rewrite exists to prevent."""
    findings = audit([dev(ports=[22, 443, 8443])])
    assert [f for f in findings if f.severity != "info"] == []


def test_an_http_200_is_not_a_finding():
    banners = {("192.168.1.10", 80): "HTTP/1.0 200 OK\r\nServer: lighttpd\r\n"}
    findings = audit([dev(ports=[80])], banners=banners)
    assert [f for f in findings if f.severity != "info"] == []


def test_a_missing_security_header_is_not_a_finding():
    """No CSP on a printer's status page is not a security problem."""
    banners = {("192.168.1.10", 80): "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n"}
    assert rules_fired(audit([dev(ports=[80])], banners=banners)) == [
        "open-ports-noted"
    ]


def test_a_connection_error_is_not_a_finding():
    findings = audit([dev(ports=[8080])], banners={("192.168.1.10", 8080): ""})
    assert [f for f in findings if f.severity != "info"] == []


def test_port_445_open_is_not_smbv1():
    """Every Windows machine and NAS has 445 open. Only a reply is evidence."""
    findings = audit([dev(ports=[445])], probes={"smb": {}})
    assert "smb-v1" not in rules_fired(findings)


def test_a_modern_ssh_server_is_not_reported():
    algorithms = ("curve25519-sha256", "rsa-sha2-512", "aes256-gcm@openssh.com")
    findings = audit(
        [dev(ports=[22])], probes={"ssh": {("192.168.1.10", 22): algorithms}}
    )
    assert "ssh-weak-algorithms" not in rules_fired(findings)


def test_a_certificate_that_is_current_and_signed_by_a_ca_is_not_reported():
    cert = Certificate("nas.local", "Some CA R3", "2026-01-01", "2027-01-01")
    findings = audit(
        [dev(ports=[443])],
        probes={"certs": {("192.168.1.10", 443): cert}},
        today="2026-08-01",
    )
    assert [f for f in findings if f.rule.startswith("tls-")] == []


def test_a_device_that_answers_no_dns_query_is_not_a_resolver():
    findings = audit([dev(ports=[53])], probes={"dns": {"192.168.1.10": ""}})
    assert "dns-recursion-open" not in rules_fired(findings)


def test_an_http_version_line_is_not_a_product_version():
    """`HTTP/1.0` names the protocol. Reporting it as software would be invention."""
    banners = {("192.168.1.10", 80): "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n"}
    assert "service-version" not in rules_fired(
        audit([dev(ports=[80])], banners=banners)
    )


# --- the depth rules, when they do fire --------------------------------------


def test_a_server_that_accepted_smbv1_is_high_and_quotes_the_dialect():
    hit = one(
        audit(
            [dev(ports=[445])], probes={"smb": {("192.168.1.10", 445): "NT LM 0.12"}}
        ),
        "smb-v1",
    )
    assert hit.severity == "high"
    assert "NT LM 0.12" in hit.evidence


def test_weak_ssh_algorithms_are_named_with_the_reason_each_is_weak():
    algorithms = ("curve25519-sha256", "ssh-rsa", "aes256-ctr", "hmac-md5")
    hit = one(
        audit([dev(ports=[22])], probes={"ssh": {("192.168.1.10", 22): algorithms}}),
        "ssh-weak-algorithms",
    )
    assert "2 deprecated" in hit.title
    assert "ssh-rsa" in hit.evidence and "hmac-md5" in hit.evidence
    assert "MD5" in hit.why  # the reason, not just the name
    assert "aes256-ctr" not in hit.evidence


def test_an_expired_certificate_reports_the_date_it_expired():
    hit = one(
        audit(
            [dev(ports=[443])],
            probes={"certs": {("192.168.1.10", 443): EXPIRED_SELF_SIGNED}},
            today="2026-08-01",
        ),
        "tls-cert-expired",
    )
    assert "2016-01-01" in hit.title
    assert "2026-08-01" in hit.evidence


def test_a_self_signed_certificate_is_info_and_says_so_is_normal():
    hit = one(
        audit(
            [dev(ports=[443])],
            probes={"certs": {("192.168.1.10", 443): EXPIRED_SELF_SIGNED}},
            today="2026-08-01",
        ),
        "tls-cert-untrusted",
    )
    assert hit.severity == "info"
    assert "not a problem" in hit.why


def test_a_version_banner_is_quoted_not_interpreted():
    banners = {("192.168.1.10", 80): "HTTP/1.0 200 OK\r\nServer: lighttpd/1.4.35\r\n"}
    hit = one(audit([dev(ports=[80])], banners=banners), "service-version")
    assert hit.severity == "info"
    assert "lighttpd 1.4.35" in hit.title
    assert hit.evidence == "Server: lighttpd/1.4.35"
    assert "CVE" not in hit.why.upper() or "does not match" in hit.why


def test_no_devices_produces_no_findings_at_all():
    assert audit([]) == []
    assert summarise([]) == "nothing to report"


def test_open_ports_are_counted_as_info_and_labelled_not_a_problem():
    findings = audit([dev(ports=[22, 443])])
    noted = [f for f in findings if f.rule == "open-ports-noted"]
    assert len(noted) == 1
    assert noted[0].severity == "info"
    assert "2 open port" in noted[0].evidence
    assert "not a vulnerability" in noted[0].why


# --- plaintext protocols ----------------------------------------------------


def test_telnet_is_reported_as_cleartext():
    banners = {("192.168.1.10", 23): "\xff\xfbUbuntu 14.04 login:"}
    findings = audit([dev(ports=[23])], banners=banners)
    hit = next(f for f in findings if f.rule == "plaintext-protocol")
    assert hit.severity == "high"
    assert "Telnet" in hit.title
    assert "login:" in hit.evidence


def test_ftp_and_telnet_on_one_device_are_two_findings():
    """Same rule, same device - they must not collapse into one row."""
    banners = {
        ("192.168.1.10", 21): "220 ProFTPD Server ready.",
        ("192.168.1.10", 23): "\xff\xfblogin:",
    }
    device = dev(ports=[21, 23])
    findings = [
        f for f in audit([device], banners=banners) if f.rule == "plaintext-protocol"
    ]
    assert len(findings) == 2
    assert {f.title for f in findings} != {findings[0].title}


def test_mqtt_on_1883_is_flagged_but_8883_is_not():
    """8883 is the TLS port. Same protocol, no confidentiality gap."""
    assert "plaintext-protocol" in rules_fired(audit([dev(ports=[1883])]))
    assert "plaintext-protocol" not in rules_fired(audit([dev(ports=[8883])]))


def test_a_silent_port_23_is_not_called_telnet():
    """A port number is a convention, not evidence. Nothing greeted us, so we
    cannot say what is behind it - naming it Telnet would be a guess dressed as
    a finding, which is the exact habit this tool exists to avoid."""
    findings = audit([dev(ports=[23])], banners={("192.168.1.10", 23): ""})
    assert "plaintext-protocol" not in rules_fired(findings)
    assert [f for f in findings if f.severity != "info"] == []


def test_a_greeting_on_port_23_is_enough_to_name_it():
    banners = {("192.168.1.10", 23): "\xff\xfb\x01Ubuntu 14.04 login:"}
    hit = next(
        f
        for f in audit([dev(ports=[23])], banners=banners)
        if f.rule == "plaintext-protocol"
    )
    assert "login:" in hit.evidence


def test_a_protocol_that_never_greets_says_so_in_its_evidence():
    """RTSP and MQTT stay silent until spoken to, so the port assignment is all
    we have - the evidence must admit that rather than imply a banner."""
    hit = next(f for f in audit([dev(ports=[1883])]) if f.rule == "plaintext-protocol")
    assert "does not announce itself" in hit.evidence


# --- HTTP auth over cleartext -----------------------------------------------


def test_auth_challenge_over_http_is_reported():
    banners = {
        ("192.168.1.10", 8080): (
            'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="NAS Admin"\r\n'
        )
    }
    hit = next(
        f
        for f in audit([dev(ports=[8080])], banners=banners)
        if f.rule == "http-auth-plaintext"
    )
    assert hit.severity == "high"
    assert "NAS Admin" in hit.evidence


def test_auth_challenge_header_match_is_case_insensitive():
    banners = {("192.168.1.10", 80): "HTTP/1.1 401\r\nwww-authenticate: Digest\r\n"}
    assert "http-auth-plaintext" in rules_fired(
        audit([dev(ports=[80])], banners=banners)
    )


def test_the_word_authenticate_in_a_page_body_is_not_a_challenge():
    """Substring matching on response bodies is how the old tool invented findings."""
    banners = {
        ("192.168.1.10", 80): "HTTP/1.1 200 OK\r\n\r\n<p>Please authenticate here</p>"
    }
    assert "http-auth-plaintext" not in rules_fired(
        audit([dev(ports=[80])], banners=banners)
    )


# --- SSH --------------------------------------------------------------------


def test_ssh_1_is_reported():
    banners = {("192.168.1.10", 22): "SSH-1.5-OpenSSH_2.9"}
    hit = next(
        f for f in audit([dev(ports=[22])], banners=banners) if f.rule == "ssh-v1"
    )
    assert hit.evidence == "SSH-1.5-OpenSSH_2.9"


def test_ssh_2_is_not_reported():
    banners = {("192.168.1.10", 22): "SSH-2.0-OpenSSH_9.6"}
    assert "ssh-v1" not in rules_fired(audit([dev(ports=[22])], banners=banners))


def test_ssh_1_99_still_counts_because_it_accepts_protocol_1():
    """1.99 advertises "I speak 2, and I will also fall back to 1 for you"."""
    banners = {("192.168.1.10", 22): "SSH-1.99-OpenSSH_3.9"}
    assert "ssh-v1" in rules_fired(audit([dev(ports=[22])], banners=banners))


# --- UPnP: the edge ---------------------------------------------------------


def test_forward_to_a_live_service_is_critical_and_names_the_device():
    device = dev(ip="192.168.1.23", hostname="nas.local", ports=[8080])
    findings = audit([device], gw([mapping(client="192.168.1.23", internal=8080)]))
    hit = next(f for f in findings if f.rule == "internet-exposed-service")
    assert hit.severity == "critical"
    assert "nas.local" in hit.title
    assert "192.168.1.23:8080" in hit.evidence


def test_forward_to_a_device_with_that_port_shut_is_lower_severity():
    device = dev(ip="192.168.1.23", ports=[22])
    findings = audit([device], gw([mapping(client="192.168.1.23", internal=8080)]))
    hit = next(f for f in findings if f.rule == "internet-exposed-port")
    assert hit.severity == "high"


def test_forward_to_an_absent_host_is_the_dangling_case():
    """The subtle one: DHCP will hand that address to something else."""
    findings = audit([dev(ip="192.168.1.10")], gw([mapping(client="192.168.1.47")]))
    hit = next(f for f in findings if f.rule == "upnp-mapping-dangling")
    assert hit.severity == "high"
    assert hit.device == "192.168.1.47"
    assert "DHCP" in hit.why


def test_a_disabled_mapping_is_not_reported():
    findings = audit([dev()], gw([mapping(enabled=False)]))
    assert not [f for f in findings if "exposed" in f.rule]


def test_a_reachable_gateway_is_itself_a_medium_finding():
    findings = audit([], gw())
    hit = next(f for f in findings if f.rule == "upnp-control-open")
    assert hit.severity == "medium"
    assert "http://192.168.1.1:5000/ctl" in hit.evidence


def test_no_gateway_means_no_upnp_findings():
    findings = audit([dev(ports=[22])], gateway=None)
    assert not [f for f in findings if "upnp" in f.rule or "exposed" in f.rule]


def test_mapping_evidence_carries_the_actual_forward():
    findings = audit([dev()], gw([mapping(external=32400, description="Plex")]))
    hit = next(f for f in findings if f.rule.startswith("internet-exposed"))
    assert "32400" in hit.evidence
    assert "Plex" in hit.evidence


# --- structure --------------------------------------------------------------


def test_every_finding_carries_evidence_and_all_three_lessons():
    device = dev(ip="192.168.1.23", ports=[23, 8080])
    banners = {("192.168.1.23", 8080): "HTTP/1.1 401\r\nWWW-Authenticate: Basic\r\n"}
    findings = audit(
        [device], gw([mapping(client="192.168.1.23", internal=8080)]), banners
    )
    assert findings
    for f in findings:
        assert f.evidence.strip(), f"{f.rule} has no receipt"
        assert f.why.strip() and f.fix.strip() and f.verify.strip()


def test_findings_sort_worst_first():
    device = dev(ip="192.168.1.23", ports=[23, 8080])
    findings = audit([device], gw([mapping(client="192.168.1.23", internal=8080)]))
    severities = [f.severity for f in findings]
    assert severities[0] == "critical"
    assert severities[-1] == "info"


def everything():
    """One network arranged so that every rule in the table fires exactly once.

    Kept as a helper because two different tests need it: one asserts the rule
    ids line up with the teaching table, the other that nothing renders a
    placeholder. A rule added without a case here fails the first of those,
    which is the point - the table and the code cannot drift apart quietly.
    """
    device = dev(ip="192.168.1.23", ports=[21, 22, 23, 443, 445, 1883, 8080])
    banners = {
        ("192.168.1.23", 22): "SSH-1.5-x",
        ("192.168.1.23", 8080): "HTTP/1.1 401\r\nWWW-Authenticate: Basic\r\n"
        "Server: lighttpd/1.4.35\r\n",
    }
    probes = {
        "certs": {("192.168.1.23", 443): EXPIRED_SELF_SIGNED},
        "smb": {("192.168.1.23", 445): "NT LM 0.12"},
        "ssh": {("192.168.1.23", 22): ("ssh-rsa", "aes128-cbc", "hmac-md5")},
        "dns": {"192.168.1.23": "answered a query for example.com"},
    }
    return audit(
        [device, dev(ip="192.168.1.30")],
        gw(
            [
                mapping(client="192.168.1.23", internal=8080),  # live -> critical
                mapping(client="192.168.1.30", internal=9999),  # shut -> high
                mapping(client="10.0.0.9"),  # absent -> dangling
            ]
        ),
        banners,
        probes,
        today="2026-08-01",
    )


def test_every_rule_id_used_by_a_rule_exists_in_the_teaching_table():
    assert {f.rule for f in everything()} == set(RULES)


def test_dangling_verify_pings_a_bare_address_not_an_ip_colon_port():
    """`ping 192.168.1.47:80` is not a command. The rule has two placeholders."""
    hit = next(
        f
        for f in audit([dev(ip="192.168.1.10")], gw([mapping(client="192.168.1.47")]))
        if f.rule == "upnp-mapping-dangling"
    )
    assert "ping -c1 192.168.1.47\n" in hit.verify
    assert "192.168.1.47:" not in hit.verify


def test_no_finding_leaves_an_unsubstituted_placeholder_anywhere():
    for f in everything():
        for field in (f.title, f.why, f.fix, f.verify):
            assert "{" not in field and "}" not in field, f.rule


def test_verify_text_interpolates_the_real_device_and_port():
    banners = {("192.168.1.77", 23): "\xff\xfblogin:"}
    hit = next(
        f
        for f in audit([dev(ip="192.168.1.77", ports=[23])], banners=banners)
        if f.rule == "plaintext-protocol"
    )
    assert "192.168.1.77 23" in hit.verify
    assert "{" not in hit.verify  # no unsubstituted placeholders


def test_summarise_counts_by_severity_worst_first():
    device = dev(ip="192.168.1.23", ports=[23, 8080])
    text = summarise(
        audit([device], gw([mapping(client="192.168.1.23", internal=8080)]))
    )
    assert text.startswith("1 critical")
    assert "info" in text


def test_a_headline_names_the_device_it_is_about():
    """Three devices running lighttpd produce three identical lines otherwise."""
    banners = {("192.168.1.10", 80): "HTTP/1.0 200\r\nServer: lighttpd/1.4.35\r\n"}
    hit = one(audit([dev(ports=[80])], banners=banners), "service-version")
    assert headline(hit).startswith("192.168.1.10  ")


def test_a_headline_does_not_repeat_a_device_the_title_already_names():
    hit = one(
        audit([dev(ports=[53])], probes={"dns": {"192.168.1.10": "answered"}}),
        "dns-recursion-open",
    )
    assert headline(hit) == hit.title
    assert hit.title.count("192.168.1.10") == 1


def test_a_finding_about_the_network_is_not_prefixed_with_the_word_network():
    hit = one(audit([dev(ports=[22])]), "open-ports-noted")
    assert headline(hit) == hit.title
