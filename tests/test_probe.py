"""The depth probes, exercised without a network.

The sockets are three lines each; the parsers are where a mistake hides, so the
parsers are what is tested. Two of these fixtures are real captures - the SMB
replies came off actual Samba servers, one with SMBv1 enabled and one without -
because a check for a protocol nobody has run in a decade is exactly the kind
that quietly stops working and reports "nothing found" forever.

The SSH packets are built here from RFC 4253 rather than with anything in
`probe.py`, for the reason `test_mdns.py` gives: a decoder tested against its
own encoder agrees with itself however wrong both are.
"""

import base64
import struct

import pytest

from netdiff.probe import (
    Certificate,
    parse_certificate,
    parse_dns_reply,
    parse_kexinit,
    parse_smb_negotiate,
    smb1_negotiate_request,
)

# --- TLS ---------------------------------------------------------------------

# openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
#   -subj "/CN=nas.local/O=Home" -keyout k.pem -out c.pem
# Generated for this test. `openssl x509 -noout -dates` on it prints
# notBefore=Aug 1 2026, notAfter=Jul 29 2036 - which is what the parser has to
# arrive at from the bytes alone.
SELF_SIGNED_DER = base64.b64decode(
    "MIIDJzCCAg+gAwIBAgIUHru3bCA+dYZEo/cml7W/A+THyTkwDQYJKoZIhvcNAQELBQAw"
    "IzESMBAGA1UEAwwJbmFzLmxvY2FsMQ0wCwYDVQQKDARIb21lMB4XDTI2MDgwMTIzNTQ1"
    "MloXDTM2MDcyOTIzNTQ1MlowIzESMBAGA1UEAwwJbmFzLmxvY2FsMQ0wCwYDVQQKDARI"
    "b21lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5iqp4j1fNGxPTY+AxoR7"
    "33wtYXDRG8+fJpThqiaEiqBx21Mgtw3ppiAhOXVUuxAL07QvoZzwgZSbdE8ln+DNLQjH"
    "JGtnLfiqNQxezAr+IFOwjK/Exmeo6UMBOvGiOPEGYR5t52qqewzqzla2HRhgXm0bxqWN"
    "Mu1ReNenIZ3cZC7GRoNqcyTY6WtcPCdQ6HXpiErMnsUyZXiEsKMNjtGJaBtSSRQVdq+I"
    "TQWP1onxHEK7YdpRvU8/cermJqJ6bJrC28mzO9ogAfFjisjRhYcBdv1INwuZYyCkckaK"
    "tJdSlU7FAGts9hDVc6K3ZCOnZW9YCDqHJqKHic6ZwG8F/v+PEwIDAQABo1MwUTAdBgNV"
    "HQ4EFgQUpiDTgBoFX5tExxNw2oC9oGn8DjEwHwYDVR0jBBgwFoAUpiDTgBoFX5tExxNw"
    "2oC9oGn8DjEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAg0cCO4m7"
    "G228oLY2U56stkH/86DnatU4/r7MxNjfLoSFhn3AS/J+sx6uNGvJ9asS0U4pU5Kbq45q"
    "dnU0Jz8b6IgQ4fCx8Ewv9YK4CPZqoUGav4rQXQlqRJXFPJq7++jftWbaCNrw2vsm3g/j"
    "HzXukzerDh2wqBGbwKAlauAjuq10cCayYDbgglkgo27T1Yyw0COguVmiaMyJ23TzsU8n"
    "NdxH2W4B1mudJt5I+yl7tSdEJLNnOjUYcpnKnW2HCJB5WyhwdJmif339dRoAWQE0JfdH"
    "ho4nszgE4XKhV5gVi9D8RicVRwn2HC/07J5j4EIKgTVNHkqugRJxGEntTZaZxw=="
)


def test_a_real_certificate_yields_its_names_and_dates():
    cert = parse_certificate(SELF_SIGNED_DER)
    assert cert == Certificate(
        subject="nas.local",
        issuer="nas.local",
        not_before="2026-08-01",
        not_after="2036-07-29",
    )


def test_a_certificate_that_signed_itself_is_recognised():
    assert parse_certificate(SELF_SIGNED_DER).self_signed


def test_a_certificate_someone_else_signed_is_not():
    assert not Certificate(
        subject="nas.local",
        issuer="Some CA R3",
        not_before="2026-01-01",
        not_after="2027-01-01",
    ).self_signed


def test_a_certificate_with_no_readable_name_claims_nothing():
    """Better a blank subject than a subject borrowed from the issuer."""
    assert not Certificate("", "", "2026-01-01", "2027-01-01").self_signed


def der_validity(not_before: bytes, not_after: bytes, tag: int = 0x17) -> bytes:
    """A SEQUENCE of two times, wrapped in enough noise to have to be found."""
    times = bytes([tag, len(not_before)]) + not_before
    times += bytes([tag, len(not_after)]) + not_after
    return b"\x30\x82\x01\x00" + b"\x02\x01\x02" + bytes([0x30, len(times)]) + times


@pytest.mark.parametrize(
    "year, expect",
    [(b"49", "2049"), (b"50", "1950"), (b"99", "1999"), (b"26", "2026")],
)
def test_a_two_digit_year_pivots_at_fifty(year, expect):
    """RFC 5280's rule. Getting it backwards dates certificates a century out."""
    cert = parse_certificate(der_validity(year + b"0101000000Z", b"300101000000Z"))
    assert cert.not_before.startswith(expect)


def test_a_four_digit_year_is_read_as_written():
    cert = parse_certificate(
        der_validity(b"20260801000000Z", b"20360729000000Z", tag=0x18)
    )
    assert (cert.not_before, cert.not_after) == ("2026-08-01", "2036-07-29")


def test_bytes_that_are_not_a_certificate_produce_nothing():
    assert parse_certificate(b"") is None
    assert parse_certificate(b"\x30\x82" + b"\xff" * 200) is None
    assert parse_certificate(SELF_SIGNED_DER[:40]) is None


# --- SMB ---------------------------------------------------------------------

# Both captured from Samba answering the request in `probe.py`, one configured
# `server min protocol = NT1` and one `= SMB2`. The second is the shape that
# matters most: a refusal is not an error, so a parser that only handles the
# happy path reports every modern server as running SMBv1.
SMB1_ACCEPTED = base64.b64decode(
    "AAAAn/9TTUJyAAAAAIgBKAAAAAAAAAAAAAAAAAAA//4AAAAAEQAAAzIAAQAEQQAAAA"
    "ABAE8AAAD984CACuml3REi3QEAAABaADlhN2JkNWNlYTUwNQAAAABgSAYGKwYBBQUC"
    "oD4wPKAOMAwGCisGAQQBgjcCAgqjKjAooCYbJG5vdF9kZWZpbmVkX2luX1JGQzQxNz"
    "hAcGxlYXNlX2lnbm9yZQ=="
)
SMB1_REFUSED = base64.b64decode(
    "AAAAJf9TTUJyAAAAAIgDQAAAAAAAAAAAAAAAAAAA//4AAAAAAf//AAA="
)


def test_the_request_is_a_well_formed_smb_message():
    """The length field and the header size are what the reply parser assumes."""
    request = smb1_negotiate_request()
    assert request[0] == 0x00
    assert int.from_bytes(request[1:4], "big") == len(request) - 4
    assert request[4:8] == b"\xffSMB"
    assert request[8] == 0x72


def test_a_server_that_accepted_smbv1_is_reported():
    assert parse_smb_negotiate(SMB1_ACCEPTED) == "NT LM 0.12"


def test_a_server_that_refused_smbv1_is_not():
    assert parse_smb_negotiate(SMB1_REFUSED) == ""


def test_nothing_that_is_not_an_smb_reply_is_reported():
    assert parse_smb_negotiate(b"") == ""
    assert parse_smb_negotiate(b"HTTP/1.1 400 Bad Request\r\n\r\n") == ""
    assert parse_smb_negotiate(SMB1_ACCEPTED[:20]) == ""


# --- DNS ---------------------------------------------------------------------


def dns_reply(flags: int, answers: int = 1, ident: int = 0x1D1F) -> bytes:
    return struct.pack("!HHHHHH", ident, flags, 1, answers, 0, 0)


def test_a_recursive_answer_is_recognised():
    # QR + recursion desired + recursion available, rcode 0.
    assert parse_dns_reply(dns_reply(0x8180))


def test_a_resolver_that_does_not_offer_recursion_is_not_reported():
    assert parse_dns_reply(dns_reply(0x8100)) == ""


def test_an_error_or_an_empty_answer_is_not_recursion():
    assert parse_dns_reply(dns_reply(0x8183)) == ""  # NXDOMAIN
    assert parse_dns_reply(dns_reply(0x8180, answers=0)) == ""  # referral only


def test_a_reply_to_someone_elses_query_is_ignored():
    assert parse_dns_reply(dns_reply(0x8180, ident=0x1234)) == ""


def test_a_question_is_not_mistaken_for_an_answer():
    assert parse_dns_reply(dns_reply(0x0100)) == ""
    assert parse_dns_reply(b"\x00" * 4) == ""


# --- SSH ---------------------------------------------------------------------


def kexinit(*name_lists: str) -> bytes:
    """An SSH binary packet carrying a KEXINIT, per RFC 4253 section 6."""
    payload = bytes([20]) + b"\x00" * 16
    for names in name_lists:
        raw = names.encode()
        payload += struct.pack("!I", len(raw)) + raw
    padding = 8 - (len(payload) + 5) % 8
    return (
        struct.pack("!IB", len(payload) + padding + 1, padding)
        + payload
        + (b"\x00" * padding)
    )


SIX = ("kex", "hostkey", "cipher-out", "cipher-in", "mac-out", "mac-in")


def test_every_offered_algorithm_is_read():
    packet = kexinit(*[f"{name}-a,{name}-b" for name in SIX])
    assert parse_kexinit(packet) == tuple(
        f"{name}-{half}" for name in SIX for half in "ab"
    )


def test_the_same_algorithm_offered_both_directions_is_one_fact():
    packet = kexinit("kex", "hostkey", "aes128-cbc", "aes128-cbc", "m", "m")
    assert parse_kexinit(packet) == ("kex", "hostkey", "aes128-cbc", "m")


def test_compression_none_is_not_read_as_an_algorithm():
    """Every SSH server offers `none` compression. Reading it would flag them all."""
    packet = kexinit(*SIX, "none", "none", "", "")
    assert "none" not in parse_kexinit(packet)


def test_a_cipher_called_none_is_still_read():
    packet = kexinit("kex", "hostkey", "none", "none", "m", "m")
    assert "none" in parse_kexinit(packet)


def test_anything_that_is_not_a_kexinit_offers_nothing():
    assert parse_kexinit(b"") == ()
    assert parse_kexinit(b"SSH-2.0-OpenSSH_9.6\r\n") == ()
    assert parse_kexinit(kexinit(*SIX)[:12]) == ()
