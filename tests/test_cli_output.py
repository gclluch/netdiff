"""How the audit renders, which is the difference between teaching and wallpaper.

A report nobody finishes reading teaches nothing, so the default view is one
line per finding and the lesson is something you ask for. These tests pin that
ladder: the headline view stays short, `-v` still carries every field, and
neither one drops a finding.

Nothing here scans. `cmd_audit` is driven with a stubbed `discover` and no UPnP,
so the only thing under test is the rendering.
"""

import re

import pytest

from netdiff import cli
from netdiff.audit import RULES, Finding
from netdiff.scan import Device

DEVICES = [
    Device(mac="aa:bb:cc:00:00:01", ip="192.168.1.10", ports=(23, 80)),
    Device(mac="aa:bb:cc:00:00:02", ip="192.168.1.11", ports=(21, 5900)),
]

BANNERS = {
    ("192.168.1.10", 23): "Welcome to the router",
    ("192.168.1.10", 80): "HTTP/1.0 401\r\nWWW-Authenticate: Basic realm=x",
    ("192.168.1.11", 21): "220 FTP server ready",
    ("192.168.1.11", 5900): "RFB 003.008",
}


@pytest.fixture
def audit_output(tmp_path, monkeypatch, capsys):
    """Run `netdiff audit` against canned observations, return its stdout."""
    monkeypatch.setattr(cli, "discover", lambda *a, **k: DEVICES)
    monkeypatch.setattr(cli, "grab_banners", lambda pairs, **k: BANNERS)
    monkeypatch.setattr(cli.mdns, "discover", dict)

    def run(*flags):
        db = str(tmp_path / "history.db")
        code = cli.main(["--db", db, "audit", "192.168.1.0/24", "--no-upnp", *flags])
        assert code == 0
        return capsys.readouterr().out

    return run


HEADLINE = re.compile(r"^    (critical|high|medium|info) ")


def headlines(out):
    """The lines that open a finding, not the ones a long title wrapped onto."""
    return [line for line in out.splitlines() if HEADLINE.match(line)]


def test_the_default_view_opens_one_headline_per_finding(audit_output):
    assert len(headlines(audit_output())) == 5, "4 plaintext/auth plus the ports note"


def test_the_default_view_is_short_enough_to_actually_read(audit_output):
    """The flaw being fixed: five findings used to be sixty lines of wallpaper."""
    short, long = audit_output(), audit_output("-v")
    assert len(short.splitlines()) < len(long.splitlines()) / 3


def test_the_default_view_names_the_severity_of_every_finding(audit_output):
    found = {HEADLINE.match(line).group(1) for line in headlines(audit_output())}
    assert found == {"high", "info"}


def test_verbose_carries_every_field_of_every_finding(audit_output):
    out = audit_output("-v")
    for field in ("evidence", "why", "fix", "verify"):
        assert out.count(f"    {field:<9}") == 5, f"{field} missing from a finding"


def test_both_views_report_the_same_findings(audit_output):
    """Brevity is allowed to drop detail. It is not allowed to drop a finding."""
    short, long = audit_output(), audit_output("-v")
    for title in ("Telnet on port 23", "FTP on port 21", "VNC on port 5900"):
        assert title in short and title in long
    # Same counts either way; only the scan id differs between the two runs.
    assert short.splitlines()[0].endswith("4 high, 1 info")
    assert long.splitlines()[0].endswith("4 high, 1 info")


def test_the_default_view_says_how_to_get_the_lesson(audit_output):
    """Otherwise the teaching layer is there and nobody ever finds it."""
    assert "-v" in audit_output().splitlines()[-2]


def test_verbose_does_not_advertise_itself(audit_output):
    out = audit_output("-v")
    assert "-v adds" not in out
    assert "do not take a scanner's word for anything" in out


def test_new_findings_are_marked_in_both_views(audit_output):
    audit_output()  # first audit: nothing is new, everything would be
    assert "[NEW]" not in audit_output()
    assert "[NEW]" not in audit_output("-v")


def test_explain_is_unaffected_by_the_verbosity_flag(capsys):
    assert cli.main(["audit", "--explain", "ssh-v1"]) == 0
    plain = capsys.readouterr().out
    assert cli.main(["audit", "-v", "--explain", "ssh-v1"]) == 0
    assert capsys.readouterr().out == plain


def test_an_unknown_rule_lists_the_known_ones(capsys):
    assert cli.main(["audit", "--explain", "no-such-rule"]) == 2
    err = capsys.readouterr().err
    assert all(rule in err for rule in RULES)


def test_a_headline_survives_a_finding_with_no_title_padding():
    """`print_field` is shared with the lesson view; severity is its label here."""
    finding = Finding(
        rule="r",
        severity="critical",
        device="d",
        title="x" * 200,
        evidence="e",
        why="w",
        fix="f",
        verify="v",
    )
    cli.print_headline(finding, is_new=True)
