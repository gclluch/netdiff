"""The HTML report, and the escaping that has to hold it together.

Everything on that page came off the network: device names, banners, mDNS
labels, a router's own description of a port forward. This is the second place
in the codebase where untrusted strings become a language other than Python -
the first was the `verify` commands, where an unquoted value became shell. The
lesson transfers exactly, so half of this file is that lesson.

Pure rendering, no sockets, no database.
"""

import re

from netdiff import report
from netdiff.audit import RULES, SEVERITY_ORDER, Finding

HOSTILE = '<script>alert(1)</script>" onload="x'


def finding(severity="high", **kw):
    fields = dict(
        rule="plaintext-protocol",
        severity=severity,
        device="192.168.1.23",
        title="Telnet on port 23 sends passwords in cleartext",
        evidence="220 router ready",
        why="Telnet has no encryption.",
        fix="Use SSH.",
        verify="nc 192.168.1.23 23",
    )
    fields.update(kw)
    return Finding(**fields)


def page(*annotated, subnet="192.168.1.0/24", summary="1 high"):
    return report.render(list(annotated), subnet, 7, "2026-08-01 12:00 BST", summary)


# --- escaping ---------------------------------------------------------------


def test_a_hostile_device_name_cannot_open_a_tag():
    out = page((finding(title=HOSTILE), False))
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_every_field_of_a_finding_is_escaped():
    """Not just the title - a banner is attacker-chosen too, and it is quoted."""
    for field in ("title", "evidence", "why", "fix", "verify"):
        out = page((finding(**{field: HOSTILE}), False))
        assert "<script>" not in out, f"{field} reached the page unescaped"
        assert "&lt;script&gt;" in out


def test_the_only_attribute_we_interpolate_into_is_a_closed_set():
    """`severity` is the one value that lands inside `class="..."`.

    It is safe because it cannot be attacker-chosen - it comes from the rule
    table, not from the network. That is the actual guarantee, so pin it here:
    if a rule ever grows a free-form severity, this fails and the quoting in the
    template becomes load-bearing.
    """
    assert set(SEVERITY_ORDER) == {"critical", "high", "medium", "info"}
    for spec in RULES.values():
        assert spec["severity"] in SEVERITY_ORDER


def test_the_subnet_and_summary_are_escaped_too():
    out = page(subnet=HOSTILE, summary=HOSTILE)
    assert "<script>" not in out


def test_a_quote_in_a_finding_cannot_reach_the_page_raw():
    """`esc` is called with quote=True, so `"` is neutralised everywhere."""
    out = page((finding(evidence='banner says "hello"'), False))
    assert '"hello"' not in out
    assert "&quot;hello&quot;" in out


# --- structure --------------------------------------------------------------


def test_the_page_stands_alone():
    """No server, no assets, no network - it gets emailed and still works."""
    out = page((finding(), False))
    assert "<style>" in out and "</style>" in out
    assert "<script" not in out
    assert not re.search(r'(src|href)="(?!#)', out), "no external references"


def test_progressive_disclosure_is_native():
    out = page((finding(), False))
    assert out.count("<details>") == 1
    assert "<summary>" in out
    assert "Telnet on port 23" in out


def test_findings_are_ordered_worst_first():
    out = page(
        (finding(severity="info", title="ports noted"), False),
        (finding(severity="critical", title="reachable from the internet"), False),
        (finding(severity="medium", title="router lets any device in"), False),
    )
    assert out.index("reachable from the internet") < out.index("router lets any")
    assert out.index("router lets any") < out.index("ports noted")


def test_new_findings_are_marked():
    assert "NEW" in page((finding(), True))
    assert "NEW" not in page((finding(), False))


def test_an_empty_audit_says_so_rather_than_rendering_a_blank_page():
    out = page()
    assert "Nothing to report" in out
    assert "<details>" not in out


def test_the_footer_repeats_that_an_open_port_is_not_a_vulnerability():
    """The thesis has to survive the trip to whoever the file gets sent to."""
    assert "not a vulnerability" in page((finding(), False))
