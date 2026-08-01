"""ARP parsing and persistence. No network is touched: parsing runs against
captured command output, and the database is a temp file."""

import pytest

from netdiff import store
from netdiff.audit import Finding
from netdiff.oui import is_randomised, lookup
from netdiff.scan import Device, normalise_mac, parse_arp_output, read_arp_table

MACOS_ARP = """\
? (192.168.1.1) at ac:63:be:1:2:3 on en0 ifscope [ethernet]
? (192.168.1.21) at b8:27:eb:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.1.44) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""

LINUX_NEIGH = """\
192.168.1.1 dev eth0 lladdr ac:63:be:01:02:03 REACHABLE
192.168.1.21 dev eth0 lladdr b8:27:eb:aa:bb:cc STALE
192.168.1.99 dev eth0  FAILED
"""


def test_macos_arp_output_is_parsed():
    table = parse_arp_output(MACOS_ARP)
    assert table["192.168.1.21"] == "b8:27:eb:aa:bb:cc"
    assert "192.168.1.44" not in table, "incomplete entries are not devices"


def test_linux_ip_neigh_output_is_parsed():
    table = parse_arp_output(LINUX_NEIGH)
    assert table["192.168.1.1"] == "ac:63:be:01:02:03"
    assert "192.168.1.99" not in table, "FAILED entries have no MAC"


def test_both_platforms_yield_the_same_mac_for_the_same_device():
    """macOS prints `1:2:3`, Linux prints `01:02:03`. Unpadded, one device
    would be recorded as two, and every scan would report a phantom change."""
    assert (
        parse_arp_output(MACOS_ARP)["192.168.1.1"]
        == parse_arp_output(LINUX_NEIGH)["192.168.1.1"]
    )


def test_normalise_mac_pads_every_octet():
    assert normalise_mac("A:B:C:1:2:3") == "0a:0b:0c:01:02:03"
    assert normalise_mac("AC:63:BE:01:02:03") == "ac:63:be:01:02:03"


def test_read_arp_table_falls_through_to_the_second_command():
    calls = []

    class Result:
        def __init__(self, code, out):
            self.returncode, self.stdout = code, out

    def fake_run(cmd, **kwargs):
        calls.append(cmd[0])
        if cmd[0] == "arp":
            raise FileNotFoundError("no arp here")
        return Result(0, LINUX_NEIGH)

    table = read_arp_table(runner=fake_run)
    assert calls == ["arp", "ip"]
    assert table["192.168.1.21"] == "b8:27:eb:aa:bb:cc"


def test_read_arp_table_returns_empty_when_nothing_works():
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    assert read_arp_table(runner=fake_run) == {}


def test_vendor_lookup_is_offline():
    assert lookup("b8:27:eb:aa:bb:cc") == "Raspberry Pi"
    assert lookup("00:00:00:00:00:00") == ""


def test_randomised_macs_are_labelled_not_treated_as_unknown_vendors():
    assert is_randomised("a2:bb:cc:dd:ee:ff")
    assert not is_randomised("b8:27:eb:aa:bb:cc")
    assert lookup("a2:bb:cc:dd:ee:ff") == "randomised"


@pytest.fixture
def conn(tmp_path):
    return store.connect(tmp_path / "history.db")


def test_scan_roundtrips_through_the_database(conn):
    devices = [
        Device(
            mac="aa:bb:cc:00:00:01", ip="192.168.1.10", vendor="Acme", ports=(22, 80)
        ),
        Device(mac="aa:bb:cc:00:00:02", ip="192.168.1.11", hostname="nas.local"),
    ]
    scan_id = store.record_scan(conn, "192.168.1.0/24", devices)
    assert store.load_scan(conn, scan_id) == devices, (
        "ports and blanks must survive the trip"
    )


def test_previous_devices_is_empty_for_the_very_first_scan(conn):
    scan_id = store.record_scan(conn, "192.168.1.0/24", [Device(mac="a", ip="1.1.1.1")])
    assert store.previous_devices(conn, scan_id) == []


def test_previous_devices_returns_the_scan_before(conn):
    first = [Device(mac="aa:bb:cc:00:00:01", ip="192.168.1.10")]
    second = [Device(mac="aa:bb:cc:00:00:02", ip="192.168.1.11")]
    store.record_scan(conn, "192.168.1.0/24", first)
    second_id = store.record_scan(conn, "192.168.1.0/24", second)
    assert store.previous_devices(conn, second_id) == first


def test_inventory_tracks_first_and_last_sighting(conn):
    device = Device(mac="aa:bb:cc:00:00:01", ip="192.168.1.10")
    store.record_scan(conn, "192.168.1.0/24", [device])
    store.record_scan(conn, "192.168.1.0/24", [])
    store.record_scan(
        conn, "192.168.1.0/24", [Device(mac="aa:bb:cc:00:00:01", ip="192.168.1.77")]
    )

    rows = store.inventory(conn)
    assert len(rows) == 1
    assert rows[0]["times_seen"] == 2, "the scan where it was absent must not count"
    assert rows[0]["ip"] == "192.168.1.77", "inventory shows the most recent details"


def test_first_seen_survives_the_device_changing_ip(conn):
    store.record_scan(
        conn, "192.168.1.0/24", [Device(mac="aa:bb:cc:00:00:01", ip="192.168.1.10")]
    )
    store.record_scan(
        conn, "192.168.1.0/24", [Device(mac="aa:bb:cc:00:00:01", ip="192.168.1.55")]
    )
    assert store.first_seen(conn, "aa:bb:cc:00:00:01") is not None


def find(rule="plaintext-protocol", device="192.168.1.10", title="Telnet on port 23"):
    return Finding(
        rule=rule,
        severity="high",
        device=device,
        title=title,
        evidence="banner",
        why="w",
        fix="f",
        verify="v",
    )


def test_findings_roundtrip_by_identity(conn):
    scan_id = store.record_scan(conn, "192.168.1.0/24", [])
    store.record_findings(conn, scan_id, [find()])
    assert store.finding_keys(conn, scan_id) == {
        ("plaintext-protocol", "192.168.1.10", "Telnet on port 23")
    }


def test_two_findings_of_one_rule_on_one_device_do_not_collide(conn):
    """FTP and Telnet on the same host are two problems, not one."""
    scan_id = store.record_scan(conn, "192.168.1.0/24", [])
    store.record_findings(
        conn, scan_id, [find(title="Telnet on port 23"), find(title="FTP on port 21")]
    )
    assert len(store.finding_keys(conn, scan_id)) == 2


def test_a_repeat_audit_finds_nothing_new(conn):
    first = store.record_scan(conn, "192.168.1.0/24", [])
    store.record_findings(conn, first, [find()])
    second = store.record_scan(conn, "192.168.1.0/24", [])
    store.record_findings(conn, second, [find()])

    seen = store.finding_keys(conn, store.last_audited_scan_id(conn, second))
    assert all((f.rule, f.device, f.title) in seen for f in [find()]), (
        "an unchanged network must not report NEW"
    )


def test_a_finding_that_appears_later_is_new(conn):
    first = store.record_scan(conn, "192.168.1.0/24", [])
    store.record_findings(conn, first, [find()])
    second = store.record_scan(conn, "192.168.1.0/24", [])
    fresh = find(rule="internet-exposed-service", title="port 8080 exposed")
    store.record_findings(conn, second, [find(), fresh])

    seen = store.finding_keys(conn, store.last_audited_scan_id(conn, second))
    assert (fresh.rule, fresh.device, fresh.title) not in seen
    assert (find().rule, find().device, find().title) in seen


def test_a_plain_scan_between_audits_does_not_reset_the_baseline(conn):
    """`netdiff scan` writes no findings; stepping back one scan would see none."""
    audited = store.record_scan(conn, "192.168.1.0/24", [])
    store.record_findings(conn, audited, [find()])
    store.record_scan(conn, "192.168.1.0/24", [])  # a plain scan, no findings
    latest = store.record_scan(conn, "192.168.1.0/24", [])

    assert store.last_audited_scan_id(conn, latest) == audited


def test_the_first_audit_ever_has_no_baseline(conn):
    scan_id = store.record_scan(conn, "192.168.1.0/24", [])
    assert store.last_audited_scan_id(conn, scan_id) is None
