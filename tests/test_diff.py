"""The change-detection logic, which is the whole reason this tool exists."""

from netdiff.diff import diff, summarise
from netdiff.scan import Device


def dev(mac="aa:bb:cc:00:00:01", ip="192.168.1.10", hostname="", ports=(), vendor=""):
    return Device(mac=mac, ip=ip, hostname=hostname, ports=tuple(ports), vendor=vendor)


def kinds(changes):
    return [c.kind for c in changes]


def test_no_changes_between_identical_scans():
    scan = [dev(), dev(mac="aa:bb:cc:00:00:02", ip="192.168.1.11")]
    assert diff(scan, scan) == []
    assert summarise([]) == "no changes"


def test_new_device_appears():
    before = [dev()]
    after = [dev(), dev(mac="de:ad:be:ef:00:01", ip="192.168.1.99")]
    changes = diff(before, after)
    assert kinds(changes) == ["appeared"]
    assert changes[0].device.mac == "de:ad:be:ef:00:01"


def test_device_vanishes():
    changes = diff([dev()], [])
    assert kinds(changes) == ["vanished"]


def test_dhcp_lease_change_is_one_device_moving_not_two_events():
    """The regression this tool exists to avoid: MAC is identity, IP is not."""
    before = [dev(ip="192.168.1.10")]
    after = [dev(ip="192.168.1.55")]
    changes = diff(before, after)
    assert kinds(changes) == ["ip-changed"]
    assert "192.168.1.10 -> 192.168.1.55" in changes[0].detail
    assert "appeared" not in kinds(changes)
    assert "vanished" not in kinds(changes)


def test_newly_open_port_is_reported():
    changes = diff([dev(ports=[22])], [dev(ports=[22, 8080])])
    assert kinds(changes) == ["port-opened"]
    assert "8080" in changes[0].detail


def test_closed_port_is_reported_separately():
    changes = diff([dev(ports=[22, 8080])], [dev(ports=[22])])
    assert kinds(changes) == ["port-closed"]
    assert "8080" in changes[0].detail


def test_open_and_closed_ports_in_one_scan_are_distinct_changes():
    changes = diff([dev(ports=[22, 80])], [dev(ports=[80, 443])])
    assert sorted(kinds(changes)) == ["port-closed", "port-opened"]


def test_hostname_change_reported_but_blank_to_blank_is_not():
    assert kinds(diff([dev(hostname="")], [dev(hostname="")])) == []
    changes = diff([dev(hostname="old.local")], [dev(hostname="new.local")])
    assert kinds(changes) == ["hostname-changed"]


def test_serious_changes_sort_before_cosmetic_ones():
    before = [dev(mac="aa:bb:cc:00:00:01", hostname="a.local")]
    after = [
        dev(mac="aa:bb:cc:00:00:01", hostname="b.local"),
        dev(mac="ff:ff:ff:00:00:09", ip="192.168.1.200"),
    ]
    changes = diff(before, after)
    assert changes[0].kind == "appeared"
    assert changes[-1].kind == "hostname-changed"


def test_diff_is_deterministic():
    """Alerts get compared and deduplicated; unstable ordering breaks that."""
    before = [
        dev(mac=f"aa:bb:cc:00:00:{i:02x}", ip=f"192.168.1.{i}") for i in range(1, 8)
    ]
    after = [
        dev(mac=f"aa:bb:cc:00:00:{i:02x}", ip=f"192.168.1.{i}") for i in range(4, 12)
    ]
    first = [str(c) for c in diff(before, after)]
    second = [str(c) for c in diff(before, after)]
    assert first == second


def test_summarise_counts_each_kind():
    changes = diff([dev()], [dev(mac="11:22:33:44:55:66", ip="192.168.1.77")])
    assert "1 appeared" in summarise(changes)
    assert "1 vanished" in summarise(changes)


def test_a_scan_that_skipped_ports_reports_no_port_changes():
    """`--no-ports` must not read as "every port closed".

    A device with nothing scanned and a device with nothing open are the same
    empty tuple here, so this is the one case the data cannot distinguish on its
    own - the caller has to say. Reporting it wrongly is a false alert, which is
    worse than no alert.
    """
    was = [Device(mac="aa:bb:cc:00:00:01", ip="192.168.1.10", ports=(22, 80))]
    now = [Device(mac="aa:bb:cc:00:00:01", ip="192.168.1.10", ports=())]

    assert [c.kind for c in diff(was, now)] == ["port-closed"]
    assert diff(was, now, compare_ports=False) == []


def test_skipping_ports_still_reports_everything_else():
    was = [Device(mac="aa:bb:cc:00:00:01", ip="192.168.1.10", ports=(22,))]
    now = [Device(mac="aa:bb:cc:00:00:01", ip="192.168.1.99", ports=())]
    assert [c.kind for c in diff(was, now, compare_ports=False)] == ["ip-changed"]
