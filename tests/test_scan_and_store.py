"""ARP parsing and persistence. No network is touched: parsing runs against
captured command output, and the database is a temp file."""

import sqlite3
import time

import pytest

from netdiff import cli, scan, store
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


# --- bounds and concurrency -------------------------------------------------
# A scan is almost entirely waiting on timeouts. Sequentially that cost is the
# sum over every device on the network, which is why these are timed rather than
# only checked for their return value - a pool that quietly stops being used
# still returns the right answer.


def test_a_subnet_larger_than_one_broadcast_segment_is_refused(monkeypatch):
    """And refused before anything is sent, not after 16.7M datagrams."""
    monkeypatch.setattr(scan, "nudge", lambda *a, **k: pytest.fail("sent packets"))
    with pytest.raises(ValueError, match="broadcast segment"):
        scan.discover("10.0.0.0/8")


def test_a_subnet_that_fits_is_not_refused(monkeypatch):
    monkeypatch.setattr(scan, "nudge", lambda *a, **k: None)
    monkeypatch.setattr(scan, "read_arp_table", dict)
    assert scan.discover("192.168.1.0/24", settle=0) == []


# --- working out where we are -----------------------------------------------

IP_ADDR_OUTPUT = (
    "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
    "2: eth0  inet 192.168.1.190/24 brd 192.168.1.255 scope global eth0\n"
)

MACOS_IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.190 netmask 0xffffff00 broadcast 192.168.1.255
"""

LINUX_IFCONFIG = """\
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.190  netmask 255.255.255.0  broadcast 192.168.1.255
"""


@pytest.fixture
def here(monkeypatch):
    """Pretend this machine is 192.168.1.190, without touching a socket."""
    monkeypatch.setattr(scan, "local_address", lambda: "192.168.1.190")


def runner_for(output, ok=("ip", "ifconfig")):
    def run(cmd, **kwargs):
        if cmd[0] not in ok:
            raise FileNotFoundError(cmd[0])

        class Result:
            returncode, stdout = 0, output

        return Result()

    return run


@pytest.mark.parametrize(
    "output", [IP_ADDR_OUTPUT, MACOS_IFCONFIG, LINUX_IFCONFIG], ids=["ip", "bsd", "gnu"]
)
def test_the_subnet_is_read_from_whichever_command_exists(here, output):
    """A CIDR, a hex mask and a dotted mask all mean the same /24."""
    assert scan.local_subnet(runner=runner_for(output)) == "192.168.1.0/24"


def test_a_mask_that_is_not_a_24_is_not_rounded_to_one(here):
    output = IP_ADDR_OUTPUT.replace("192.168.1.190/24", "192.168.1.190/22")
    assert scan.local_subnet(runner=runner_for(output)) == "192.168.0.0/22"


def test_an_unreadable_mask_asks_rather_than_assuming_24(here):
    """Guessing would be right most of the time, which is the wrong kind of right."""
    with pytest.raises(ValueError, match="pass one explicitly"):
        scan.local_subnet(runner=runner_for("no interfaces here"))


def test_the_loopback_line_is_not_mistaken_for_ours(here):
    """127.0.0.1/8 appears first and would give the whole of 127/8."""
    assert scan.local_subnet(runner=runner_for(MACOS_IFCONFIG)) == "192.168.1.0/24"


def test_an_omitted_subnet_is_filled_in_and_announced(monkeypatch, capsys):
    monkeypatch.setattr(cli, "local_subnet", lambda: "10.1.2.0/24")
    args = type("Args", (), {"subnet": None})()
    cli.resolve_subnet(args)
    assert args.subnet == "10.1.2.0/24"
    captured = capsys.readouterr()
    assert "10.1.2.0/24" in captured.err, "a scan must show its target"
    assert captured.out == "", "and must not put the notice inside --json output"


def test_an_explicit_subnet_is_left_alone(monkeypatch, capsys):
    monkeypatch.setattr(cli, "local_subnet", lambda: pytest.fail("should not detect"))
    args = type("Args", (), {"subnet": "192.168.9.0/24"})()
    cli.resolve_subnet(args)
    assert args.subnet == "192.168.9.0/24"
    assert capsys.readouterr().out == ""


def test_a_bad_subnet_is_a_message_not_a_traceback(capsys):
    assert cli.main(["scan", "not-a-subnet"]) == 2
    assert capsys.readouterr().err.strip(), "the reason has to reach the user"


def test_devices_are_scanned_concurrently(monkeypatch):
    table = {f"192.168.1.{n}": f"aa:bb:cc:00:00:{n:02x}" for n in range(1, 13)}
    monkeypatch.setattr(scan, "nudge", lambda *a, **k: None)
    monkeypatch.setattr(scan, "read_arp_table", lambda: table)
    monkeypatch.setattr(scan, "ttl_hint", lambda ip: time.sleep(0.2) or "")
    monkeypatch.setattr(
        scan, "_port_open", lambda ip, port, timeout=0.3: time.sleep(0.2) or False
    )

    start = time.monotonic()
    devices = scan.discover(
        "192.168.1.0/24", ports=(22,), settle=0, resolve_names=False
    )
    elapsed = time.monotonic() - start

    assert [d.ip for d in devices] == sorted(
        table, key=lambda ip: int(ip.split(".")[3])
    )
    assert elapsed < 1.0, f"12 devices x 0.4s took {elapsed:.1f}s - run sequentially?"


def test_a_long_port_list_costs_one_timeout_not_a_hundred(monkeypatch):
    """The point of `--ports top100`: ports overlap, they do not queue."""
    monkeypatch.setattr(
        scan, "_port_open", lambda ip, port, timeout=0.3: time.sleep(0.2) or False
    )
    start = time.monotonic()
    assert scan.scan_ports("192.168.1.10", scan.TOP_100_PORTS) == ()
    elapsed = time.monotonic() - start
    assert elapsed < 1.0, f"100 ports x 0.2s took {elapsed:.1f}s - run sequentially?"


def test_banners_are_gathered_concurrently(monkeypatch):
    pairs = [("192.168.1.10", port) for port in range(8000, 8012)]
    monkeypatch.setattr(
        scan, "grab_banner", lambda ip, port, timeout=2.0: time.sleep(0.2) or f"{port}"
    )

    start = time.monotonic()
    banners = scan.grab_banners(pairs)
    elapsed = time.monotonic() - start

    assert banners == {pair: str(pair[1]) for pair in pairs}
    assert elapsed < 1.0, f"12 ports x 0.2s took {elapsed:.1f}s - run sequentially?"


def test_no_open_ports_means_no_banner_work():
    assert scan.grab_banners([]) == {}


# --- choosing what to scan, and guessing what answered -----------------------


def test_a_named_port_set_expands_to_its_ports():
    assert scan.resolve_ports(["top100"]) == scan.TOP_100_PORTS
    assert scan.resolve_ports(["default"]) == tuple(sorted(scan.DEFAULT_PORTS))


def test_numbers_and_a_set_can_be_mixed_and_are_deduplicated():
    assert scan.resolve_ports(["default", "22", "32400"]) == tuple(
        sorted(set(scan.DEFAULT_PORTS) | {32400})
    )


@pytest.mark.parametrize("bad", ["top1000", "0", "65536", "-1", "80/tcp", ""])
def test_something_that_is_neither_is_a_message_not_a_traceback(bad):
    with pytest.raises(ValueError, match="not a port number"):
        scan.resolve_ports([bad])


def test_the_top_100_is_a_hundred_ports_in_order():
    assert len(set(scan.TOP_100_PORTS)) == 100
    assert list(scan.TOP_100_PORTS) == sorted(scan.TOP_100_PORTS)


@pytest.mark.parametrize(
    "ttl, expect", [(64, "Linux"), (128, "Windows"), (255, "network gear")]
)
def test_a_ttl_suggests_an_os_family_and_says_it_is_a_guess(ttl, expect):
    hint = scan.os_family(ttl)
    assert expect in hint
    assert "?" in hint and str(ttl) in hint, "a guess has to look like one"


def test_an_unrecognised_ttl_is_reported_as_a_number_not_a_family():
    """32 is not "nearly 64". Rounding it into a family would be invention."""
    assert scan.os_family(32) == "TTL 32"


def test_a_ttl_nothing_could_have_sent_claims_nothing():
    assert scan.os_family(0) == ""
    assert scan.os_family(300) == ""


def test_the_ttl_is_read_from_a_real_ping_line():
    line = "64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=2.508 ms"
    assert scan.ttl_hint("192.168.1.1", runner=fake_runner(line)) == scan.os_family(64)


def test_a_host_that_drops_icmp_has_no_hint_rather_than_a_wrong_one():
    assert scan.ttl_hint("192.168.1.9", runner=fake_runner("")) == ""


def fake_runner(stdout):
    class Result:
        returncode = 0

    Result.stdout = stdout
    return lambda *a, **k: Result()


@pytest.fixture
def conn(tmp_path):
    return store.connect(tmp_path / "history.db")


def test_scan_roundtrips_through_the_database(conn):
    devices = [
        Device(
            mac="aa:bb:cc:00:00:01",
            ip="192.168.1.10",
            vendor="Acme",
            services="Chromecast",
            ports=(22, 80),
            os_hint="Linux, macOS or BSD? (TTL 64)",
        ),
        Device(mac="aa:bb:cc:00:00:02", ip="192.168.1.11", hostname="nas.local"),
    ]
    scan_id = store.record_scan(conn, "192.168.1.0/24", devices)
    assert store.load_scan(conn, scan_id) == devices, (
        "ports, services, the OS hint and blanks must survive the trip"
    )


# The observations table as it shipped before `services` existed. Databases in
# this shape are on real machines with months of history in them.
SCHEMA_BEFORE_SERVICES = """
CREATE TABLE scans (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    started   TEXT NOT NULL,
    subnet    TEXT NOT NULL
);
CREATE TABLE observations (
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    mac       TEXT NOT NULL,
    ip        TEXT NOT NULL,
    vendor    TEXT NOT NULL DEFAULT '',
    hostname  TEXT NOT NULL DEFAULT '',
    ports     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, mac)
);
"""


def old_database(path):
    """A history file written by the previous release, with one scan in it."""
    legacy = sqlite3.connect(path)
    legacy.executescript(SCHEMA_BEFORE_SERVICES)
    legacy.execute("INSERT INTO scans (started, subnet) VALUES ('2026-01-01', 'x')")
    legacy.execute(
        "INSERT INTO observations (scan_id, mac, ip, vendor, hostname, ports)"
        " VALUES (1, 'aa:bb:cc:00:00:01', '192.168.1.10', 'Acme', 'nas.local', '22,80')"
    )
    legacy.commit()
    legacy.close()
    return path


def columns_of(conn, table="observations"):
    """Each column as name -> (type, notnull, default).

    Deliberately not a list: `ALTER TABLE` appends and `SCHEMA` inserts, so a
    migrated database orders its columns differently from a fresh one. Nothing
    in netdiff selects `*`, so that difference is invisible - and pinning the
    order here would be asserting something the code does not rely on.
    """
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r[1]: (r[2], r[3], r[4]) for r in rows}


def test_an_existing_database_gains_the_services_column(tmp_path):
    """CREATE TABLE IF NOT EXISTS does nothing to a table that already exists,
    so without the migration every read of `services` fails on exactly the
    databases worth keeping - the ones with history in them."""
    path = old_database(tmp_path / "history.db")
    devices = store.load_scan(store.connect(path), 1)

    assert devices == [
        Device(
            mac="aa:bb:cc:00:00:01",
            ip="192.168.1.10",
            vendor="Acme",
            hostname="nas.local",
            ports=(22, 80),
        )
    ], "old rows read back intact, with an empty services"


def test_migrating_twice_changes_nothing(tmp_path):
    """Every `netdiff` command opens the database, so this runs constantly."""
    path = old_database(tmp_path / "history.db")
    store.connect(path).close()
    conn = store.connect(path)

    assert "services" in columns_of(conn)
    assert store.load_scan(conn, 1)[0].hostname == "nas.local"


def test_a_migrated_database_matches_a_fresh_one(tmp_path, conn):
    """SCHEMA and ADDED_COLUMNS are two descriptions of one shape, and nothing
    stops them drifting apart except this."""
    migrated = store.connect(old_database(tmp_path / "old.db"))
    assert columns_of(migrated) == columns_of(conn)


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


def find(
    rule="plaintext-protocol",
    device="192.168.1.10",
    title="Telnet on port 23",
    evidence="banner",
):
    return Finding(
        rule=rule,
        severity="high",
        device=device,
        title=title,
        evidence=evidence,
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


def test_two_forwards_differing_only_in_protocol_are_both_kept(conn):
    """A TCP and a UDP forward on the same external port are two doors.

    Their rule, device and title are identical - only the evidence, which is the
    router's own `str(Mapping)` line, carries the protocol. Without evidence in
    the primary key the second silently replaced the first, and the audit that
    the database recorded was not the audit that was printed.
    """
    scan_id = store.record_scan(conn, "192.168.1.0/24", [])
    store.record_findings(
        conn,
        scan_id,
        [
            find(title="port 8080 forwarded", evidence="*:8080/tcp -> 192.168.1.10:80"),
            find(title="port 8080 forwarded", evidence="*:8080/udp -> 192.168.1.10:80"),
        ],
    )
    rows = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    assert rows == 2


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
