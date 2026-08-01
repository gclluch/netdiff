"""mDNS parsing against hand-built packets. No network is touched - the same
approach as the ARP fixtures in test_scan_and_store.py and the router XML in
test_upnp.py.

The packets here are assembled by local helpers rather than by `mdns.encode_name`,
because a decoder tested only against its own encoder agrees with itself no matter
how wrong both are. `test_the_wire_format_is_what_we_think_it_is` pins the helpers
against a literal captured off the wire, so the rest of the file rests on bytes and
not on assumptions.

Half of these are malformed inputs. A device that answers badly - or hostilely -
must cost us that one device, never the scan.
"""

import struct

from netdiff import mdns

# --- packet builders ---------------------------------------------------------


def name(text):
    """A DNS name: each label length-prefixed, terminated by a zero byte."""
    out = b""
    for label in text.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def record(owner, rtype, rdata, ttl=120):
    """One resource record. `owner` may be raw bytes to place a pointer."""
    head = owner if isinstance(owner, bytes) else name(owner)
    return head + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


def message(*records, answers=None):
    """A response packet. `answers` overrides the count, to lie about it."""
    count = len(records) if answers is None else answers
    return struct.pack("!HHHHHH", 0, 0x8400, 0, count, 0, 0) + b"".join(records)


def txt(**pairs):
    """TXT rdata: a run of length-prefixed `key=value` strings."""
    out = b""
    for key, value in pairs.items():
        chunk = f"{key}={value}".encode()
        out += bytes([len(chunk)]) + chunk
    return out


POINTER_TO_OFFSET_12 = b"\xc0\x0c"


def test_the_wire_format_is_what_we_think_it_is():
    """The literal is the first name in a real reply this Mac sent, captured off
    the LAN. If the builders above are wrong, everything else here is theatre."""
    assert name("_services._dns-sd._udp.local") == (
        b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    )
    assert mdns.encode_name("_services._dns-sd._udp.local") == name(
        "_services._dns-sd._udp.local"
    )


# --- names and compression ---------------------------------------------------


def test_a_compressed_name_is_followed_to_where_it_points():
    data = message(record("_airplay._tcp.local", mdns.TYPE_PTR, name("tv.local")))
    assert mdns.decode_name(data, 12)[0] == "_airplay._tcp.local"


def test_a_pointer_resumes_after_the_pointer_not_after_the_target():
    """The two-byte pointer is what the reader consumes; the target may sit
    anywhere. Getting this wrong desynchronises every record that follows."""
    data = message(record("printer.local", mdns.TYPE_A, bytes([192, 168, 1, 5])))
    _, after = mdns.decode_name(data + POINTER_TO_OFFSET_12, len(data))
    assert after == len(data) + 2


def test_a_pointer_loop_is_abandoned_rather_than_followed_forever():
    """A name that points at itself is malformed input, not a name. Unbounded,
    this is a hang triggerable by anything that can send us a packet."""
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    label, after = mdns.decode_name(header + POINTER_TO_OFFSET_12, 12)
    assert label == ""
    assert after == 14, "the reader still moves past the pointer"


def test_two_pointers_chasing_each_other_also_terminate():
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    pair = b"\xc0\x0e" + b"\xc0\x0c"  # offset 12 -> 14, offset 14 -> 12
    assert mdns.decode_name(header + pair, 12)[0] == ""


def test_a_label_running_off_the_end_yields_what_was_there():
    """A label claiming nine bytes with five behind it. Reading what arrived and
    stopping beats raising: it costs one name, not the whole reply."""
    assert mdns.decode_name(b"\x09_serv", 0)[0] == "_serv"


# --- record parsing ----------------------------------------------------------


def test_records_are_read_past_the_question_section():
    """Our own multicast query comes back to us, questions and all, because we
    joined the group we sent to."""
    query = struct.pack("!HHHHHH", 0, 0, 1, 1, 0, 0)
    query += name("_airplay._tcp.local") + struct.pack("!HH", mdns.TYPE_PTR, 1)
    query += record("_airplay._tcp.local", mdns.TYPE_PTR, name("tv.local"))

    assert mdns.parse_records(query) == [
        ("_airplay._tcp.local", mdns.TYPE_PTR, "tv.local")
    ]


def test_an_a_record_becomes_a_dotted_address():
    data = message(record("printer.local", mdns.TYPE_A, bytes([192, 168, 1, 5])))
    assert mdns.parse_records(data) == [("printer.local", mdns.TYPE_A, "192.168.1.5")]


def test_an_srv_target_is_read_past_its_priority_weight_and_port():
    data = message(
        record(
            "tv._airplay._tcp.local",
            mdns.TYPE_SRV,
            struct.pack("!HHH", 0, 0, 7000) + name("tv.local"),
        )
    )
    assert mdns.parse_records(data)[0][2] == "tv.local"


def test_unreadable_record_types_are_stepped_over_not_choked_on():
    """AAAA and NSEC records arrive in every real reply and mean nothing to us,
    but the records after them do."""
    data = message(
        record("tv.local", 28, b"\xfe\x80" + b"\x00" * 14),  # AAAA
        record("tv.local", mdns.TYPE_A, bytes([192, 168, 1, 5])),
    )
    assert mdns.parse_records(data)[-1][2] == "192.168.1.5"


def test_a_truncated_record_yields_what_was_read_before_it():
    whole = message(
        record("printer.local", mdns.TYPE_A, bytes([192, 168, 1, 5])),
        record("tv.local", mdns.TYPE_A, bytes([192, 168, 1, 9])),
    )
    assert mdns.parse_records(whole[:-3]) == [
        ("printer.local", mdns.TYPE_A, "192.168.1.5")
    ]


def test_a_header_claiming_more_records_than_it_carries_is_survivable():
    data = message(
        record("printer.local", mdns.TYPE_A, bytes([192, 168, 1, 5])), answers=99
    )
    assert len(mdns.parse_records(data)) == 1


def test_a_message_too_short_to_hold_a_header_is_not_an_error():
    assert mdns.parse_records(b"") == []
    assert mdns.parse_records(b"\x00\x01\x02") == []


# --- TXT ---------------------------------------------------------------------


def test_txt_pairs_are_split_on_the_first_equals():
    data = message(record("tv.local", mdns.TYPE_TXT, txt(model="Mac15,7", fex="a=b=c")))
    assert mdns.parse_records(data)[0][2] == {"model": "Mac15,7", "fex": "a=b=c"}


def test_txt_keys_are_lowercased_because_devices_disagree_on_case():
    data = message(record("tv.local", mdns.TYPE_TXT, txt(MD="Chromecast")))
    assert mdns.parse_records(data)[0][2] == {"md": "Chromecast"}


def test_a_txt_string_with_no_value_is_kept_as_an_empty_one():
    """`\\x02id` is a flag, not a malformed pair - it says something by existing."""
    data = message(record("tv.local", mdns.TYPE_TXT, b"\x02id"))
    assert mdns.parse_records(data)[0][2] == {"id": ""}


def test_an_empty_txt_string_is_dropped_rather_than_keyed_on_nothing():
    data = message(record("tv.local", mdns.TYPE_TXT, b"\x00" + b"\x03a=b"))
    assert mdns.parse_records(data)[0][2] == {"a": "b"}


# --- describing a device -----------------------------------------------------


def test_a_stated_model_beats_an_inferred_service_label():
    """`model=Mac15,7` is the device answering the question directly. A service
    label is us translating what it offers into what it probably is."""
    records = [
        ("mac._device-info._tcp.local", mdns.TYPE_TXT, {"model": "Mac15,7"}),
        ("_services._dns-sd._udp.local", mdns.TYPE_PTR, "_airplay._tcp.local"),
    ]
    assert mdns.describe(records).startswith("Mac15,7")


def test_a_service_type_is_named_whether_it_arrives_as_owner_or_target():
    """The meta-query answer names a type in the target; a direct query for that
    type names an instance in the owner. Both identify the device."""
    as_target = [
        ("_services._dns-sd._udp.local", mdns.TYPE_PTR, "_googlecast._tcp.local")
    ]
    as_owner = [
        ("_googlecast._tcp.local", mdns.TYPE_PTR, "living-room._googlecast._tcp.local")
    ]
    assert mdns.describe(as_target) == "Chromecast"
    assert mdns.describe(as_owner) == "Chromecast"


def test_a_service_announced_twice_is_only_said_once():
    records = [
        ("_services._dns-sd._udp.local", mdns.TYPE_PTR, "_airplay._tcp.local"),
        ("_airplay._tcp.local", mdns.TYPE_PTR, "tv._airplay._tcp.local"),
    ]
    assert mdns.describe(records) == "AirPlay"


def test_a_device_announcing_everything_is_not_described_by_a_paragraph():
    records = [
        ("_services._dns-sd._udp.local", mdns.TYPE_PTR, f"{svc}._tcp.local")
        for svc in ("_airplay", "_raop", "_smb", "_ssh", "_http")
    ]
    assert mdns.describe(records).count(",") == 2, "three parts, not five"


def test_a_device_offering_nothing_we_have_a_word_for_describes_as_nothing():
    """Better silent than confidently wrong. The tool this replaced called a
    printer a "Managed Web Server" rather than admit it did not know."""
    records = [("_services._dns-sd._udp.local", mdns.TYPE_PTR, "_obscure._tcp.local")]
    assert mdns.describe(records) == ""


# --- discover ----------------------------------------------------------------


def test_replies_are_attributed_to_the_address_that_sent_them():
    tv = message(
        record("_services._dns-sd._udp.local", mdns.TYPE_PTR, name("_googlecast._tcp"))
    )
    printer = message(
        record("_services._dns-sd._udp.local", mdns.TYPE_PTR, name("_ipp._tcp"))
    )
    found = mdns.discover(
        sender=lambda t: [("192.168.1.5", tv), ("192.168.1.9", printer)]
    )
    assert found == {"192.168.1.5": "Chromecast", "192.168.1.9": "Printer"}


def test_several_packets_from_one_device_are_merged_into_one_description():
    """A device with a lot to say sends several datagrams, and the model can
    arrive in a different one from the services."""
    info = message(
        record("mac._device-info._tcp.local", mdns.TYPE_TXT, txt(model="Mac15,7"))
    )
    services = message(
        record("_services._dns-sd._udp.local", mdns.TYPE_PTR, name("_airplay._tcp"))
    )
    found = mdns.discover(
        sender=lambda t: [("192.168.1.5", info), ("192.168.1.5", services)]
    )
    assert found == {"192.168.1.5": "Mac15,7, AirPlay"}


def test_a_device_we_cannot_describe_is_absent_rather_than_present_and_blank():
    """An empty string here would print as an empty pair of brackets and read as
    a bug. Not knowing is the normal case, not a finding."""
    quiet = message(record("thing.local", mdns.TYPE_A, bytes([192, 168, 1, 5])))
    assert mdns.discover(sender=lambda t: [("192.168.1.5", quiet)]) == {}


def test_our_own_query_coming_back_to_us_names_no_device():
    """We joined the multicast group we send to, so we receive our own question.
    It carries every service name we asked about and must describe nothing."""
    echo = mdns.encode_query((mdns.SERVICE_ENUM, *mdns.COMMON_SERVICES), unicast=False)
    assert mdns.discover(sender=lambda t: [("192.168.1.190", echo)]) == {}
