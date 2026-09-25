"""The fields export is the cheap path. JSON is only for a row that does not line up."""

def test_opcode_names_match_wireshark():
    assert ac.opcode_name("0xb5") == "Get Cluster Config"
    assert "cluster map" in ac.opcode_description("0xb5")
    assert "pessimistic lock" in ac.opcode_description("0x94")
    assert ac.opcode_name("0x1d") == "Get and Touch"
    assert ac.opcode_name("0x94") == "Get Locked"
    assert ac.opcode_name("0xdf") == "0xdf"

import analyze_capture as ac


def _row(
    magic, opcode, opaque, key="", status="", body="", ack="", raw_key="",
    vbucket="", duration="", durability="", snap_memory="", snap_disk="",
    snap_start="", snap_end="", bytes_ack="", ttp="", ttr="", replica_read="",
):
    return "\t".join(
        [
            "10", "1.5", "3", "10.0.0.2", "4000", "10.0.0.3", "11210",
            magic, opcode, opaque, key, raw_key, status, body, ack,
            vbucket, duration, durability, snap_memory, snap_disk, snap_start, snap_end, bytes_ack,
            ttp, ttr, replica_read,
        ]
    )


def test_one_message_per_repeated_field():
    agg = ac.FIELD_AGG
    line = _row(
        agg.join(["0x80", "0x80"]),
        agg.join(["0x00", "0x01"]),
        agg.join(["0x1", "0x2"]),
        agg.join(["doc::a", "doc::b"]),
    )
    messages, bad, loss = ac.messages_from_field_line(line)
    assert bad is None
    assert loss is None
    assert [msg["key"] for msg in messages] == ["doc::a", "doc::b"]
    assert messages[0]["magic"] == 0x80
    assert messages[1]["opcode"] == "0x01"
    assert messages[0]["opaque"] == "0x00000001"
    assert messages[0]["status"] == ""
    assert messages[0]["body"] == 0


def test_blank_column_applies_to_every_message():
    agg = ac.FIELD_AGG
    line = _row(agg.join(["0x18", "0x18"]), agg.join(["0x00", "0x01"]), agg.join(["0xa", "0xb"]), "", agg.join(["0x0", "0x9"]))
    messages, bad, loss = ac.messages_from_field_line(line)
    assert bad is None
    assert loss is None
    assert [msg["key"] for msg in messages] == ["", ""]
    assert [msg["status"] for msg in messages] == ["0x0000", "0x0009"]
    assert all(msg["magic"] == 0x18 for msg in messages)


def test_body_length_stays_with_its_message():
    agg = ac.FIELD_AGG
    line = _row(
        agg.join(["0x80", "0x18"]),
        agg.join(["0x01", "0x00"]),
        agg.join(["0x1", "0x1"]),
        agg.join(["doc::a", ""]),
        "",
        agg.join(["1048576", "24"]),
    )
    messages, bad, loss = ac.messages_from_field_line(line)
    assert bad is None
    assert loss is None
    assert [msg["body"] for msg in messages] == [1048576, 24]


def test_stat_key_comes_from_couchbase_key_when_the_logical_key_is_empty():
    line = _row("0x80", "0x10", "0xde030e00", "", "", "13", "", "vbucket-seqno")
    messages, bad, _loss = ac.messages_from_field_line(line)
    assert bad is None
    assert messages[0]["key"] == "vbucket-seqno"
    assert ac.traffic_role(messages[0]["sport"], messages[0]["dport"], messages[0]["opcode"], messages[0]["key"]) == "cluster"


def test_duration_vbucket_and_durability_stay_on_the_message():
    line = _row(
        "0x81", "0x01", "0x10", "doc", "0x0000", "24", "", "",
        vbucket="689", duration="56.5", durability="0x02", bytes_ack="",
    )
    messages, bad, _loss = ac.messages_from_field_line(line)
    assert bad is None
    assert messages[0]["vbucket"] == 689
    assert messages[0]["server_us"] == 56.5
    assert messages[0]["durability"] == 2
    assert messages[0]["bytes_to_ack"] is None
    assert messages[0]["ttp"] is None
    assert messages[0]["ttr"] is None
    timed = _row("0x81", "0x01", "0x12", "doc", "0x0000", "8", ttp="0", ttr="40")
    timed_messages, timed_bad, _loss = ac.messages_from_field_line(timed)
    assert timed_bad is None
    assert timed_messages[0]["ttp"] == 0
    assert timed_messages[0]["ttr"] == 40
    disk = _row("0x80", "0x56", "0x11", "", "", "20", "", "", snap_disk="True", snap_start="10", snap_end="40", bytes_ack="4096")
    marker, marker_bad, _loss = ac.messages_from_field_line(disk)
    assert marker_bad is None
    assert marker[0]["snapshot_disk"] is True
    assert marker[0]["snapshot_memory"] is False
    assert marker[0]["snap_start"] == 10
    assert marker[0]["snap_end"] == 40
    assert marker[0]["bytes_to_ack"] == 4096


def test_snapshot_ack_flag_marks_that_marker_as_wanting_a_reply():
    line = _row("0x80", "0x56", "0x10", "", "", "20", "True")
    messages, bad, _loss = ac.messages_from_field_line(line)
    assert bad is None
    assert messages[0]["snapshot_ack"] is True
    paired = ac.pair_messages(messages, [])
    assert paired["no_reply"] == []
    assert len(paired["unanswered"]) == 1
    quiet = _row("0x80", "0x56", "0x11", "", "", "20", "")
    quiet_messages, quiet_bad, _loss = ac.messages_from_field_line(quiet)
    assert quiet_bad is None
    assert ac.pair_messages(quiet_messages, [])["no_reply"]


def test_shifted_column_is_handed_back_for_a_second_read():
    agg = ac.FIELD_AGG
    line = _row(agg.join(["0x80", "0x80"]), agg.join(["0x00", "0x01"]), agg.join(["0x1", "0x2"]), "only-the-first")
    messages, bad, loss = ac.messages_from_field_line(line)
    assert messages == []
    assert bad == "10"
    assert loss is None


def test_same_size_files_group_together_and_different_sizes_do_not(tmp_path):
    same_a = tmp_path / "a.pcap"
    same_b = tmp_path / "b.pcap"
    other = tmp_path / "c.pcap"
    same_a.write_bytes(b"same-bytes")
    same_b.write_bytes(b"same-bytes")
    other.write_bytes(b"different")
    groups = ac.unique_pcaps([same_b, other, same_a])
    assert len(groups) == 2
    bundled = next(members for _rep, members in groups if len(members) == 2)
    assert {path.name for path in bundled} == {"a.pcap", "b.pcap"}


def test_packet_kind_splits_couchbase_and_tcp():
    assert ac.packet_kind(True, True, True, False, "DCP Snapshot Marker", False, 100) == "DCP Snapshot Marker request"
    assert ac.packet_kind(False, False, True, False, "", False, 100, True) == "Capture duplicate"
    assert ac.is_capture_duplicate(True, 0.000001) is True
    assert ac.is_capture_duplicate(True, None) is True
    assert ac.is_capture_duplicate(True, 0.2) is False
    assert ac.packet_kind(False, True, True, False, "", False, 100) == "Lost segment"
    assert ac.packet_kind(False, False, True, False, "", False, 100) == "Retransmission"
    assert ac.packet_kind(True, False, False, False, "Get", False, 100) == "Get request"
    assert ac.packet_kind(True, False, False, False, "Set", True, 20) == "Set response"
    assert ac.packet_kind(False, False, False, False, "", False, 0) == "TCP ACK"
    assert ac.packet_kind(False, False, False, False, "", False, 1460) == "TCP data segment"


def test_kv_port_is_either_side():
    assert ac.on_kv_port("4000", "11210")
    assert ac.on_kv_port("11210", "4000")
    assert not ac.on_kv_port("80", "443")


def test_gap_flags_share_the_couchbase_row_and_other_ports_drop():
    couchbase = ["0x18", "0x00", "0x3", "", "", "0x0", "24", ""] + [""] * (ac._CB_COLUMNS - 8)
    line = "\t".join(
        ["20", "4.0", "1", "10.0.0.3", "11210", "10.0.0.2", "4000", *couchbase, "1", "", "1"]
    )
    messages, bad, loss = ac.messages_from_field_line(line)
    assert bad is None
    assert len(messages) == 1
    assert loss["lost"] and loss["ack"] and not loss["retrans"]
    only_gap = "\t".join(
        ["21", "4.1", "9", "10.9.9.9", "80", "10.9.9.1", "443", *[""] * ac._CB_COLUMNS, "", "1", ""]
    )
    no_messages, no_bad, other = ac.messages_from_field_line(only_gap)
    assert no_messages == []
    assert no_bad is None
    assert other["retrans"]
    summary = ac.summarize_loss([loss, other], ["11210"])
    assert summary["lost_segments"] == 1
    assert summary["ack_lost_segments"] == 1
    assert summary["retransmissions"] == 0
    assert summary["server_to_client"] == 1
    assert summary["lost_by_stream"] == {"1": 1}
