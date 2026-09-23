"""The fields export is the cheap path. JSON is only for a row that does not line up."""

def test_opcode_names_match_wireshark():
    assert ac.opcode_name("0xb5") == "Get Cluster Config"
    assert "cluster map" in ac.opcode_description("0xb5")
    assert "pessimistic lock" in ac.opcode_description("0x94")
    assert ac.opcode_name("0x1d") == "Get and Touch"
    assert ac.opcode_name("0x94") == "Get Locked"
    assert ac.opcode_name("0xdf") == "0xdf"

import analyze_capture as ac


def _row(magic, opcode, opaque, key="", status="", body=""):
    return "\t".join(
        ["10", "1.5", "3", "10.0.0.2", "4000", "10.0.0.3", "11210", magic, opcode, opaque, key, status, body]
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


def test_gap_flags_share_the_couchbase_row_and_other_ports_drop():
    line = "\t".join(
        ["20", "4.0", "1", "10.0.0.3", "11210", "10.0.0.2", "4000", "0x18", "0x00", "0x3", "", "0x0", "24", "1", "", "1"]
    )
    messages, bad, loss = ac.messages_from_field_line(line)
    assert bad is None
    assert len(messages) == 1
    assert loss["lost"] and loss["ack"] and not loss["retrans"]
    only_gap = "\t".join(["21", "4.1", "9", "10.9.9.9", "80", "10.9.9.1", "443", "", "", "", "", "", "", "", "1", ""])
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
