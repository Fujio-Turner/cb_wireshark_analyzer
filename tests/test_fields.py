"""The fields export is the cheap path. JSON is only for a row that does not line up."""

import analyze_capture as ac


def _row(magic, opcode, opaque, key="", status=""):
    return "\t".join(
        ["10", "1.5", "3", "10.0.0.2", "4000", "10.0.0.3", "11210", magic, opcode, opaque, key, status]
    )


def test_one_message_per_repeated_field():
    agg = ac.FIELD_AGG
    line = _row(
        agg.join(["0x80", "0x80"]),
        agg.join(["0x00", "0x01"]),
        agg.join(["0x1", "0x2"]),
        agg.join(["doc::a", "doc::b"]),
    )
    messages, bad = ac.messages_from_field_line(line)
    assert bad is None
    assert [msg["key"] for msg in messages] == ["doc::a", "doc::b"]
    assert messages[0]["magic"] == 0x80
    assert messages[1]["opcode"] == "0x01"
    assert messages[0]["opaque"] == "0x00000001"
    assert messages[0]["status"] == ""


def test_blank_column_applies_to_every_message():
    agg = ac.FIELD_AGG
    line = _row(agg.join(["0x18", "0x18"]), agg.join(["0x00", "0x01"]), agg.join(["0xa", "0xb"]), "", agg.join(["0x0", "0x9"]))
    messages, bad = ac.messages_from_field_line(line)
    assert bad is None
    assert [msg["key"] for msg in messages] == ["", ""]
    assert [msg["status"] for msg in messages] == ["0x0000", "0x0009"]
    assert all(msg["magic"] == 0x18 for msg in messages)


def test_shifted_column_is_handed_back_for_a_second_read():
    agg = ac.FIELD_AGG
    line = _row(agg.join(["0x80", "0x80"]), agg.join(["0x00", "0x01"]), agg.join(["0x1", "0x2"]), "only-the-first")
    messages, bad = ac.messages_from_field_line(line)
    assert messages == []
    assert bad == "10"


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
