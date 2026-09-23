"""Field-export parsing."""

import analyze_capture as ac


def test_comma_joined_request_row_splits_into_messages(tmp_path):
    reqs = tmp_path / "reqs.tsv"
    resps = tmp_path / "resps.tsv"
    reqs.write_text(
        "10\t1.0\t0\t10.0.0.2\t40000\t10.0.0.3\t11210\t0x00,0x01\t0x0000000a,0x0000000b\tleft,right\n"
        "11\t2.0\t0\t10.0.0.2\t40000\t10.0.0.3\t11210\t0x00\t0x0000000c\tok\n"
    )
    resps.write_text(
        "12\t1.02\t0\t0x00\t0x0000000a\t0x0000\n"
        "13\t2.01\t0\t0x00\t0x0000000c\t0x0000\n"
    )
    loaded_reqs, loaded_resps, joined = ac.load_tsv_pair(reqs, resps)
    assert joined == 1
    assert len(loaded_reqs) == 3
    assert len(loaded_resps) == 2
    assert {row["key"] for row in loaded_reqs} == {"left", "right", "ok"}
    unanswered = ac.pair_messages(loaded_reqs, loaded_resps)["unanswered"]
    assert [row["key"] for row in unanswered] == ["right"]


def test_header_row_is_recognized(tmp_path):
    path = tmp_path / "both.tsv"
    path.write_text(
        "frame.number\tframe.time_relative\ttcp.stream\tcouchbase.magic\tcouchbase.opcode\tcouchbase.opaque\tcouchbase.key.logical_key\tcouchbase.status\n"
        "1\t0.1\t0\t0x80\t0x00\t0x1\tdoc::a\t\n"
        "2\t0.2\t0\t0x18\t0x00\t0x1\t\t0x0000\n"
    )
    requests, responses, _joined = ac.load_table(path)
    assert len(requests) == 1
    assert len(responses) == 1
    assert requests[0]["key"] == "doc::a"
    assert responses[0]["status"] == "0x0000"


def test_plain_pcap_wins_over_its_gzip_copy(tmp_path):
    pcap = tmp_path / "a.pcap"
    gzip = tmp_path / "a.pcap.gz"
    pcap.write_bytes(b"not a real pcap")
    gzip.write_bytes(b"gzip bytes")
    chosen = ac.prefer_plain_pcaps([gzip, pcap])
    assert chosen == [pcap]
