"""Pairing, edge windows, and the counted note."""

import analyze_capture as ac


def message(time, stream, opaque, opcode="0x00", key="doc", kind="req", status=""):
    return {
        "frame": str(int(time * 1000)),
        "time": time,
        "stream": stream,
        "src": "10.0.0.2",
        "sport": "40000",
        "dst": "10.0.0.3",
        "dport": "11210",
        "opcode": opcode,
        "opaque": opaque,
        "key": key,
        "status": status,
        "magic": 0x80 if kind == "req" else 0x18,
    }


def sample():
    requests = [
        message(1.0, "0", "0x00000001", key="cache::manifest::aaa"),
        message(0.2, "0", "0x00000002", key="cache::manifest::bbb"),
        message(9.98, "0", "0x00000003", "0x01", "edge::key::1"),
    ]
    responses = [
        message(1.03, "0", "0x00000001", kind="res", status="0x0000"),
        message(0.01, "0", "0x00000009", "0x01", "", kind="res", status="0x0000"),
    ]
    return requests, responses


def test_response_before_request_is_not_a_match():
    requests, responses = sample()
    paired = ac.pair_messages(requests, responses)
    assert len(paired["matched"]) == 1
    assert len(paired["unanswered"]) == 2
    assert len(paired["resp_only"]) == 1
    assert paired["matched"][0][0]["key"] == "cache::manifest::aaa"


def test_edges_use_the_longest_matched_round_trip():
    requests, responses = sample()
    facts = ac.build_facts(
        requests,
        responses,
        ac.pair_messages(requests, responses),
        source_label="unit",
        pcap_names=[],
        capture_end=10.0,
        packet_count=None,
        magics=None,
        joined_rows=0,
        opcode_names={},
        loss=None,
    )
    assert facts["edge"]["start_responses"] == 1
    assert facts["edge"]["end_requests"] == 1
    assert facts["edge"]["interior_unanswered"] == 1
    assert abs(facts["rtt_seconds"]["max"] - 0.03) < 1e-9
    assert facts["edge"]["closing_examples"][0]["key"] == "edge::key::1"


def test_summary_names_the_interior_key_and_splice_fills_the_table():
    requests, responses = sample()
    facts = ac.build_facts(
        requests,
        responses,
        ac.pair_messages(requests, responses),
        source_label="unit",
        pcap_names=[],
        capture_end=10.0,
        packet_count=4,
        magics=None,
        joined_rows=0,
        opcode_names={},
        loss=None,
    )
    text = ac.render_summary(facts)
    assert "cache::manifest::bbb" in text
    assert ac.TABLE_TOKEN not in text
    brief = ac.facts_brief(facts)
    assert ac.TABLE_TOKEN in brief
    spliced = ac.splice_table(brief, ac.unanswered_table(facts["unanswered"]))
    assert "cache::manifest::bbb" in spliced
    assert ac.TABLE_TOKEN not in spliced


def test_same_opaque_on_two_streams_stays_two_operations():
    requests = [
        message(1.0, "7", "0x0000000a", "0x01", "ref::one"),
        message(1.1, "9", "0x0000000a", "0x00", "dat::other"),
    ]
    responses = [message(1.2, "9", "0x0000000a", kind="res", status="0x0000")]
    paired = ac.pair_messages(requests, responses)
    assert len(paired["matched"]) == 1
    assert paired["unanswered"][0]["stream"] == "7"
    assert paired["matched"][0][0]["stream"] == "9"
