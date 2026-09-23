"""Chart aggregates are bucketed without another capture read."""

import analyze_capture as ac


def msg(time, stream="0", opaque="0x1", opcode="0x00", key="doc", src="10.0.0.2", kind="req", body=0):
    return {
        "frame": "1",
        "time": time,
        "stream": stream,
        "src": src,
        "sport": "4000",
        "dst": "10.0.0.3",
        "dport": "11210",
        "opcode": opcode,
        "opaque": opaque,
        "key": key,
        "status": "",
        "body": body,
        "magic": 0x80 if kind == "req" else 0x18,
    }


def test_buckets_percentiles_and_top_keys():
    requests = [
        msg(0.2, opaque="0x1", key="widget::hot", src="10.0.0.2"),
        msg(0.4, opaque="0x2", key="widget::hot", src="10.0.0.2"),
        msg(1.2, opaque="0x3", key="widget::slow", src="10.0.0.8", body=1048576),
        msg(1.4, opaque="0x4", key="widget::gone", src="10.0.0.2"),
    ]
    responses = [
        msg(0.21, opaque="0x1", kind="res"),
        msg(0.46, opaque="0x2", kind="res"),
        msg(1.35, opaque="0x3", kind="res", body=200),
    ]
    paired = ac.pair_messages(requests, responses)
    loss = [{
        "time": 1.1,
        "stream": "0",
        "sport": "11210",
        "dport": "4000",
        "lost": True,
        "retrans": True,
        "ack": False,
    }, {
        "time": 1.2,
        "stream": "8",
        "sport": "80",
        "dport": "443",
        "lost": True,
        "retrans": False,
        "ack": False,
    }]
    charts = ac.build_charts(requests, paired, loss, ["11210"], 2.0)
    first = charts["buckets"]["1"][0]
    second = charts["buckets"]["1"][1]
    assert first["requests"] == 2
    assert first["opcodes"]["Get"] == 2
    assert first["matched"] == 2
    assert first["unanswered"] == 0
    assert second["unanswered"] == 1
    assert second["lost"] == 1
    assert second["retrans"] == 1
    assert charts["buckets"]["1"][0]["rtt_n"] == 2
    assert charts["by_requester_ip"][0]["ip"] == "10.0.0.2"
    assert charts["by_requester_ip"][0]["requests"] == 3
    assert charts["by_connection"][0]["port"] == "4000"
    assert sum(row["requests"] for row in charts["by_connection"]) == 4
    assert charts["top_requested"][0] == {"key": "widget::hot", "count": 2, "unanswered": 0}
    assert charts["top_slowest"][0]["key"] == "widget::slow"
    assert charts["top_slowest"][0]["time_ms"] == 150.0
    assert charts["top_slowest"][0]["seconds"] == 1.2
    assert charts["top_slowest"][0]["opaque"] == "0x3"
    assert charts["top_slowest"][0]["stream"] == "0"
    assert charts["top_slowest"][0]["body_bytes"] == 1048576
    assert first["body_in_max"] == 0
    assert second["body_in_max"] == 1048576
    assert second["body_in_bytes"] == 1048576
    assert second["body_out_max"] == 200
    assert second["body_out_bytes"] == 200
    assert second["body_large"] == 1
    assert second["lost_s2c"] == 1
    assert second["lost_c2s"] == 0
    assert charts["by_connection"][0]["unanswered_pct"] == 33.3
    candidates = ac.interest_candidates(charts)
    assert any(item["seconds"] == 1.2 and item["title"] == "Slow call" for item in candidates)
    picked = ac.parse_interest_stakes(
        '[{"seconds": 99, "title": "Invented", "why": "no"}, {"seconds": 1.2, "title": "Big and slow", "why": "150 ms"}]',
        candidates,
    )
    assert [item["seconds"] for item in picked] == [1.2]
    assert picked[0]["title"] == "Big and slow"
    offline = ac.choose_interest_stakes(charts, base_url="", model="", timeout=1, use_model=False)
    assert any(item["seconds"] == 1.2 for item in offline)
    assert charts["slow_ms"]["over_100"] == 1
    assert charts["slow_ms"]["over_250"] == 0
    assert next(row["count"] for row in charts["rtt_histogram"] if row["label"] == "100–250") == 1
    assert len(charts["buckets"]["5"]) == 1
    assert len(charts["buckets"]["10"]) == 1
