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


def test_dcp_mutation_is_not_a_lost_response():
    mutation = msg(1.0, opaque="0x1", opcode="0x57", key="doc::a")
    paired = ac.pair_messages([mutation], [])
    assert paired["unanswered"] == []
    assert len(paired["no_reply"]) == 1
    charts = ac.build_charts([mutation], paired, [], ["11210"], 5.0)
    row = charts["by_opcode"][0]
    assert row["expects_reply"] is False
    assert row["unanswered"] == 0
    assert charts["missing_response_total"] == 0
    assert charts["traffic"]["cluster"]["no_reply"] == 1
    assert charts["traffic"]["cluster"]["unanswered"] == 0


def test_node_port_and_dcp_are_cluster_and_an_app_port_is_sdk():
    assert ac.traffic_role("11210", "11210", "0x01") == "cluster"
    assert ac.traffic_role("4000", "11210", "0x57") == "cluster"
    assert ac.traffic_role("4000", "11210", "0xa2") == "cluster"
    assert ac.traffic_role("4000", "11210", "0x00") == "sdk"
    assert ac.traffic_role("4000", "11210", "0x48") == "cluster"
    assert ac.traffic_role("4000", "11210", "0x10", "vbucket-seqno") == "cluster"
    assert ac.traffic_role("4000", "11210", "0x10", "connections") == "sdk"
    assert ac.expects_reply("0x56") is False
    assert ac.expects_reply("0x56", snapshot_ack=True) is True
    assert ac.expects_reply("0x57") is False
    assert ac.expects_reply("0x5c") is True
    assert ac.expects_reply("0x5d") is False
    app = msg(0.2, opaque="0x1")
    node = msg(1.0, opaque="0x9", opcode="0x57", src="10.0.0.9")
    node["sport"] = "11210"
    node["dport"] = "11210"
    paired = ac.pair_messages([app, node], [])
    charts = ac.build_charts(
        [app, node],
        paired,
        [{"time": 1.0, "stream": "1", "sport": "11210", "dport": "11210", "lost": False, "retrans": True, "ack": False}],
        ["11210"],
        5.0,
    )
    assert charts["traffic"]["sdk"]["requests"] == 1
    assert charts["traffic"]["cluster"]["requests"] == 1
    assert charts["traffic"]["cluster"]["retrans"] == 1
    dcp = msg(2.0, opaque="0x8", opcode="0x57", src="10.0.0.7")
    dcp["sport"] = "5000"
    paired_dcp = ac.pair_messages([dcp], [])
    reply_retrans = ac.build_charts(
        [dcp],
        paired_dcp,
        [{"time": 2.1, "stream": "2", "sport": "11210", "dport": "5000", "lost": False, "retrans": True, "ack": False}],
        ["11210"],
        5.0,
    )
    assert reply_retrans["traffic"]["cluster"]["retrans"] == 1
    assert reply_retrans["traffic"]["sdk"]["retrans"] == 0
    roles = {(row["ip"], row["port"]): row["role"] for row in charts["by_connection"]}
    assert roles[("10.0.0.2", "4000")] == "sdk"
    assert roles[("10.0.0.9", "11210")] == "cluster"
    assert charts["buckets"]["1"][0]["sdk_requests"] == 1
    assert charts["buckets"]["1"][1]["cluster_requests"] == 1
    assert charts["by_opcode"][0]["role"] in {"sdk", "cluster"}


def test_missing_rows_are_spaced_across_the_capture():
    requests = [msg(float(i), opaque=f"0x{i:x}", key=f"k{i}") for i in range(1, 31)]
    paired = ac.pair_messages(requests, [])
    charts = ac.build_charts(requests, paired, [], ["11210"], 40.0)
    rows = charts["missing_response"]
    assert charts["missing_response_total"] == 30
    assert len(rows) == 10
    assert rows[0]["key"] == "k2"
    assert rows[-1]["key"] == "k30"
    assert rows[0]["where"] == "inside"
    assert rows[0]["seconds"] < rows[4]["seconds"] < rows[-1]["seconds"]
    assert all(not row["at_edge"] for row in rows)


def test_missing_calls_are_listed_sdk_then_cluster():
    app = msg(1.0, opaque="0x1", opcode="0x00", key="app::gone")
    node = msg(1.0, opaque="0x2", opcode="0xa2", key="cluster::gone", src="10.0.0.9")
    done = msg(2.0, opaque="0x3", opcode="0x00", key="ok")
    early = msg(0.01, opaque="0x4", opcode="0xa2", kind="res", src="10.0.0.9")
    paired = ac.pair_messages([app, node, done], [msg(2.05, opaque="0x3", kind="res"), early])
    charts = ac.build_charts([app, node, done], paired, [], ["11210"], 5.0)
    assert charts["missing_response_sdk_total"] == 1
    assert charts["missing_response_cluster_total"] == 1
    assert charts["missing_response_sdk"][0]["key"] == "app::gone"
    assert charts["missing_response_cluster"][0]["key"] == "cluster::gone"
    assert charts["missing_request_sdk_total"] == 0
    assert charts["missing_request_cluster_total"] == 1


def test_sdk_and_cluster_speeds_stay_on_their_own_series():
    app = msg(1.0, opaque="0x1", opcode="0x00", key="app::doc")
    replication = msg(1.0, opaque="0x2", opcode="0xa2", key="cluster::doc", src="10.0.0.9")
    opening = msg(0.01, opaque="0x3", opcode="0xa2", key="open::key", src="10.0.0.9")
    responses = [
        msg(1.002, opaque="0x1", kind="res"),
        msg(1.035, opaque="0x2", kind="res"),
    ]
    paired = ac.pair_messages([app, replication, opening], responses)
    charts = ac.build_charts([app, replication, opening], paired, [], ["11210"], 2.0)
    bands = {row["label"]: row for row in charts["rtt_histogram"]}
    assert bands["0–20"]["sdk"] == 1
    assert bands["0–20"]["cluster"] == 0
    assert bands["30–40"]["cluster"] == 1
    second = charts["buckets"]["1"][1]
    assert second["sdk_median"] == 2.0
    assert second["cluster_median"] == 35.0
    assert second["sdk_p99"] == 2.0
    assert charts["missing_response"][0]["where"] == "start"
    assert charts["missing_response"][0]["key"] == "open::key"


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
    clients = {row["ip"]: row for row in charts["clients"]}
    assert clients["10.0.0.2"]["unanswered"] == 1
    assert clients["10.0.0.2"]["unanswered_pct"] == 33.3
    assert clients["10.0.0.2"]["connections"] == 1
    assert clients["10.0.0.2"]["matched"] == 2
    assert clients["10.0.0.2"]["median_ms"] is not None
    assert clients["10.0.0.8"]["unanswered"] == 0
    assert charts["by_connection"][0]["port"] == "4000"
    assert sum(row["requests"] for row in charts["by_connection"]) == 4
    assert charts["top_requested"][0] == {"key": "widget::hot", "count": 2, "unanswered": 0}
    assert charts["top_slowest"][0]["key"] == "widget::slow"
    assert charts["top_slowest"][0]["time_ms"] == 150.0
    assert charts["top_slowest"][0]["seconds"] == 1.2
    assert charts["missing_response"][0]["key"] == "widget::gone"
    assert charts["missing_response"][0]["at_edge"] is False
    assert charts["missing_response_total"] == 1
    assert charts["missing_request"] == []
    assert charts["missing_request_total"] == 0
    assert charts["server"]["ip"] == "10.0.0.3"
    assert charts["server"]["port"] == "11210"
    assert charts["server"]["host"]
    typed = ac.build_charts(
        requests, paired, loss, ["11210"], 2.0,
        packet_types=ac.Counter({"Get request": 4, "TCP ACK": 2, "Lost segment": 1}),
    )
    assert [row["name"] for row in typed["packet_types"]] == ["Get request", "TCP ACK", "Lost segment"]
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
