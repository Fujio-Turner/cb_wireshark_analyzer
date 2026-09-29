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
    assert rows[0]["key"] == "k1"
    assert rows[0]["where"] == "start"
    assert rows[-1]["key"] == "k30"
    assert rows[0]["seconds"] < rows[4]["seconds"] < rows[-1]["seconds"]
    assert all(row["where"] != "end" for row in rows)
    assert rows[0]["seconds_left"] > charts["in_flight_window"]


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


def test_a_nearby_tcp_hole_marks_the_missing_call_possible():
    request = msg(1.0, opaque="0x11", opcode="0x00", key="widget::gone", stream="4")
    hole = {
        "time": 1.2,
        "stream": "4",
        "sport": "11210",
        "dport": "4000",
        "lost": True,
        "retrans": False,
        "ack": False,
        "duplicate": False,
    }
    far = dict(hole, time=4.0, stream="9")
    paired = ac.pair_messages([request], [])
    charts = ac.build_charts([request], paired, [hole, far], ["11210"], 5.0)
    row = charts["missing_response"][0]
    assert row["error"] == "possible"
    call, hole_text = row["error_filter"].split(") || (", 1)
    assert "tcp.stream == 4" in call
    assert hole_text.startswith("tcp.stream == 4 && ")
    assert "ip.addr" not in row["error_filter"]
    assert "couchbase.opaque == 0x11" in row["error_filter"]
    assert 'couchbase.key.logical_key == "widget::gone"' in row["error_filter"]
    assert "tcp.analysis.lost_segment" in row["error_filter"]
    assert "frame.time_relative >= " in row["error_filter"]
    other = dict(hole, stream="9")
    charts = ac.build_charts([request], paired, [other], ["11210"], 5.0)
    widened = charts["missing_response"][0]
    assert widened["error"] == "possible"
    assert "ip.addr == 10.0.0.2" in widened["error_filter"]
    assert "tcp.stream == 9" not in widened["error_filter"]
    quiet = msg(1.0, opaque="0x12", opcode="0x00", key="other", stream="8")
    charts = ac.build_charts([quiet], ac.pair_messages([quiet], []), [far], ["11210"], 5.0)
    assert charts["missing_response"][0]["error"] == ""


def test_half_second_buckets_split_one_second():
    early = msg(0.2, opaque="0x1", opcode="0x00", key="early")
    late = msg(0.7, opaque="0x2", opcode="0x00", key="late")
    paired = ac.pair_messages(
        [early, late],
        [msg(0.21, opaque="0x1", kind="res"), msg(0.71, opaque="0x2", kind="res")],
    )
    charts = ac.build_charts([early, late], paired, [], ["11210"], 1.2)
    halves = charts["buckets"]["0.5"]
    assert [row["t"] for row in halves] == [0.0, 0.5, 1.0]
    assert halves[0]["requests"] == 1
    assert halves[1]["requests"] == 1
    assert halves[2]["requests"] == 0
    assert "1" in charts["buckets"]


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
    assert charts["top_slowest"][0]["requester"] == "10.0.0.9"
    assert charts["top_slowest"][0]["stream"]
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
    assert charts["top_requested"][0]["key"] == "widget::hot"
    assert charts["top_requested"][0]["count"] == 2
    assert charts["top_requested"][0]["unanswered"] == 0
    assert charts["top_requested"][0]["per_second"] == 1.0
    assert charts["top_requested"][0]["avg_body_bytes"] == 0
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


def test_busiest_key_averages_the_larger_body_of_each_call():
    big = msg(0.1, opaque="0x1", key="doc::fat")
    big_reply = msg(0.2, opaque="0x1", key="doc::fat", kind="resp", body=1_000_000)
    small = msg(0.3, opaque="0x2", key="doc::fat", body=100)
    small_reply = msg(0.4, opaque="0x2", key="doc::fat", kind="resp", body=200)
    requests = [big, small]
    paired = ac.pair_messages(requests, [big_reply, small_reply])
    charts = ac.build_charts(requests, paired, [], ["11210"], 2.0)
    row = charts["top_requested"][0]
    assert row["key"] == "doc::fat"
    assert row["count"] == 2
    assert row["per_second"] == 1.0
    assert row["avg_body_bytes"] == 500_100


def test_busiest_and_slowest_lists_keep_each_side():
    sdk = [
        msg(0.10, opaque="0x1", key="app::hot", body=100),
        msg(0.20, opaque="0x2", key="app::hot", body=100),
        msg(0.30, opaque="0x3", key="app::hot", body=100),
        msg(0.40, opaque="0x4", key="app::lost", body=10),
        msg(0.50, opaque="0x5", key="app::lost", body=10),
        msg(1.00, opaque="0x6", key="app::slow", body=50),
        msg(1.40, opaque="0x7", key="shared::doc", body=1000),
    ]
    cluster = [
        msg(0.11, opaque="0x11", opcode="0xa2", key="repl::busy", src="10.0.0.9"),
        msg(0.21, opaque="0x12", opcode="0xa2", key="repl::busy", src="10.0.0.9"),
        msg(0.31, opaque="0x13", opcode="0xa2", key="repl::busy", src="10.0.0.9"),
        msg(0.41, opaque="0x14", opcode="0xa2", key="repl::busy", src="10.0.0.9"),
        msg(1.00, opaque="0x15", opcode="0xa2", key="repl::slow", src="10.0.0.9", body=80),
        msg(1.40, opaque="0x16", opcode="0xa2", key="shared::doc", src="10.0.0.9", body=10),
    ]
    responses = [
        msg(0.12, opaque="0x1", kind="res", body=300),
        msg(0.22, opaque="0x2", kind="res", body=300),
        msg(0.32, opaque="0x3", kind="res", body=300),
        msg(1.08, opaque="0x6", kind="res", body=10),
        msg(1.41, opaque="0x7", kind="res", body=0),
        msg(0.12, opaque="0x11", kind="res"),
        msg(0.22, opaque="0x12", kind="res"),
        msg(0.32, opaque="0x13", kind="res"),
        msg(0.42, opaque="0x14", kind="res"),
        msg(1.25, opaque="0x15", kind="res", body=20),
        msg(1.45, opaque="0x16", kind="res", body=4000),
    ]
    requests = sdk + cluster
    charts = ac.build_charts(requests, ac.pair_messages(requests, responses), [], ["11210"], 2.0)
    assert charts["top_requested"][0]["key"] == "repl::busy"
    assert charts["top_requested"][0]["count"] == 4
    sdk_keys = {row["key"]: row for row in charts["top_requested_sdk"]}
    cluster_keys = {row["key"]: row for row in charts["top_requested_cluster"]}
    assert sdk_keys["app::hot"]["count"] == 3
    assert sdk_keys["app::hot"]["unanswered"] == 0
    assert sdk_keys["app::hot"]["avg_body_bytes"] == 300
    assert sdk_keys["app::hot"]["per_second"] == 1.5
    assert sdk_keys["app::lost"]["unanswered"] == 2
    assert "repl::busy" not in sdk_keys
    assert cluster_keys["repl::busy"]["count"] == 4
    assert "app::hot" not in cluster_keys
    assert sdk_keys["shared::doc"]["avg_body_bytes"] == 1000
    assert cluster_keys["shared::doc"]["avg_body_bytes"] == 4000
    shared = next(row for row in charts["top_requested"] if row["key"] == "shared::doc")
    assert shared["count"] == 2
    assert shared["avg_body_bytes"] == 2500
    assert charts["top_slowest"][0]["key"] == "repl::slow"
    assert charts["top_slowest_sdk"][0]["key"] == "app::slow"
    assert charts["top_slowest_sdk"][0]["time_ms"] == 80.0
    assert charts["top_slowest_sdk"][0]["role"] == "sdk"
    assert charts["top_slowest_cluster"][0]["key"] == "repl::slow"
    assert charts["top_slowest_cluster"][0]["time_ms"] == 250.0
    assert charts["top_slowest_cluster"][0]["body_bytes"] == 80
    assert all(row["role"] == "sdk" for row in charts["top_slowest_sdk"])
    assert all(row["role"] == "cluster" for row in charts["top_slowest_cluster"])
    assert len(charts["top_requested_sdk"]) <= 10
    assert len(charts["top_slowest_cluster"]) <= 10
    digest = "\n".join(ac.chart_digest(charts))
    assert "Ten busiest SDK document ids" in digest
    assert "app::hot" in digest
    assert "Ten busiest cluster document ids" in digest
    assert "repl::busy" in digest
    assert "Ten slowest SDK calls" in digest
    assert "app::slow" in digest
    assert "Ten slowest cluster calls" in digest
    assert "repl::slow" in digest


def test_gap_sample_keeps_a_request_that_had_time_and_caps_the_close():
    early = msg(0.02, opaque="0x1", key="app::early")
    middle = [
        msg(3.0, opaque="0x2", key="app::mid"),
        msg(4.0, opaque="0x3", key="app::mid2"),
    ]
    closing = [msg(9.96 + i * 0.003, opaque=f"0x{i + 10:x}", key=f"app::close{i}") for i in range(9)]
    done = msg(1.0, opaque="0xff", key="app::ok")
    reply = msg(1.05, opaque="0xff", kind="res")
    requests = [early, done, *middle, *closing]
    charts = ac.build_charts(requests, ac.pair_messages(requests, [reply]), [], ["11210"], 10.0)
    rows = charts["missing_response_sdk"]
    assert charts["missing_response_sdk_total"] == 12
    assert [row["key"] for row in rows if row["where"] != "end"] == ["app::early", "app::mid", "app::mid2"]
    assert sum(1 for row in rows if row["where"] == "end") == ac._EDGE_SAMPLE
    assert rows[0]["where"] == "start"
    assert rows[0]["seconds_left"] > charts["in_flight_window"]
    crowded = [msg(float(i), opaque=f"0x{i:x}", key=f"app::in{i}") for i in range(1, 13)]
    ends = [msg(19.97, opaque="0xee", key="app::end")]
    quiet = msg(2.0, opaque="0xfe", key="app::pace")
    quiet_reply = msg(2.04, opaque="0xfe", kind="res")
    many = crowded + ends + [quiet]
    wide = ac.build_charts(many, ac.pair_messages(many, [quiet_reply]), [], ["11210"], 20.0)
    shown = wide["missing_response"]
    assert wide["missing_response_total"] == 13
    assert len(shown) == 10
    assert all(row["where"] != "end" for row in shown)


def test_opening_replies_do_not_fill_the_missing_request_sample():
    opening = [
        msg(0.001 * i, opaque=f"0x{i:x}", opcode="0xa2", kind="res", src="10.0.0.9", key=f"repl::open{i}")
        for i in range(1, 13)
    ]
    later = [
        msg(4.0 + i, opaque=f"0xa{i}", opcode="0xa2", kind="res", src="10.0.0.9", key=f"repl::later{i}")
        for i in range(3)
    ]
    done = msg(1.0, opaque="0xff", opcode="0xa2", key="repl::ok", src="10.0.0.9")
    reply = msg(1.05, opaque="0xff", opcode="0xa2", kind="res", src="10.0.0.9")
    charts = ac.build_charts([done], ac.pair_messages([done], opening + later + [reply]), [], ["11210"], 10.0)
    rows = charts["missing_request_cluster"]
    assert charts["missing_request_cluster_total"] == 15
    assert sum(1 for row in rows if row["where"] == "inside") == 3
    assert sum(1 for row in rows if row["where"] == "start") == ac._EDGE_SAMPLE
    assert {row["key"] for row in rows if row["where"] == "inside"} == {"repl::later0", "repl::later1", "repl::later2"}


def test_closing_unanswered_spike_is_not_a_point_of_interest():
    interior = msg(4.2, opaque="0x1", key="app::look")
    closing = [msg(10.05 + i * 0.02, opaque=f"0x{i + 2:x}", key=f"app::tail{i}") for i in range(6)]
    done = msg(1.0, opaque="0xff", key="app::ok")
    reply = msg(1.3, opaque="0xff", kind="res")
    requests = [interior, done, *closing]
    charts = ac.build_charts(requests, ac.pair_messages(requests, [reply]), [], ["11210"], 10.2)
    assert charts["in_flight_window"] == 0.3
    picked = [item for item in ac.interest_candidates(charts) if item["title"] == "Most lost responses"]
    assert picked
    assert all(item["seconds"] < 10 for item in picked)
    assert picked[0]["seconds"] == 4.0
    assert "point of interest" in ac.SYSTEM_PROMPT
    assert "Do not pick those seconds" in ac.INTEREST_SYSTEM


def test_replica_reads_are_counted_by_the_node_that_was_asked():
    active = msg(1.0, opaque="0x1", opcode="0x00")
    active["dst"] = "10.0.0.9"
    replica = msg(1.1, opaque="0x2", opcode="0x83")
    replica["dst"] = "10.0.0.4"
    subdoc = msg(1.2, opaque="0x3", opcode="0xc5")
    subdoc["dst"] = "10.0.0.4"
    subdoc["replica_read"] = True
    quiet = msg(1.3, opaque="0x4", opcode="0xc5")
    quiet["dst"] = "10.0.0.4"
    quiet["replica_read"] = False
    requests = [active, replica, subdoc, quiet]
    paired = ac.pair_messages(requests, [])
    facts = ac.build_facts(
        requests, [], paired,
        source_label="unit", pcap_names=[], capture_end=5.0,
        packet_count=4, magics=None, joined_rows=0, opcode_names={}, loss=None,
    )
    reads = facts["replica_reads"]
    assert reads["total"] == 2
    assert reads["get_replica"] == 1
    assert reads["subdoc"] == 1
    assert reads["servers"][0]["ip"] == "10.0.0.4"
    assert reads["servers"][0]["total"] == 2
    text = ac.render_summary(facts)
    assert "10.0.0.4" in text
    assert "2.5 seconds" in text
    brief = ac.facts_brief(facts)
    assert "Get Replica 1" in brief
    assert "10.0.0.4: 2" in brief


def test_diagnosis_charts_separate_slow_missing_and_one_way_dcp():
    slow = msg(1.2, opaque="0x1", opcode="0x01", key="doc::slow")
    slow["durability"] = 3
    slow["vbucket"] = 7
    slow_reply = msg(1.45, opaque="0x1", opcode="0x01", kind="resp")
    slow_reply["status"] = "0x0000"
    slow_reply["server_us"] = 40.0
    fast = msg(2.0, opaque="0x2", opcode="0x00", key="doc::fast")
    fast["vbucket"] = 7
    fast_reply = msg(2.001, opaque="0x2", opcode="0x00", kind="resp")
    fast_reply["status"] = "0x0001"
    fast_reply["server_us"] = 12.0
    missing = msg(3.0, opaque="0x3", opcode="0x00", key="doc::gone", src="10.0.0.8")
    missing["vbucket"] = 9
    exists = msg(3.2, opaque="0x4", opcode="0x02")
    exists_reply = msg(3.21, opaque="0x4", opcode="0x02", kind="resp")
    exists_reply["status"] = "0x0002"
    wrong = msg(3.4, opaque="0x5", opcode="0x00", src="10.0.0.8")
    wrong["vbucket"] = 9
    wrong_reply = msg(3.41, opaque="0x5", opcode="0x00", kind="resp")
    wrong_reply["status"] = "0x0007"
    mutation = msg(0.4, opaque="0x6", opcode="0x57", key="doc::dcp", src="10.0.0.9")
    mutation["sport"] = "11210"
    mutation["dport"] = "11210"
    marker = msg(0.4, opaque="0x6", opcode="0x56", key="", src="10.0.0.9")
    marker["sport"] = "11210"
    marker["dport"] = "11210"
    marker["snapshot_disk"] = True
    marker["snap_start"] = 100
    marker["snap_end"] = 150
    ack = msg(0.5, opaque="0x0", opcode="0x5d", key="", src="10.0.0.4")
    ack["sport"] = "11210"
    ack["dport"] = "11210"
    ack["bytes_to_ack"] = 4096
    requests = [slow, fast, missing, exists, wrong, mutation, marker, ack]
    responses = [slow_reply, fast_reply, exists_reply, wrong_reply]
    paired = ac.pair_messages(requests, responses)
    charts = ac.build_charts(requests, paired, [], ["11210"], 5.0)
    assert [point["rtt"] for point in charts["scatter"]] == [250.0]
    assert charts["scatter"][0]["server_us"] == 40.0
    assert charts["scatter"][0]["durability"] == 3
    assert any(point["server_us"] == 12.0 for point in charts["scatter_server"])
    box = next(row for row in charts["boxplot"] if row["opcode"] == "0x01")
    assert box["role"] == "sdk"
    assert box["box"][2] == 250.0
    assert box["box"][4] == 250.0
    heat = charts["heatmap"]["1"]["clients"]
    assert heat[0]["name"] == "10.0.0.8"
    assert sum(heat[0]["values"]) == 1
    outcomes = {(link["source"], link["target"]): link["value"] for link in charts["sankey"]["links"]}
    assert outcomes[("Cluster", "DCP (Key) Mutation")] == 1
    assert outcomes[("DCP (Key) Mutation", "Not expected")] == 1
    assert outcomes[("Get", "Not found")] == 1
    assert outcomes[("Get", "Error status")] == 1
    assert outcomes[("Add", "Key exists")] == 1
    assert any(row["status"] == "0x0007" and row["name"] == "not my vbucket" for row in charts["status_counts"])
    durable = next(row for row in charts["durability"] if row["level"] == 3)
    assert durable["name"] == "Persist to majority"
    assert durable["p99_ms"] == 250.0
    vb = next(row for row in charts["vbuckets"] if row["vbucket"] == 9)
    assert vb["unanswered"] == 1
    second = charts["buckets"]["1"][0]
    assert second["snap_disk"] == 1
    assert second["snap_span_max"] == 50
    assert second["ack_bytes"] == 4096
    assert second["mutations"] == 1
    assert second["buffer_acks"] == 1
    slow_reply["ttp"] = 80
    slow_reply["ttr"] = 12
    fast_reply["ttp"] = 0
    paired_persist = ac.pair_messages(requests, responses)
    persist_charts = ac.build_charts(requests, paired_persist, [], ["11210"], 5.0)
    assert persist_charts["persist"]["ttp"]["n"] == 2
    assert persist_charts["persist"]["ttp"]["median"] == 40.0
    assert persist_charts["persist"]["ttr"]["n"] == 1
    assert persist_charts["persist"]["ttr"]["median"] == 12.0
    bucket = persist_charts["buckets"]["1"][1]
    assert bucket["ttp_n"] == 1
    assert bucket["ttp_median"] == 80.0
    assert bucket["ttr_median"] == 12.0
    assert persist_charts["buckets"]["1"][2]["ttp_median"] == 0.0
    views = charts["sankey"]["views"]
    assert views["all"]["links"] == charts["sankey"]["links"]

    def bands(view):
        return {(link["source"], link["target"]): link["value"] for link in view["links"]}

    application = bands(views["application"])
    assert application[("Application", "Get")] == 3
    assert ("Cluster", "DCP (Key) Mutation") not in application
    assert all(link["source"] != "Cluster" for link in views["application"]["links"])
    cluster = bands(views["cluster"])
    assert cluster[("DCP (Key) Mutation", "Not expected")] == 1
    assert all(link["source"] != "Application" for link in views["cluster"]["links"])
    excluded = bands(views["exclude_not_expected"])
    assert ("DCP (Key) Mutation", "Not expected") not in excluded
    assert excluded[("Get", "Missing reply")] == 1
    assert excluded[("Get", "Not found")] == 1
    unmatched = bands(views["unmatched"])
    assert unmatched[("Get", "Missing reply")] == 1
    assert ("DCP (Key) Mutation", "Not expected") not in unmatched
    assert all(link["target"] != "Not expected" for link in views["unmatched"]["links"])
    assert ("Get", "Not found") not in unmatched
    assert ("Add", "Key exists") not in unmatched
    assert ("Get", "Error status") not in unmatched


def test_sankey_menu_refolds_the_busiest_commands_in_that_view():
    requests = []
    responses = []
    serial = 0
    for opcode, count in (
        ("0x00", 9),
        ("0x01", 8),
        ("0x02", 7),
        ("0x04", 6),
        ("0x05", 5),
        ("0x06", 4),
        ("0x07", 3),
        ("0x08", 2),
        ("0x09", 1),
    ):
        for _ in range(count):
            serial += 1
            opaque = f"0x{serial:x}"
            requests.append(msg(1.0, stream="1", opaque=opaque, opcode=opcode))
            reply = msg(1.01, stream="1", opaque=opaque, opcode=opcode, kind="resp")
            reply["status"] = "0x0000"
            responses.append(reply)
    for _ in range(100):
        serial += 1
        mutation = msg(0.4, stream="2", opaque=f"0x{serial:x}", opcode="0x57", key="doc::dcp", src="10.0.0.9")
        mutation["sport"] = "11210"
        mutation["dport"] = "11210"
        requests.append(mutation)
    charts = ac.build_charts(requests, ac.pair_messages(requests, responses), [], ["11210"], 5.0)
    views = charts["sankey"]["views"]

    def names(view):
        return {node["name"] for node in view["nodes"]}

    assert "Flush" not in names(views["all"])
    assert "Flush" in names(views["application"])
    assert "DCP (Key) Mutation" not in names(views["application"])
    assert "Get Quietly" not in names(views["application"])
    assert names(views["cluster"]) == {"Cluster", "DCP (Key) Mutation", "Not expected"}
    assert "Not expected" not in names(views["exclude_not_expected"])
    assert "Flush" in names(views["exclude_not_expected"])
    assert views["unmatched"]["links"] == []


def test_packet_errors_keep_holes_and_skip_capture_duplicates():
    dcp = msg(0.3, opaque="0x8", opcode="0x57", src="10.0.0.9")
    dcp["sport"] = "5000"
    dcp["dport"] = "11210"
    paired = ac.pair_messages([dcp], [])
    charts = ac.build_charts(
        [dcp],
        paired,
        [
            {"time": 1.2, "stream": "4", "sport": "11210", "dport": "4000", "lost": True, "retrans": False, "ack": False},
            {"time": 1.5, "stream": "4", "sport": "4000", "dport": "11210", "lost": False, "retrans": True, "ack": False, "duplicate": True},
            {"time": 2.0, "stream": "9", "sport": "5000", "dport": "11210", "lost": False, "retrans": True, "ack": True},
        ],
        ["11210"],
        5.0,
    )
    rows = charts["packet_errors"]
    assert [(row["t"], row["kind"], row["toward"], row["role"], row["stream"]) for row in rows] == [
        (1.2, "lost", "client", "sdk", "4"),
        (2.0, "ack", "server", "cluster", "9"),
    ]
    assert rows[1]["kinds"] == ["ack", "retrans"]
    assert charts["related"]["lanes"] == []
    assert charts["related"]["points"] == []


def test_boxplot_splits_application_and_cluster():
    app = msg(1.0, opaque="0x1", opcode="0x00")
    app_reply = msg(1.05, opaque="0x1", opcode="0x00", kind="resp")
    app_reply["status"] = "0x0000"
    node = msg(2.0, opaque="0x2", opcode="0x00", src="10.0.0.9")
    node["sport"] = "11210"
    node["dport"] = "11210"
    node_reply = msg(2.2, opaque="0x2", opcode="0x00", kind="resp")
    node_reply["status"] = "0x0000"
    meta = msg(3.0, opaque="0x3", opcode="0xa2", src="10.0.0.9")
    meta["sport"] = "11210"
    meta["dport"] = "11210"
    meta_reply = msg(3.4, opaque="0x3", opcode="0xa2", kind="resp")
    meta_reply["status"] = "0x0000"
    requests = [app, node, meta]
    responses = [app_reply, node_reply, meta_reply]
    charts = ac.build_charts(requests, ac.pair_messages(requests, responses), [], ["11210"], 5.0)
    gets = [row for row in charts["boxplot"] if row["opcode"] == "0x00"]
    assert {row["role"] for row in gets} == {"sdk", "cluster"}
    sdk = next(row for row in gets if row["role"] == "sdk")
    cluster_get = next(row for row in gets if row["role"] == "cluster")
    assert sdk["box"][2] == 50.0
    assert cluster_get["box"][2] == 200.0
    meta_row = next(row for row in charts["boxplot"] if row["opcode"] == "0xa2")
    assert meta_row["role"] == "cluster"
    assert meta_row["box"][2] == 400.0


def _answered(request, delay):
    reply = msg(
        request["time"] + delay,
        stream=request["stream"],
        opaque=request["opaque"],
        opcode=request["opcode"],
        key=request["key"],
        src=request["dst"],
        kind="resp",
    )
    reply["dst"] = request["src"]
    reply["sport"] = request["dport"]
    reply["dport"] = request["sport"]
    reply["status"] = "0x0000"
    return reply


def test_related_keeps_a_path_when_a_hole_sits_beside_a_slow_call():
    app = msg(1.0, stream="7", opaque="0xabc", opcode="0x00", key="doc", src="10.0.0.8")
    cluster = msg(1.1, stream="8", opaque="0xdef", opcode="0xa2", key="doc", src="10.0.0.3")
    cluster["dst"] = "10.0.0.8"
    cluster["sport"] = "11210"
    cluster["dport"] = "11210"
    fast = msg(4.0, stream="7", opaque="0x11", opcode="0x00", key="doc", src="10.0.0.8")
    other = msg(2.0, stream="3", opaque="0x22", opcode="0x00", key="doc", src="10.0.0.4")
    other["dst"] = "10.0.0.5"
    requests = [app, cluster, fast, other]
    responses = [_answered(app, 0.08), _answered(cluster, 0.15), _answered(fast, 0.01), _answered(other, 0.01)]
    charts = ac.build_charts(
        requests,
        ac.pair_messages(requests, responses),
        [
            {"time": 1.3, "stream": "7", "src": "10.0.0.3", "dst": "10.0.0.8", "sport": "11210", "dport": "4000", "lost": True, "retrans": False, "ack": False},
            {"time": 1.35, "stream": "7", "src": "10.0.0.8", "dst": "10.0.0.3", "sport": "4000", "dport": "11210", "lost": False, "retrans": False, "ack": True},
            {"time": 1.2, "stream": "7", "src": "10.0.0.8", "dst": "10.0.0.3", "sport": "4000", "dport": "11210", "lost": False, "retrans": True, "ack": False, "duplicate": True},
            {"time": 3.5, "stream": "7", "src": "10.0.0.8", "dst": "10.0.0.3", "sport": "4000", "dport": "11210", "lost": False, "retrans": True, "ack": False},
            {"time": 2.05, "stream": "3", "src": "10.0.0.5", "dst": "10.0.0.4", "sport": "11210", "dport": "4000", "lost": True, "retrans": False, "ack": False},
            {"time": 1.0, "stream": "1", "sport": "11210", "dport": "4000", "lost": True, "retrans": False, "ack": False},
        ],
        ["11210"],
        5.0,
    )
    related = charts["related"]
    assert related["port"] == "11210"
    assert related["window"] == 0.5
    assert [(lane["lane"], lane["label"], lane["related"]) for lane in related["lanes"]] == [
        (0, "10.0.0.3 ↔ 10.0.0.8", 2),
    ]
    by_kind = {}
    for point in related["points"]:
        assert "key" not in point
        assert "doc" not in point.values()
        by_kind.setdefault(point["kind"], []).append(point)
    assert set(by_kind) == {"call", "lost", "ack", "retrans"}
    calls = {(point["role"], point["name"], point["z"], point["burst"], point["near"], point["filter"]) for point in by_kind["call"]}
    assert calls == {
        ("sdk", "Get", ac._ms(0.08), 1, True, "tcp.stream == 7 && couchbase.opaque == 0xabc"),
        ("cluster", "Set with Meta", ac._ms(0.15), 1, True, "tcp.stream == 8 && couchbase.opaque == 0xdef"),
    }
    lost = by_kind["lost"][0]
    assert lost["lane"] == 0
    assert lost["z"] == 0
    assert lost["toward"] == "client"
    assert lost["src"] == "10.0.0.3" and lost["dst"] == "10.0.0.8"
    assert lost["near"] is True and lost["burst"] == 1
    assert lost["filter"] == "tcp.stream == 7 && tcp.analysis.lost_segment"
    ack = by_kind["ack"][0]
    assert ack["toward"] == "server" and ack["burst"] == 1 and ack["near"] is True
    assert ack["filter"] == "tcp.stream == 7 && tcp.analysis.ack_lost_segment"
    retry = by_kind["retrans"][0]
    assert retry["t"] == round(3.5, 3)
    assert retry["burst"] == 2 and retry["near"] is False and retry["z"] == 0
    assert retry["filter"] == "tcp.stream == 7 && tcp.analysis.retransmission && tcp.analysis.rto >= 0.001"
    assert all(point["t"] != round(4.0, 3) for point in related["points"])

    alone = msg(1.0, stream="5", opaque="0x5", src="10.0.0.6")
    alone_charts = ac.build_charts([alone], ac.pair_messages([alone], [_answered(alone, 0.2)]), [], ["11210"], 5.0)
    assert alone_charts["related"]["lanes"] == []


def test_related_keeps_the_overlapping_call_when_the_row_is_capped():
    near = msg(1.0, stream="1", opaque="0x1", src="10.0.0.2")
    requests = [near]
    responses = [_answered(near, 0.08)]
    for index in range(40):
        request = msg(10.0 + index, stream="2", opaque=f"0x{index + 2:x}", src="10.0.0.2")
        requests.append(request)
        responses.append(_answered(request, 0.2))
    loss = {
        "time": 1.2,
        "stream": "1",
        "src": "10.0.0.2",
        "dst": "10.0.0.3",
        "sport": "4000",
        "dport": "11210",
        "lost": True,
        "retrans": False,
        "ack": False,
    }
    charts = ac.build_charts(requests, ac.pair_messages(requests, responses), [loss], ["11210"], 60.0)
    calls = [point for point in charts["related"]["points"] if point["kind"] == "call"]
    assert len(calls) == ac._RELATED_CALLS
    kept = [point for point in calls if point["t"] == round(1.0, 3)]
    assert len(kept) == 1
    assert kept[0]["near"] is True
    assert kept[0]["z"] == ac._ms(0.08)


def test_side_tally_skips_an_empty_key_and_keeps_a_zero():
    tally = ac._SideTally()
    tally.add("sdk", "", 5)
    tally.add("cluster", "doc", 0)
    tally.add("sdk", "doc", 4)
    assert list(tally.all) == ["doc"]
    assert tally.all["doc"] == 4
    assert tally.cluster["doc"] == 0
    assert tally.sdk["doc"] == 4

