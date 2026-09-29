"""Config resolution, dry-run, and the counted write path."""

import json
from pathlib import Path

import analyze_capture as ac


def _pair(tmp_path):
    reqs = tmp_path / "reqs.tsv"
    resps = tmp_path / "resps.tsv"
    reqs.write_text(
        "10\t1.0\t0\t10.0.0.2\t40000\t10.0.0.3\t11210\t0x00\t0x0000000a\tleft\n"
    )
    resps.write_text("11\t1.04\t0\t0x00\t0x0000000a\t0x0000\n")
    return reqs, resps


def test_dry_run_prints_the_plan_and_writes_nothing(tmp_path, capsys):
    reqs, resps = _pair(tmp_path)
    out = tmp_path / "out"
    code = ac.main(
        [
            "--from-tsv",
            "--reqs",
            str(reqs),
            "--resps",
            str(resps),
            "--dry-run",
            "--no-ai",
            "-o",
            str(out),
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert not out.exists()
    assert "dry-run" in captured.out
    assert "summary.md" in captured.out
    assert "model: skipped (--no-ai)" in captured.out
    assert "unanswered 0" in captured.out
    assert "matched 1" in captured.out


def test_dry_run_names_the_model_it_would_call(tmp_path, capsys):
    reqs, resps = _pair(tmp_path)
    code = ac.main(
        [
            "--from-tsv",
            "--reqs",
            str(reqs),
            "--resps",
            str(resps),
            "--dry-run",
            "--model",
            "qwen3.8:27b-mlx",
            "--ollama",
            "http://127.0.0.1:11434",
            "-o",
            str(tmp_path / "nowhere"),
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "would call qwen3.8:27b-mlx at http://127.0.0.1:11434" in captured.out
    assert "summary.computed.md" in captured.out
    assert not (tmp_path / "nowhere").exists()


def test_no_ai_writes_the_counted_note(tmp_path):
    reqs, resps = _pair(tmp_path)
    out = tmp_path / "report"
    code = ac.main(
        [
            "--from-tsv",
            "--reqs",
            str(reqs),
            "--resps",
            str(resps),
            "--no-ai",
            "-o",
            str(out),
        ]
    )
    assert code == 0
    assert (out / "summary.md").is_file()
    assert (out / "facts.json").is_file()
    assert (out / "charts.json").is_file()
    assert (out / "index.html").is_file()
    assert (out / "summary.html").is_file()
    assert (out / "index.original.html").is_file()
    page = (out / "index.html").read_text()
    assert "vendor/echarts.min.js" in page
    assert "https://github.com/Fujio-Turner/cb_wireshark_analyzer" in page
    assert f">v{ac.project_version()}<" in page
    assert 'id="timings"' in page
    assert 'id="data-source"' in page
    assert 'href="charts.json" target="_blank"' in page
    assert 'href="summary.html"' in page
    report = (out / "summary.html").read_text()
    assert "summary.md" in report
    assert 'id="note"' in report
    assert "jsdelivr" not in page
    assert "vendor/echarts-gl.min.js" in page
    assert (out / "vendor" / "echarts.min.js").is_file()
    assert (out / "vendor" / "echarts-gl.min.js").is_file()
    assert "matched" in (out / "summary.md").read_text()
    facts = json.loads((out / "facts.json").read_text())
    assert facts["counts"]["matched"] == 1
    assert facts["counts"]["unanswered_requests"] == 0


def test_openai_request_uses_chat_completions_and_leaves_the_key_out_of_the_body():
    url, payload, headers = ac.model_request(
        "counts",
        provider="openai",
        base_url="https://example.test/v1/",
        model="remote-model",
        system="Be brief.",
        api_key="secret-value",
    )
    assert url == "https://example.test/v1/chat/completions"
    assert payload["messages"][0]["content"] == "Be brief."
    assert "secret-value" not in json.dumps(payload)
    assert headers["Authorization"] == "Bearer secret-value"
    text = ac.message_text(
        {"choices": [{"message": {"content": [{"type": "text", "text": "hello "}, {"type": "text", "text": "there"}]}}]},
        "openai",
    )
    assert text == "hello there"
    ollama_url, ollama_payload, _headers = ac.model_request(
        "counts",
        provider="ollama",
        base_url="http://127.0.0.1:11434/",
        model="qwen",
        system=None,
        api_key="",
    )
    assert ollama_url == "http://127.0.0.1:11434/api/chat"
    assert ollama_payload["think"] is False


def test_remote_openai_requires_an_api_key():
    try:
        ac.call_model(
            "hi",
            provider="openai",
            base_url="https://api.openai.com/v1",
            model="remote-model",
            timeout=1,
            api_key="",
        )
    except SystemExit as exc:
        assert "AI_API_KEY" in str(exc)
    else:
        raise AssertionError("a remote API without a key should stop")


def test_openai_config_reads_the_key_from_the_environment(tmp_path, monkeypatch):
    for name in ("OLLAMA_BASE_URL", "AI_PROVIDER", "AI_BASE_URL", "AI_MODEL", "AI_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    cfg = tmp_path / "config.json"
    cfg.write_text(
        json.dumps(
            {
                "ai": {
                    "provider": "openai",
                    "base_url": "https://example.test/v1",
                    "model": "remote-model",
                    "timeout_seconds": 30,
                },
                "ollama": {"model": "local-model", "base_url": "http://127.0.0.1:11434"},
            }
        )
    )
    monkeypatch.setenv("AI_API_KEY", "secret-value")
    args = ac.parse_args(["--config", str(cfg), "--reqs", "reqs.tsv", "--from-tsv"])
    ac.apply_config(args)
    assert args.provider == "openai"
    assert args.model == "remote-model"
    assert args.api_base == "https://example.test/v1"
    assert args.api_key == "secret-value"
    assert args.timeout == 30
    args = ac.parse_args(
        [
            "--config",
            str(cfg),
            "--reqs",
            "reqs.tsv",
            "--from-tsv",
            "--provider",
            "openai",
            "--api-base",
            "https://cli.test/v1",
            "--model",
            "cli-model",
        ]
    )
    ac.apply_config(args)
    assert args.model == "cli-model"
    assert args.api_base == "https://cli.test/v1"


def test_config_then_environment_then_cli(tmp_path, monkeypatch):
    for name in ("AI_PROVIDER", "AI_BASE_URL", "AI_MODEL", "AI_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    cfg = tmp_path / "config.json"
    cfg.write_text(
        json.dumps(
            {
                "ollama": {
                    "model": "from-config",
                    "base_url": "http://config:11434",
                    "timeout_seconds": 12,
                },
                "tshark": "/opt/tshark",
                "output_dir": "from-config-out",
            }
        )
    )
    args = ac.parse_args(["--config", str(cfg), "--reqs", "reqs.tsv", "--from-tsv"])
    ac.apply_config(args)
    assert args.model == "from-config"
    assert args.ollama == "http://config:11434"
    assert args.timeout == 12
    assert args.tshark == "/opt/tshark"
    assert args.out == "from-config-out"

    monkeypatch.setenv("OLLAMA_BASE_URL", "http://env:9")
    monkeypatch.setenv("TSHARK", "/env/tshark")
    args = ac.parse_args(["--config", str(cfg), "--reqs", "reqs.tsv", "--from-tsv"])
    ac.apply_config(args)
    assert args.ollama == "http://env:9"
    assert args.tshark == "/env/tshark"
    assert args.model == "from-config"

    args = ac.parse_args(
        [
            "--config",
            str(cfg),
            "--reqs",
            "reqs.tsv",
            "--from-tsv",
            "--model",
            "from-cli",
            "--ollama",
            "http://cli:1",
            "--tshark",
            "/cli/tshark",
            "-o",
            "from-cli-out",
        ]
    )
    ac.apply_config(args)
    assert args.model == "from-cli"
    assert args.ollama == "http://cli:1"
    assert args.tshark == "/cli/tshark"
    assert args.out == "from-cli-out"


def test_capinfos_prefers_the_exact_packet_count():
    text = """
Number of packets:   82 k
Capture duration:    119.990358 seconds
Number of packets = 82230
"""
    duration, packets = ac.parse_capinfos_text(text)
    assert duration == 119.990358
    assert packets == 82230


def test_capinfos_expands_a_rounded_summary_when_that_is_all_it_has():
    duration, packets = ac.parse_capinfos_text("Number of packets: 82 k\nCapture duration: 10.5 seconds\n")
    assert duration == 10.5
    assert packets == 82000


def test_log_level_defaults_to_info():
    args = ac.parse_args(["--reqs", "reqs.tsv", "--from-tsv"])
    assert args.log_level == "INFO"
    debug = ac.parse_args(["--reqs", "reqs.tsv", "--from-tsv", "--log-level", "debug"])
    assert debug.log_level == "DEBUG"


def test_log_record_is_one_json_line(capsys):
    ac.telemetry.set_level("INFO")
    ac.log("counted the capture", packets=3)
    lines = [line for line in capsys.readouterr().err.splitlines() if line.strip()]
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["body"] == "counted the capture"
    assert record["severity_text"] == "INFO"
    assert record["severity_number"] == 9
    assert record["timestamp"].endswith("Z")
    assert "T" in record["timestamp"]
    assert len(record["trace_id"]) == 32
    assert record["attributes"]["packets"] == 3
    assert record["resource"]["service.name"] == "cb_wireshark_analyzer"
    assert record["resource"]["service.version"]
    assert record["instrumentation_scope"]["name"] == "analyze_capture"


def test_span_records_duration_and_keeps_attributes(capsys):
    ac.telemetry.set_level("INFO")
    try:
        with ac.telemetry.span("pair_messages", requests=2, folder=Path("/tmp/report")) as span:
            span.set(matched=1)
            span.set(skipped=None)
    finally:
        ac.telemetry.set_level("INFO")
    lines = [json.loads(line) for line in capsys.readouterr().err.splitlines() if line.strip()]
    assert len(lines) == 1
    row = lines[0]
    assert row["kind"] == "span"
    assert row["name"] == "pair_messages"
    assert row["duration_ms"] >= 0
    assert row["status"]["code"] == "OK"
    assert row["attributes"]["requests"] == 2
    assert row["attributes"]["matched"] == 1
    assert row["attributes"]["folder"] == "/tmp/report"
    assert "skipped" not in row["attributes"]
    assert len(row["trace_id"]) == 32
    assert len(row["span_id"]) == 16

    ac.telemetry.set_level("DEBUG")
    try:
        with ac.telemetry.span("load_pcap"):
            pass
    finally:
        ac.telemetry.set_level("INFO")
    debug_lines = [json.loads(line) for line in capsys.readouterr().err.splitlines() if line.strip()]
    assert any(item["body"] == "load_pcap started" and item["severity_text"] == "DEBUG" for item in debug_lines)
    assert any(item.get("kind") == "span" and item["name"] == "load_pcap" for item in debug_lines)


def test_log_level_hides_lower_severities(capsys):
    ac.telemetry.set_level("ERROR")
    try:
        ac.log("quiet progress")
        ac.log("broke", severity="ERROR", frames=1)
    finally:
        ac.telemetry.set_level("INFO")
    lines = [json.loads(line) for line in capsys.readouterr().err.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["severity_text"] == "ERROR"
    assert lines[0]["severity_number"] == 17
    assert lines[0]["attributes"]["frames"] == 1


def test_span_marks_an_error_and_reraises(capsys):
    ac.telemetry.set_level("INFO")
    try:
        with ac.telemetry.span("call_model"):
            raise SystemExit("model down")
    except SystemExit as exc:
        assert "model down" in str(exc)
    else:
        raise AssertionError("span should not swallow SystemExit")
    finally:
        ac.telemetry.set_level("INFO")
    lines = [json.loads(line) for line in capsys.readouterr().err.splitlines() if line.strip()]
    row = next(item for item in lines if item.get("kind") == "span")
    assert row["status"]["code"] == "ERROR"
    assert row["severity_text"] == "ERROR"
    assert row["attributes"]["error"] == "model down"
