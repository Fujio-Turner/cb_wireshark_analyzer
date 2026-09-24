"""Config resolution, dry-run, and the counted write path."""

import json

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
    page = (out / "index.html").read_text()
    assert "vendor/echarts.min.js" in page
    assert "https://github.com/Fujio-Turner/cb_wireshark_analyzer" in page
    assert f">v{ac.project_version()}<" in page
    assert "jsdelivr" not in page
    assert (out / "vendor" / "echarts.min.js").is_file()
    assert "matched" in (out / "summary.md").read_text()
    facts = json.loads((out / "facts.json").read_text())
    assert facts["counts"]["matched"] == 1
    assert facts["counts"]["unanswered_requests"] == 0


def test_config_then_environment_then_cli(tmp_path, monkeypatch):
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
