# Couchbase Wireshark analyzer

## Problem

A Wireshark dump of Couchbase is a long list of requests, replies, opcodes, document sizes, and TCP holes. One slow operation is one row in that list. The useful question is the larger picture: what else was happening in that same second, and what keeps happening across the capture.

- Did response time rise with one command, or with everything?
- Did missing replies sit next to TCP holes, or on their own?
- Did a large document move in or out in the same second as the slow calls?
- Is the pattern one connection, or the whole client?

The dump has the packets. It does not line those trends up.

## Solution

This tool counts the capture and draws the trends on one time axis. The time charts share a crosshair. A stake marks the same second on every chart, so opcode mix, response time, missing replies, TCP loss, and body size can be read together. Python owns every number. A local Qwen model writes the note from those counts, including the next questions.

![From dump to note](images/pipeline.svg)

![What an unmatched packet means](images/edges.svg)

The match key is `tcp.stream` plus `couchbase.opaque`. The in-flight window is the longest matched round trip: a response at the open of the file, and a request at the close, are the capture cutting through calls already on the wire. Unmatched rows farther inside the file are counted with the TCP gaps when a pcap is available.

### Calls by opcode and response time

![Stacked opcodes with median and p99](images/op_type_vs_speed.png)

Each color is one Couchbase command. Bar height is how many of that command ran in the second. Median and p99 are the lines on the millisecond axis. Read it for the correlation: a p99 spike next to a tall stack is one command getting slow, or a mix of commands getting slow together.

### Lost responses, retries, and TCP loss

![Lost responses beside TCP holes](images/no_response_vs_tcp_packet_loss.png)

The bars are Couchbase operations: matched calls, requests whose reply is missing, and replies whose request is missing. TCP loss and retries use the packet axis. Read it for the correlation: a lost response beside a TCP hole means the reply was probably never in the recording. Retries stay near zero when the sender did not resend, which fits packets missing from the capture.

### Total body length

![Largest request and reply body each second](images/json_size_in_out.png)

Each bar is the largest Couchbase body in that second. Body length is extras, key, and value. Into Couchbase is the request. Out of Couchbase is the reply. A high bar means a lot of document data moved in or out during that second. A 1 Gbit NIC can carry about 125 MB/s (125,000,000 bytes). A 10 Gbit NIC can carry about 1,250 MB/s (1,250,000,000 bytes). Read it against the p99 line for the same second: the bytes and the slow calls either land together or they do not.

## Getting Started

You need Python 3.11 or newer and tshark (from Wireshark). The chart page does not need a network. The model note needs Ollama already running.

```bash
git clone https://github.com/Fujio-Turner/cb_wireshark_analyzer.git
cd cb_wireshark_analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 analyze_capture.py --no-ai /path/to/capture.pcap -o ./orphan-report
cd orphan-report
python3 -m http.server
```

Open `http://127.0.0.1:8000/`. Add the local model by dropping `--no-ai` once Ollama is listening. The virtual-machine section and the Docker section below have the full install steps.

## Config

`config.json` in the project root:

```json
{
  "ollama": {
    "base_url": "http://127.0.0.1:11434",
    "model": "qwen3.8:27b-mlx",
    "timeout_seconds": 600
  },
  "tshark": "",
  "output_dir": ""
}
```

An empty `tshark` or `output_dir` means "detect it" and "write `orphan-report/` next to the input". A flag on the command line wins over the environment, which wins over this file. `OLLAMA_BASE_URL` and `TSHARK` are the environment names. `qwen3.8-notes:latest` is the other local tag if you want it in `model`.

## Run on a virtual machine

These steps are for an Ubuntu VM (or any Linux host) with the repo checked out. The same virtualenv commands work on macOS. tshark comes from Wireshark; on a Mac with the app installed, the script finds it under `/Applications/Wireshark.app` when it is not on `PATH`.

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv tshark
# Offline pcaps do not need dumpcap setuid. Answer "no" if the package asks.

git clone https://github.com/Fujio-Turner/cb_wireshark_analyzer.git
cd cb_wireshark_analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# See the plan. Nothing is written and Ollama is not called.
python3 analyze_capture.py --dry-run /path/to/capture.pcap

# Counted note only.
python3 analyze_capture.py --no-ai /path/to/capture.pcap -o ./orphan-report

# Counted note plus the local model. Ollama must already be listening.
python3 analyze_capture.py /path/to/capture.pcap -o ./orphan-report

python3 -m pytest -q
```

Install Ollama on the VM if the note should be written there, or point `ollama.base_url` at a machine that already has `qwen3.8:27b-mlx`. `--dry-run` and `--no-ai` do not need the model.

A `.tsv` or `.csv` field export works too. Request rows are 10 columns (frame, time, tcp.stream, source, source port, destination, destination port, opcode, opaque, key). Response rows are 6 (frame, time, tcp.stream, opcode, opaque, status). A header row that names those fields also works. When a pcap sits next to `reqs.tsv`, the pcap is used, because that export leaves `couchbase.key` empty on collections and can join several messages into one row. `--from-tsv` keeps the spreadsheet files.

```bash
python3 analyze_capture.py reqs.tsv --resps resps.tsv --from-tsv --dry-run
```

## Run in Docker

`docker-compose.yml` builds one image and exposes two services: `analyze` and `test`. The image includes Python, pytest, and tshark. Ollama is not in the image. Compose points the container at `host.docker.internal` so it can use the model on the machine running Docker.

Put a capture in `captures/` (that directory is gitignored except for the placeholder).

```bash
docker compose build

# Unit tests. No capture and no model.
docker compose run --rm test

# Plan only. No files written, model not called.
docker compose run --rm analyze --dry-run --no-ai /captures/your.pcap -o /out

# Counted note, written to ./orphan-report on the host.
docker compose run --rm analyze --no-ai /captures/your.pcap -o /out

# Counted note plus Qwen on the host.
docker compose run --rm analyze /captures/your.pcap -o /out
```

`CAPTURE_DIR` and `OUT_DIR` change the mounts. `OLLAMA_BASE_URL` changes where the container sends the note request. From a Linux VM, `host.docker.internal` is added by Compose (`host-gateway`). Start Ollama on the host before the last command.

## Charts

Every run writes `charts.json` and `index.html` next to the note. The page opens with latency tiles: median, p90, p95, p99, max, and how many matched calls were at least 100 ms or 250 ms. A side panel switches the time bucket (1, 5, or 10 seconds) and switches every numeric axis between linear and log. The time charts share one crosshair. Double-click drops a stake on that second. The stake stays when a legend series is hidden. Each chart has an expand control that opens it on a black transparent overlay and keeps the current zoom and stakes.

The ten slowest matched calls are listed with the response time, the second the request was sent, and the body size. **Set Stake** marks that second on the other charts, which is how a single slow call is placed back into the trend. The bottom of the page is **Next questions / steps**, written from the same counts as the note.

The same page also has the latency histogram, round-trip percentiles, a chart of median and p99 with dashed TCP-loss and retry lines, a min-to-max candle, p99 by opcode, and the client chart. Client IP is the first tab. IP and source port is the second.

From the report folder:

```bash
python3 -m http.server
```

Then open `http://127.0.0.1:8000/`. A browser that opens the file directly will not be allowed to read `charts.json`. ECharts is stored in `web/vendor/` and copied next to the page, so the charts do not need a network.

## Dry run

`--dry-run` still reads the capture and counts. It prints the output directory, the files it would write, whether it would call the model, and the three headline counts. It does not create the directory and it does not call Ollama.

```bash
python3 analyze_capture.py --dry-run /path/to/capture.pcap
```

## Output

| File | What it is |
|---|---|
| `summary.md` | The note. The model writes it unless `--no-ai` is set. |
| `summary.computed.md` | The counted note. Written on a model run, next to the model text. |
| `facts.json` | The counts the note is built from. |
| `charts.json` | One-, five-, and ten-second aggregates for the chart page. |
| `index.html` | ECharts page. Open it from a local server so it can read `charts.json`. |
| `orphans.tsv` | Unanswered requests, one per row, with the document key. |
| `reqs.pdus.tsv` | One client request per row. Column J is the logical key. |
| `resps.tsv` | One client response per row. |

## Tests

```bash
source .venv/bin/activate
python3 -m pytest -q
```

`python3 analyze_capture.py --self-test` runs that same suite. In Docker, `docker compose run --rm test` runs it inside the image. The tests use small fixtures. They do not read a pcap and they do not call Ollama.

## Release Notes

[RELEASE_NOTES.md](RELEASE_NOTES.md)

## Troubleshooting

**tshark is not found.** On macOS, install Wireshark. The script looks on `PATH`, then in `/Applications/Wireshark.app`. Set `tshark` in `config.json` or `TSHARK` if the binary lives somewhere else.

**The chart page is blank, or it says it could not read `charts.json`.** Open the report through a local server (`python3 -m http.server` in the report folder). A browser will not let a `file://` page read `charts.json`.

**The model note was not written.** Ollama has to be listening at `ollama.base_url`, and the `model` tag has to be pulled. `--no-ai` skips the model and still writes the counted `summary.md`. If the model call fails, that counted note is what gets saved.

**Docker cannot reach the model.** Ollama stays on the host. Compose uses `host.docker.internal`. Start Ollama on the host before `docker compose run analyze` without `--no-ai`.

**A `.tsv` next to a pcap was ignored.** When both are in the folder, the pcap is used. `--from-tsv` keeps the spreadsheet files. Collection document ids are `couchbase.key.logical_key`. An export of `couchbase.key` is often empty.

**The client IP chart is one slice.** Every request in that capture came from one address. The **IP : port** tab splits that client by source port.

## License

[Apache License 2.0](LICENSE)
