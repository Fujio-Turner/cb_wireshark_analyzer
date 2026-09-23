# Couchbase capture orphans

Counts Couchbase requests that have no response in a Wireshark dump, then asks a local Qwen model to write the note. Python owns every number. The model writes from those counts.

![From dump to note](images/pipeline.svg)

![What an unmatched packet means](images/edges.svg)

The match key is `tcp.stream` plus `couchbase.opaque`. The in-flight window is the longest matched round trip: a response at the open of the file, and a request at the close, are the capture cutting through calls already on the wire. Unmatched rows farther inside the file are counted with the TCP gaps when a pcap is available.

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

git clone <this repo> cb-capture-orphans
cd cb-capture-orphans
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
| `orphans.tsv` | Unanswered requests, one per row, with the document key. |
| `reqs.pdus.tsv` | One client request per row. Column J is the logical key. |
| `resps.tsv` | One client response per row. |

## Tests

```bash
source .venv/bin/activate
python3 -m pytest -q
```

`python3 analyze_capture.py --self-test` runs that same suite. In Docker, `docker compose run --rm test` runs it inside the image. The tests use small fixtures. They do not read a pcap and they do not call Ollama.
