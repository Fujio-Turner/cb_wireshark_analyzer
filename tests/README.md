# Tests

The suite is in this folder. It uses small TSV fixtures. It does not read a pcap and it does not call Ollama.

## Virtual machine

On the Ubuntu VM (or the Mac), from the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m pytest -q
```

`python3 analyze_capture.py --self-test` runs the same pytest command.

## Docker

From the repo root, with Docker running:

```bash
docker compose build
docker compose run --rm test
```

That service overrides the entrypoint and runs `python3 -m pytest -q` inside the image. The `analyze` service is the capture tool; see the root README for `--dry-run` and a mounted `/captures` file.
