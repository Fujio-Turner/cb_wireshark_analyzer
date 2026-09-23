# Release notes

## 0.1.0

First packaged release of the Couchbase capture orphan tool.

- Count client requests with no response, and responses with no request, on `tcp.stream` plus `couchbase.opaque`.
- Separate the open and close of the capture from interior gaps, using the longest matched round trip.
- When the input is a pcap, count TCP lost segments and retransmissions on the Couchbase port.
- Ask a local Ollama model (default `qwen3.8:27b-mlx` in `config.json`) to write `summary.md` from those counts.
- `--dry-run` prints the plan and the counts, and does not write files or call the model.
- `--no-ai` writes the counted note only.
- Unit tests live in `tests/`. Run them in a virtualenv on a VM, or with `docker compose run --rm test`.
- `Dockerfile` and `docker-compose.yml` install Python and tshark. Ollama stays on the host.
