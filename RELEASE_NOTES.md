# Release notes

## 0.3.0

Correlations on one second, and a Wireshark sheet for tracing a missing reply.

- The local model picks points of interest from the counted spikes and the page draws those stakes when it opens. **Points of interest** lists them as `pi:1`, `pi:2`, and so on. The chart flag reads `Stake 1(pi:1)`. Remove stake clears the lines. Set Stake puts that row back.
- Each interest row shows that second’s median, p99, top opcode, bytes in, bytes out, loss toward the client, loss toward the server, and lost responses.
- Total body length keeps bars for the largest request and the largest reply. Dashed lines add every document byte in that second. Those lines start hidden.
- TCP loss is split into loss toward the client (reply path) and loss toward the server (request path). The Matched bars on the lost-response chart start hidden.
- The IP : port tab sorts connections by unanswered percent.
- Hiding a legend series on one chart leaves the same name visible on the other charts. The crosshair still lines up.
- The slow-call table shows TCP stream and `couchbase.opaque`, the semi-transaction number shared by the request and its reply.
- The glossary sits at the bottom of the page.
- [CB_WIRESHARK.md](CB_WIRESHARK.md) lists document, opaque, opcode, status, body, and TCP-loss filters. It explains `couchbase && tcp.time_delta > 0.05` and how to add that gap as a column. It walks through tracing a request with no response, and warns that requests still in flight at the end of the file are false positives.
- The README describes the two outputs of a run: `summary.md`, and `charts.json` with `index.html`.

## 0.2.0

The project is now `cb_wireshark_analyzer`. Chart page, body size, and a fuller note for the local model.

- One tshark pass reads Couchbase messages and TCP loss, retransmission, and ack-lost flags together.
- `couchbase.total_bodylength` is kept on each message. The chart page plots the largest request body and the largest reply body in each second.
- `charts.json` and `index.html` are written beside the note. ECharts 5.6.0 is vendored in `web/vendor/` and copied into the report, so the page works offline.
- The page leads with latency tiles, then a histogram, opcode mix with median and p99, round-trip percentiles, median and p99 drawn with dashed TCP-loss and retry lines, a min-to-max candle, lost responses against TCP loss, and total body length.
- Time charts share a crosshair. The bucket control is 1, 5, or 10 seconds. The axis control switches linear and log on every numeric axis.
- Double-click drops a colored stake on that second across the time charts. Hiding a legend series leaves the stake in place. Each chart expands onto a black transparent overlay and keeps the current zoom and stakes.
- Client IP is the first donut tab. IP and source port is the second.
- Opcode names and short descriptions come from the Wireshark client opcode list. The chart popup shows the command and the count. The hex and the description sit in the opcode table.
- The slowest-call table lists response time, seconds from the start of the capture, and body bytes, with a Set Stake button. A second click on the same second does not add another line.
- The bottom of the page and the note both end with Next questions and steps, built from the counts.
- The local model receives the slow-call bands, body sizes, client connections, opcode medians, and the ten slowest calls, along with the orphan counts.

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
