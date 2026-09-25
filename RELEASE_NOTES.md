# Release notes

## 0.9.1

Each capture writes its own report folder. `filename_1.pcap` becomes `filename_1-report/` next to the file, so a second pcap in the same directory does not overwrite the first. Pass `-o` when you want a different path.

## 0.9.0

The chart page and the report hand you a Wireshark filter for the row you are looking at.

- The time-bucket menu adds 0.5 seconds next to 1 second.
- Missing calls have an **Errors** column. A dash means no TCP hole within half a second. **possible** copies one filter: the document and the opaque on their stream, or the lost segments and lost acks to and from that requester in the surrounding time.
- Copy icons sit on the stream, the opaque (stream and opaque together, which is one call), the opcode, the client address, and the half-second around **Set Stake**. Click a bar on **Packets on port 11210** to copy that command. [CB_WIRESHARK.md](CB_WIRESHARK.md) lists each of these.
- The report ends with a counted **Wireshark filters** section. Each line has a Copy button.
- **Choose a client** opens the application addresses, missing replies first, with a box that narrows the list as you type.

## 0.8.0

DCP is read as replication, not as lost calls, and a second copy of the same TCP segment is no longer called a retry.

- Command names and DCP flags come from Wireshark’s dissector, `epan/dissectors/packet-couchbase.c`. There is no separate Couchbase decoder tree. The GitHub copy is a read-only mirror of the GitLab file. The protocol is Couchbase kv_engine’s binary protocol and DCP docs. [CB_WIRESHARK.md](CB_WIRESHARK.md) names both.
- DCP is full duplex. The opaque on a stream request is copied onto every later snapshot and mutation. That number is the stream, not one call. Those packets do not expect a command reply. A snapshot marker wants a reply only when the ack flag is set. A buffer acknowledgement does not get a reply. A noop does. A later packet with the same opaque is the next change, not a retry. Statistics key `vbucket-seqno` is many packets on one opaque and counts as one call. Get All VBucket Seqnos and that statistics key are cluster setup, not application calls.
- The timing charts draw the application and the cluster separately: tiles, histogram, round trip, tail, candles, and the opcode-mix lines. Blue is the application. Rust is the cluster. The time-bucket menu adds 0.5 seconds next to 1 second.
- Missing calls are four tabs. Application requests and application replies come first, then the cluster tabs.
- **Capture duplicate** is the same TCP segment recorded again within a millisecond. Wireshark calls that a retransmission. The bar starts hidden. The glossary holds the explanation, and the dotted words on the chart point there. A red Retransmission bar is a resend that waited out a timeout. A packet with a Couchbase header is counted as that command even when TCP also flags it.
- The note sent to the model stays bounded. The stream list is the 12 busiest connections, and the reply is capped. The brief includes the DCP rules and the capture-duplicate count.

## 0.7.0

Cluster replication and application calls are counted apart, so a missing reply or a retransmission can be blamed on the side that caused it.

- **Cluster** is node port 11210 or 11207 talking to another node port, or a DCP or replication-meta command (Set with Meta, Get Meta, Delete with Meta). **SDK** is an application port talking to 11210. A reply packet stays with the same flow.
- **Cluster** sits above **Client fleet**. It has the replication commands, the node connections, and a time chart of SDK requests, cluster requests, missing replies, and retransmissions. That chart shares the crosshair with the other time charts.
- **Client fleet** and **Look up a client** are application addresses only. Look up is a search box, not a menu of every address. Click a row in the fleet table to open that client.
- The tiles show an SDK median and a cluster median. The missing-call sample, the ten slowest calls, and the opcode list are marked `sdk` or `cluster`. The counted note and the first next question state both sides.

## 0.6.0

Clients at fleet scale, a formatted report, and a note that can go to your own API.

- **Clients** is its own section. The pie is the eight clients with the most missing replies, then one slice for every other client. Names are in a legend. The bar counts clients in six unanswered-percent bands, so the chart stays the same size for thousands of clients. One address has its own port pie. The old Requests by client IP chart is gone.
- **Report / Questions** opens `summary.html`, which formats `summary.md` in the same header and colors as the charts. `summary.computed.md` is a second tab when a model run wrote it. Next questions stay under the button.
- The section pills stay on the left of the bar. On the right, plain links open the note and `charts.json`. The report page uses the same split: note tabs on the left, `charts.json` on the right.
- Under **Glossary**, **Data source** links to `charts.json` and says what that file holds. Python writes it before a model runs.
- The note can go to an OpenAI-compatible chat API as well as local Ollama. Set `ai.provider` to `openai`, or pass `--provider openai --api-base … --model …`. The key belongs in `AI_API_KEY` or `OPENAI_API_KEY`, not in `config.json`.

## 0.5.0

The chart page is grouped, and the missing-call tables are spaced across the capture.

- A bar under the title jumps to **Timings**, **Operations**, **Packets**, **Documents**, **Marks**, **Questions**, and **Glossary**. Chips under each heading jump to that chart. A dotted word jumps to its glossary entry.
- Related charts sit side by side on a wide window, so the page is shorter. On a narrow window they stack, and wide tables scroll inside the card.
- Requests with no response, and responses with no request, show up to ten rows spaced from the earliest to the latest. They are not the first ten. The tab label is still the full count. The page does not list every missing call. Every unanswered request is in `orphans.tsv`.
- The previous single-column page is kept as `index.original.html`, in the repo and in each report folder.

## 0.4.0

What is on port 11210, and a copy icon that pastes the Wireshark filter.

- The count keeps packets whose source or destination is TCP port 11210. A capture filter of `dst port 11210` still drops the replies, so that file has requests and no round trips.
- **Packets on port 11210** is a vertical bar. Each Couchbase command is its own bar, split into a request (blue) and a response (green). TCP packets are greys. Lost segments, retransmissions, and ack-lost segments are reds. TCP data segment and TCP ACK start hidden. The legend turns one bar back on at a time, including when the axis is log.
- Under the ten-row tables, two tabs list requests with no response and responses with no request. The tab label is the full count. The rows are a sample of ten. **Inside**, **End of file**, and **Start of file** say whether the missing half is in the middle of the capture or at the edge.
- A copy icon beside a document id copies `couchbase && couchbase.key.logical_key == "…"`. Beside an opaque it copies `couchbase && couchbase.opaque == 0x…`. A toast in the top right confirms the copy.
- The note, `charts.json`, and the page title name the Couchbase server. The title is `Couchbase capture: hostname (ip)` when reverse DNS returns a name, and the IP when it does not.
- The upper right of the page links to the GitHub repo and shows the version from `pyproject.toml`.
- [CB_WIRESHARK.md](CB_WIRESHARK.md) now says server duration is on the response, durability is on the request, and a reply with no request later in the file means the capture lost the request. Disk durability (`0x02` and `0x03`) is a common cause of a slow write.

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
