# Design

This is how the analyzer is put together. [README.md](../README.md) is the way to run it. [CB_WIRESHARK.md](../CB_WIRESHARK.md) is the protocol and the display filters. [CB_TCPDUMP.md](../CB_TCPDUMP.md) is how to record a capture. [RELEASE_NOTES.md](../RELEASE_NOTES.md) is what each version changed.

The product is a folder of static files. Python counts the capture. A model may write the prose. The browser draws the counts. The page does not pair packets, and the model does not invent a number.

## Repository

| Path | Role |
| --- | --- |
| `analyze_capture.py` | The whole analysis: read, pair, count, call the model, write the report. |
| `web/index.html` | The chart page. Markup, CSS, and the drawing script live in this one file. |
| `web/summary.html` | The note page. It fetches `summary.md` and formats a small slice of Markdown. |
| `web/index.original.html` | The earlier single-column page. It is copied into each report and left as a snapshot. |
| `web/vendor/echarts.min.js` | ECharts 5.6.0, vendored. The page has no build step and no CDN. |
| `config.json` | Model settings: provider, URL, model name, timeout. API keys stay in the environment. |
| `tests/` | Pytest. Small fixtures. No pcap, no tshark, no Ollama. |
| `pyproject.toml` | The version string. `project_version()` reads it when a report is written. |

`analyze_capture.py` stays one module on purpose. The functions are the sections. A new chart is a function that returns a piece of `charts.json`, plus a `draw*` function in `web/index.html`. A new core concept (a second matcher, a second page runtime) would be the thing that justifies another file.

## From a capture to a folder

`main` parses arguments, applies `config.json` through `apply_config`, and calls `run_job`.

1. `resolve_job` picks the input. A pcap next to a field export wins, unless `--from-tsv` is set. The default output directory is `<capture name>-report` beside the input. `-o` overrides it.
2. `load_pcap` asks tshark for every TCP packet on port 11210, both directions. A directory of TSV or CSV exports goes through `load_tsv_pair` instead, and then there are no TCP-loss events.
3. `pair_messages` matches requests to responses.
4. `build_facts` is the note's shape: counts, the in-flight window, the full unanswered list, streams, opcodes, statuses.
5. `build_charts` walks the packets already in memory once and fills every bucket width from that walk. It does not open the pcap again.
6. `next_questions` fills `facts["next_steps"]` and the same list on `charts`.
7. `render_summary` writes the counted note. `--no-ai` saves that text as `summary.md`. A model run saves it as `summary.computed.md` and writes the model's markdown to `summary.md`.
8. `choose_interest_stakes` picks seconds for the vertical marks. The fallback list is counted. The model may choose among those candidate seconds.
9. `write_charts` writes compact `charts.json` and copies the two live pages, the original page, and `web/vendor/`.

Stage timing and progress go to stderr as one OpenTelemetry-style JSON record per line (severity, body, trace id, span id, attributes). A span record adds the duration. `--log-level` defaults to INFO.

`--dry-run` stops after the facts and prints the plan. It does not create the directory and it does not call the model.

`write_charts` stamps `#app-version` from `pyproject.toml` via `stamp_version`. Editing `web/index.html` changes the next report. A report that is already on disk keeps the HTML it was given. `index.original.html` is copied as-is and is not stamped.

The report folder is:

| File | What it holds |
| --- | --- |
| `charts.json` | Everything the chart page draws. Compact JSON. The filename stays `charts.json`. |
| `facts.json` | The note's counts, including every unanswered request. Pretty-printed. |
| `index.html`, `summary.html` | Copies of the templates, version stamped. |
| `index.original.html`, `vendor/` | The previous page and ECharts. |
| `summary.md` | The note the report page opens. Model text when a model ran, otherwise the counted note. |
| `summary.computed.md` | The counted note, present when a model also ran. |
| `orphans.tsv` | Every unanswered request. The page shows a sample. |
| `reqs.pdus.tsv`, `resps.tsv` | The messages that were paired. |

Open the folder with a local HTTP server. The page fetches `charts.json`. A `file://` URL cannot.

## Python

### What is counted

`KV_PORT` is `"11210"`. The tshark display filter is `tcp.port == 11210`, so a reply leaving the server stays in the file. `KV_PORTS` is `11210` and `11207`. Port 11207 is a cluster endpoint for role checks. The field pass does not decrypt TLS, so 11207 traffic is not charted as KV messages.

A packet with a Couchbase header becomes a message. Magic `0x80` and `0x08` are client requests. Magic `0x81` and `0x18` are client responses. Magic `0x82` is a server request and is not stored as a client reply. An error status still counts as a response.

The message dict carries frame, time, stream, addresses, ports, magic, opcode, opaque, key, status, and body length, plus the optional measures from `_measure`: vBucket, server microseconds, durability level, snapshot flags and sequence numbers, buffer-ack credit, `ttp`, `ttr`, and the replica-read flag. Blank stays missing. Zero is a real reading.

Collection document ids come from `couchbase.key.logical_key`. A statistics key such as `vbucket-seqno` often arrives in `couchbase.key` when the logical key is empty. The loader uses the logical key first.

tshark `-T fields` is one pass. Repeated Couchbase cells are joined with the unit separator `FIELD_AGG` (`\x1f`), because document keys contain commas. A frame whose Couchbase columns do not line up is collected and re-read once, in EK JSON, by `_iter_ek_messages`.

TCP expert flags on the same pass become `loss_events`: lost segment, retransmission, and ack-lost segment. `is_capture_duplicate` treats a retransmission whose RTO is under `_DUPLICATE_RTO_SECONDS` (1 ms), or a retransmission with no RTO, as a second copy of the same segment. That event is not a retry. `packet_kind` names the packet bar. A Couchbase header wins over a TCP flag, so a command that was also retransmitted is still that command.

Opcode names are the `OPCODES` table copied from Wireshark's `client_opcode_vals` in `packet-couchbase.c`. The project does not ship a decoder. `OPCODE_DESCRIPTIONS` is the sentence the chart tooltip shows.

### Pairing

`pair_messages` groups by `(tcp.stream, opaque)` and walks each group in time order. Opaque alone is not a call. The same opaque on another stream is a different call. A later request that reuses the opaque on the same stream is a new call.

`expects_reply` decides whether a request enters the matcher. One-way DCP opcodes live in `_NO_REPLY_OPCODES`: stream end, snapshot marker, mutation, deletion, expiration, buffer acknowledgement, and the later producer-data opcodes through `0x67`. Those packets are `no_reply`. A snapshot marker (`0x56`) expects a reply only when the ack flag is set. Noop (`0x5c`) expects a reply. The opcode table calls `expects_reply` without that per-message flag, so a snapshot row with zero unanswered stays "not expected" even when one marker in the file asked for an ack.

Inside a group, `_pair_one_to_one` pairs in order. A response earlier than the request is `resp_only`. A request with no later response is unanswered.

Statistics (`0x10`) is the exception. `is_multi_response` sends that group to `_pair_multi_response`. Every response packet until the next request on the same stream and opaque is one call. The body is the sum. The extra packets are `multi_response_continuations`, not extra calls. `vbucket-seqno` is this pattern and is also classified as cluster.

### SDK and cluster

`traffic_role` returns `cluster` or `sdk`.

- Both ports are in `KV_PORTS` (11210 or 11207): cluster.
- The opcode is in `_CLUSTER_OPCODES`: DCP `0x50`–`0x67`, Get All VBucket Seqnos `0x48`, and the meta opcodes used by replication.
- Statistics whose key starts with `vbucket-seqno`: cluster.
- Otherwise: sdk. An application port talking to 11210 is the usual case.

`cluster_endpoints` remembers the ephemeral ports that carried a cluster command. `flow_role` uses that set so a TCP event with no opcode, such as a retransmission of an empty segment, can still be blamed on the cluster connection or the SDK connection.

Blue is the application. Rust is the cluster. The page uses those two colors everywhere both sides appear. A blended median is stored for the overall tile and is not the line on the time charts.

### Two JSON shapes

`build_facts` answers "what should the note say?" It keeps the full unanswered list, the opening and closing windows, stream and key-family rollups, replica-read counts, and the loss summary. `render_summary`, `facts_brief`, and `next_questions` read it.

`build_charts` answers "what should the page draw?" It keeps bucket series, histograms, client rows, opcode rows, document tables, sampled gap rows, diagnosis series, and the sankey views. The page reads only this file.

Both are built from the same `paired` dict. A number that appears in both has one definition in Python. The page formats and filters. It does not recompute a percentile.

`build_charts` fills four bucket widths, `0.5`, `1`, `5`, and `10`, under `buckets`, in one walk. Each message is classified once. Each row is one time slot and already holds SDK and cluster request counts, missing-reply counts, medians, p99, min, max, opcode counts, body bytes, loss by direction, retransmissions, snapshot counts, buffer-ack credit, and Observe `ttp` / `ttr`. The page picks a width with the bucket menu. The default is 1 second, or 10 seconds when `capture_seconds` is over 180.

The in-flight window is the longest matched round trip, from `_in_flight_window`. With no matched call it is 1 second. A response in that opening window, and a request in that closing window, are the capture cutting a live call.

### What the page is allowed to see

Gap tables are sampled in `_ten_gaps`. `_GAP_LIMIT` is 10. The tab label is the full count (`missing_response_sdk_total` and its three siblings). The sample prefers rows that had time for the other half:

- Requests missing a response: `where != "end"` first. A request near the start with a large `seconds_left` stays in this set.
- Responses missing a request: `where != "start"` first.
- `_EDGE_SAMPLE` is 2. At most two opening-window replies, or two closing-window requests, are added when the list has room.

`at_edge` is still `where != "inside"`. The sampler itself uses `start` and `end` so an opening request that had the rest of the capture left is not treated as an edge example. Every unanswered request remains in `orphans.tsv` and in `facts.json`.

`_annotate_gap_errors` marks a sampled row `possible` when a lost segment or an ack-lost segment is within `_ERROR_WINDOW_SECONDS` (0.5 s). Capture duplicates are already excluded from the marks. A hole on the same `tcp.stream` produces a filter that names that stream. A hole only on another connection of the same machine produces a filter on `ip.addr` or `ipv6.addr` for the requester. The call half is `_call_filter`: stream, plus opaque or logical key. The two halves are OR'd. The short document-id copy on the page is a different string and is built in the browser.

Document tables are four lists of ten, plus the combined lists the note still uses:

- `top_requested_sdk`, `top_requested_cluster`
- `top_slowest_sdk`, `top_slowest_cluster`
- `top_requested`, `top_slowest`

`per_second` is the request count divided by the capture length. `avg_body_bytes` is the mean of the larger of each call's request body and reply body. An unanswered call contributes the request body. The slowest rows are matched calls that have a document id, one row per call.

Diagnosis series are also precomputed:

- `scatter` is matched calls of at least 50 ms, capped. `scatter_server` is the same calls against `couchbase.flex_frame.frame.duration` when that field is present. The duration is microseconds.
- `packet_errors` is one mark per frame for a lost segment, an ack-lost segment, or a retry whose RTO is at least 1 ms. The mark carries a role so the page can color application and cluster separately.
- `heatmap` is missing replies by time, for the client view and the command view.
- `boxplot` is one row per `(role, opcode)`, the sixteen slowest p99 tails on each side.
- `sankey.views` holds `all`, `application`, `cluster`, `exclude_not_expected`, and `unmatched`. Each view refolds to its own eight busiest commands. `unmatched` is "Missing reply" only. "Not expected" is one-way traffic and is a different outcome. Not found, key exists, and error status are other outcomes.
- `durability`, `persist`, `vbuckets`, and `status_counts` feed the smaller diagnosis cards.

`interest_candidates` proposes stake seconds from slow calls, body peaks, and loss. A "Most lost responses" bucket whose start falls inside the closing in-flight window is skipped. The model prompt in `INTEREST_SYSTEM` and `facts_brief` says the same thing in words: opening responses with no request, and closing requests with no response, are expected on both sides and are not points of interest.

### The model

`facts_brief` is the only text the model sees about the capture. It is a bounded list: the busiest streams, a sample of other keys, the side-by-side document lists, the edge counts, and the rules. The system prompt names the markdown headings and forbids invented counts.

`call_model` posts to Ollama or to an OpenAI-compatible `/chat/completions` URL. `strip_think` drops a reasoning fence. `splice_table` puts the counted unanswered table back into the model's note at `{{UNANSWERED_TABLE}}`. `append_trace_filters` adds the Wireshark filters section from the gap rows' `error_filter` fields. After the call, the script checks that the unanswered total and most of the counted keys survived. The model text stays in `summary.md` either way. `summary.computed.md` is the counted note.

`--no-ai` skips the call. It still writes stakes from the counted fallback and still writes `summary.md` from `render_summary`.

Replica reads are a paragraph, not a chart. `replica_reads` counts Get Replica (`0x83`) and subdocument requests with the replica-read flag. The brief tells the model to name only servers present in that count.

## The chart page

`web/index.html` is one document. The `<style>` block is the theme. The `<body>` is the sections. One `<script>` at the bottom fetches `charts.json` and draws. There is no module bundler, no framework, and no second chart runtime. ECharts is loaded from `vendor/echarts.min.js` next to the page.

`summary.html` repeats the header, the colors, and the repo corner so the note feels like the same report. Its script is a small Markdown renderer: headings, lists, tables, fenced code, bold, code spans, and `http` links. It does not load a Markdown library. A `code` span that looks like a display filter gets a copy button. `?note=summary.computed.md` selects the counted note. The chart page shows that link after a `HEAD` request succeeds.

### Boot

`fetch("charts.json")` stores the payload in `data` and calls `boot`. `boot` runs `echarts.init` on each plot div and keeps the instances in the `charts` object, keyed by element id. The plot div and a heading must not share an id. The NIC card's heading is `nic` and the plot is `nic-gauge`, because initializing ECharts on the heading produced a zero-height canvas.

The first paint is `drawTiles`, `drawFixed`, `drawTime`, `drawHeat`, and `drawScatter`. Menus call the one `draw*` they own. The linear/log control calls `drawFixed`, `drawTime`, `drawBoxes`, and `drawScatter`.

`yType` and `yValue` implement that control. Log mode turns a non-positive value into `null` so ECharts leaves a gap. Pies and the NIC gauge ignore the control. The scatter's horizontal axis stays linear in time mode and follows the control only in server-time mode.

### Sections and the functions that fill them

| Section | Element | Drawn by |
| --- | --- | --- |
| Timings | `#spread`, `#rtt`, `#tail`, `#range`, `#tiles` | `drawFixed`, `drawTime`, `drawTiles` |
| Operations | `#mix`, `#opcodes`, `#opcodes-seen` | `drawTime`, the opcode table in `drawFixed` |
| Diagnosis | `#scatter`, `#heat`, `#boxes`, `#paths`, `#statuses`, `#durable`, `#persist`, `#vbars`, `#snaps`, `#buffer` | `drawScatter`, `drawHeat`, `drawBoxes`, `drawPaths`, `drawStatuses`, `drawDurability`, `drawPersist`, `drawVbuckets`, `drawSnapshots`, `drawBuffer` |
| Packets | `#packets`, `#issues`, `#gaps` | packet bars, `drawTime`, `drawGaps` |
| Clients | `#flow`, `#cluster-ops`, `#cluster-conns`, fleet and the client picker | `drawTime`, `drawCluster`, `drawClientFleet` |
| Documents | `#nic-gauge`, `#body`, `#top-asked`, `#top-slow` | `drawGauge`, `drawTime`, the two tabbed tables |
| Marks | `#interest` | the points-of-interest table |
| Report | `#next-list` | `data.next_steps` |

`drawTime` reads `data.buckets[bucket]` and sets the category charts together: round trip, tail, candles, opcode mix, lost responses, body length, the cluster over-time chart (`#flow`), snapshots, buffer acknowledgement, and persist. `pin` appends the stake series after the real series so a redraw keeps the marks.

The cluster over-time chart is a dual axis. Request bars stay on the left. SDK missing, cluster missing, and retransmissions are lines on the right, with circle symbols, so a count of one stays visible beside thousands of requests. Log scale would turn a zero into a gap, which is why the symbols are on.

`#packets` is a vertical bar chart, one series per `packet_kind`, drawn with `barGap: "-100%"`. "TCP data segment", "TCP ACK", and "Capture duplicate" start hidden (`hiddenPacketBars`). Requests are blues. Responses are greens. Loss and retries are reds.

### Shared time

Category time charts share one ECharts group:

```js
echarts.connect([charts.mix, charts.rtt, charts.tail, charts.range,
  charts.issues, charts.body, charts.flow, charts.snaps,
  charts.buffer, charts.persist, charts.heat]);
```

`timeChartIds` is that list without `heat`:

```js
["mix", "rtt", "tail", "range", "issues", "body", "flow", "snaps", "buffer", "persist"]
```

`axisZoom` reuses the window recorded from `#rtt`'s `datazoom` event and writes it back onto every chart `drawTime` updates, so a bucket change keeps the zoom. An event without a numeric start and end leaves that recorded window alone. Reset zoom walks `timeChartIds` and `charts.heat`, then calls `syncScatterToCategory`.

`#scatter` is not in the connect group. Its horizontal axis is a value axis (seconds, or server microseconds), and a category slider cannot drive it. `charts.rtt` `datazoom` records the window, then calls `syncScatterToCategory`. The scatter's own `datazoom` calls `syncCategoryFromScatter`. `scatterWindow` converts the category percentage into bucket indexes with a half-step margin, `(i0 - 0.5) * step` through `(i1 + 0.5) * step`, so the value axis lines up with the bucket the category chart is showing. `applyingZoom` stops the two listeners from bouncing. Server-time mode leaves this link alone because that horizontal axis is no longer capture time.

`#heat` is in the connect group, so its slider follows the category charts. It also receives stake lines from `applyStakes`.

These charts do not take stakes or the shared slider: the opcode pie (`#cluster-ops`), the connection bars (`#cluster-conns`), the packet bars, the box plot, the sankey, the gauge, and the status, durability, and vBucket cards.

### Stakes

A stake is a second, stored in the `stakes` array. `interest_stakes` from `charts.json` are loaded with `takeStake` before the first draw. Set Stake, a double-click, and Remove stake all go through `addStake` or a full clear. Double-click and Set Stake must not change the zoom.

`STAKE_SERIES` is the series name `"__stake"`. `paintStake` sets that series' `markLine` from the index saved when the chart was last drawn, and does not read the chart option back. On category charts the mark is a category label. On the scatter the mark is a value-axis line from `stakeMarkValue`. `cross` and `scopedLegend` skip `__stake`, so the line is visible and absent from the legend and the tooltip. Stake colors start at `#1a8cff` and follow `stakeColors` by creation order. A stake that lands on a point of interest is labeled `Stake N(pi:N)`.

Slow calls hide stakes when the menu is server time. `applyStakes` clears the scatter mark line in that mode.

A new time chart joins this behavior only when its id is in `timeChartIds`, it is created in `boot`, it is passed to `echarts.connect`, and `drawTime` (or its own draw) calls `pin`. Missing any one of those leaves the chart out of reset, double-click, or the stake paint.

### Tables, tabs, and copy

Tables are HTML strings built in the script, not ECharts. `lostCount` wraps a lost-response count in `<span class="lost-many">` when the count is greater than 1. Points of Interest call `lostCount(bucket.unanswered, 0)`, so any count above zero is red and bold there. The "not expected" label is plain text with a link to `#not-expected`.

`#asked-tabs` and `#slow-tabs` switch `askedSide` and `slowSide` between `sdk` and `cluster`. The rows come from `top_requested_*` and `top_slowest_*`. An older `charts.json` without those keys falls back to the combined list. The slowest table has no Role column. The gap tables still show Role.

`#gap-tabs` has four keys: SDK and cluster, requests missing a response, and responses missing a request. The default is `sdk-request`. Requests show Seconds and Left. Responses show Seconds and Since Start. Both of those response columns are `row.seconds`, seconds from the first packet.

Copy buttons use the class `copy-filter` and `data-filter`. One document click listener copies `data-filter`. The visible control is the two-rectangle icon. The accessible name is "Copy Wireshark filter". Opaque on a slow or missing row copies stream plus `couchbase.opaque`. A document id copies `couchbase.key.logical_key == "…"`. A `couchbase.` field already limits the list, so those copies omit a leading `couchbase &&`. A filter that is only TCP fields keeps `couchbase &&` when the intent is Couchbase packets in that window, as Set Stake's half-second filter does. Packet bars copy opcode plus request or response magic, or the TCP analysis flag. Set Stake marks time and does not itself copy a filter. The Errors cell copies the `error_filter` Python stored on the row.

Sankey and box menus do not recompute. `#flow-mode` selects a key of `data.sankey.views`. `#box-mode` filters `data.boxplot` by role and then grows the chart height with the row count. On the unmatched sankey view, a band thinner than 12% of the largest link is drawn wider. The label and the tooltip keep the real count.

`sdkClients` drops cluster addresses before the fleet pie, the rate bars, and Choose a client. The menu lists application addresses, missing replies first, capped at 80, with a filter box. Clicking a fleet row still selects that client.

### Glossary and chrome

A dotted `.term` looks up `glossaryJump` and scrolls to a `<dt>` in the glossary. The long explanation lives there. The card note stays one or two sentences and links to that entry.

The header is one bar. Section pills are on the left (`#sections`). Plain file links are on the right. The upper right is the repo name and `#app-version`. `markSection` highlights the pill for the group currently under the header.

Expand wraps each `.chart` in a button that moves the node into `#lightbox` and calls `resize`. Close puts the node back. The lightbox is a view of the same ECharts instance, so zoom and stakes survive the trip.

## Colors

| Use | Color |
| --- | --- |
| Application / SDK series | `#1a5276`, fill `#d6e2ea` |
| Cluster series | `#c45c26`, fill `#f6d7c4` |
| Application packet-error diamond | `#1a8cff` |
| Cluster packet-error diamond | `#ff2d2d` |
| First stake | `#1a8cff` |
| Lost-response emphasis | `#c0392b`, weight 700, class `lost-many` |
| Paper / card | `#f6f3ee` / `#fff` |

Packet-error diamonds sit on a low hidden value so they share the capture-time axis with the slow calls. Their height is not a round trip. The tooltip says which flag and which direction.

## Tests

`tests/` imports `analyze_capture` and feeds it small message lists. `python3 analyze_capture.py --self-test` and `python3 -m pytest -q` run the same suite. See [tests/README.md](../tests/README.md).

A test should state how two values relate: a paired call's `time_ms`, a side list that contains only that side, a gap sample that keeps an interior row and caps the edge rows, a filter string that names the stream when the hole is on that stream. A test that freezes a version number, an opcode-table length, or a model list will break on the next ordinary edit.

Fixtures use generic keys and addresses. Capture names, customer hostnames, and real document ids do not belong in the suite.

## Where a change goes

| Change | Edit |
| --- | --- |
| A new counted field | The tshark column list if the packet must be read, then the message dict, then `build_charts` or `build_facts`. Add the draw or the table cell in `web/index.html`. |
| A new time chart | A plot div, an id in `boot`, `echarts.connect`, and `timeChartIds`, and `pin` inside its draw. |
| A new menu on data Python already computed | A `<select>` and a branch in the existing `draw*` function. |
| A new Wireshark copy | Python when the filter depends on pairing or TCP holes. The page when it is a field already on the row. Keep the string in [CB_WIRESHARK.md](../CB_WIRESHARK.md) in step with the code. |
| A sentence the model must respect | `facts_brief` and the system prompt together. The page's next-steps list is `next_questions`, which is counted and does not wait for the model. |
| A version | `pyproject.toml`, both image tags in `docker-compose.yml`, the `#app-version` spans in `web/index.html` and `web/summary.html`, and a section at the top of [RELEASE_NOTES.md](../RELEASE_NOTES.md). Leave `web/index.original.html` on its historical version. |
