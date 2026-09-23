# Couchbase Wireshark filters

Paste these into the Wireshark display-filter bar. Combine them with `&&`. Couchbase KV is TCP port **11210**.

The chart page’s slow-call table gives the `tcp.stream` and `couchbase.opaque` for each slow row. Those two fields together are one call.

## One document

```text
couchbase.key.logical_key == "invoice:12345"
```

Collections put the document id in `couchbase.key.logical_key`. `couchbase.key` is often empty on those packets.

```text
couchbase.key.logical_key contains "invoice:"
```

## One call

Opaque is the client’s semi-transaction number. The request and its reply carry the same value. The same opaque on another TCP stream is a different call.

```text
tcp.stream == 0 && couchbase.opaque == 0x00ab12cd
```

Use the stream and opaque from the slow-call table. Wireshark accepts the hex form printed there.

## Trace a request that never got a response

A lost request is a client packet with no later reply on the same TCP stream and the same opaque. The reply is missing from the file. That is not the same as an error status: a response with `couchbase.status == 0x0001` (key not found) did come back.

The analyzer writes these rows to `orphans.tsv` in the report folder. Use that list, then trace the interesting ones in Wireshark. Hunting every request by eye in a large capture is how the ones at the end of the file get counted by mistake.

1. Show only client requests.

```text
tcp.port == 11210 && (couchbase.magic == 0x80 || couchbase.magic == 0x08)
```

2. Pick a row. In the packet details, write down four fields:

- **tcp.stream**, the connection
- **couchbase.opaque**, the semi-transaction number
- **couchbase.key.logical_key**, the document
- **frame.time_relative**, seconds from the start of the file

3. Replace the filter with that stream and opaque. Use the hex opaque from the packet or from `orphans.tsv`.

```text
tcp.stream == 0 && couchbase.opaque == 0x00ab12cd
```

4. Read the packet list for that filter.

- Two packets, a request (`0x80` or `0x08`) and a response (`0x81` or `0x18`) with the same opaque, means the call completed. Check `couchbase.status` on the response if you care why.
- One packet, the request only, means the reply is not in this capture.

5. If the reply is missing, check how close the request is to the end of the file before you call it lost.

Look at **Statistics → Capture File Properties** for the file duration, or sort the Time column and look at the last packet. Subtract `frame.time_relative` of the request from that duration.

The false-positive window is the longest round trip that did complete in this file. A healthy KV capture is often a few tens of milliseconds, sometimes under 200 ms. A request inside that window of the end was still in flight when the capture stopped. The reply can be absent because the file ended, not because Couchbase stayed silent. Treat those as false positives.

A request with seconds of capture still after it had time for a reply to arrive. Those are the ones to trace.

The mirror is at the start of the file. A response with no request is often a call that began before the recording started. Do not treat that as a client that never sent the request.

6. For a request that sits well inside the file, look for a hole on that stream around the same time.

```text
tcp.stream == 0 && tcp.analysis.lost_segment
```

Loss toward the client is a hole in packets the server sent. The missing bytes are often the reply, which is why the request is in the file and the response is not. Loss toward the server is a hole in packets the client sent.

7. Clear the filter back to the single call and read `tcp.time_delta` on the request. A large gap there means the previous packet on that connection was already far behind. The column steps in the next section are how to see that gap on every row.

Repeat from step 3 for the next opaque in `orphans.tsv`. Skip the rows whose time is inside the end window.

## Gaps longer than 50 ms

```text
couchbase && tcp.time_delta > 0.05
```

`tcp.time_delta` is the time since the previous frame **in this TCP stream**, in seconds. `0.05` is 50 milliseconds. `0.1` is 100 ms. The filter keeps Couchbase packets that showed up more than 50 ms after the previous packet on that same connection.

When the previous packet was the request and this packet is the response, that gap is the round trip of the call: client send, server work, reply back onto the wire. When the connection was simply idle, a new request can also show a large delta. Read the opcode and the magic before calling it a slow server. A Get or Set response (`0x81` or `0x18`) with a large delta is the interesting row. A request (`0x80` or `0x08`) with a large delta usually means the client waited before sending.

`frame.time_delta` is a different field. It is the gap since the previous captured frame of any connection, so on a busy span it stays small even when one Couchbase connection stalled. Use `tcp.time_delta`.

### Show it as a column

The filter hides the quiet packets. A column lets you read the gap on every row while you scroll.

1. Select any Couchbase packet.
2. In the packet details, expand **Transmission Control Protocol**.
3. Open **Timestamps**, or find the line **Time since previous frame in this TCP stream**.
4. Right-click that line and choose **Apply as Column**.

The packet list gains a column. Drag the header to sit next to Time or Info. Double-click the header to rename it `TCP delta`. Click the header to sort, and the slow rows rise to the top.

The same column can be added from preferences:

1. **Wireshark → Preferences → Appearance → Columns** (on Linux and Windows: **Edit → Preferences → Appearance → Columns**).
2. Click **+**.
3. Title: `TCP delta`. Type: **Custom**. Fields: `tcp.time_delta`.
4. Click **OK**.

Then apply `couchbase && tcp.time_delta > 0.05`. The column still shows the gap, and the list is only the Couchbase packets that waited longer than 50 ms.

## Requests and responses

| What | Filter |
|---|---|
| Client request, classic | `couchbase.magic == 0x80` |
| Client response, classic | `couchbase.magic == 0x81` |
| Client request, flex | `couchbase.magic == 0x08` |
| Client response, flex | `couchbase.magic == 0x18` |
| Either client request | `couchbase.magic == 0x80 \|\| couchbase.magic == 0x08` |
| Either client response | `couchbase.magic == 0x81 \|\| couchbase.magic == 0x18` |

`couchbase.magic == 0x82` is the server asking the client for something, such as a cluster-map notification. It is not the reply to a client get or set.

## Opcode

| Command | Filter |
|---|---|
| Get | `couchbase.opcode == 0x00` |
| Set | `couchbase.opcode == 0x01` |
| Add | `couchbase.opcode == 0x02` |
| Replace | `couchbase.opcode == 0x03` |
| Touch | `couchbase.opcode == 0x1c` |
| Get and Touch | `couchbase.opcode == 0x1d` |
| Get Locked | `couchbase.opcode == 0x94` |
| Get Cluster Config | `couchbase.opcode == 0xb5` |

The opcode table on the chart page names every command that appears in that capture.

## Status

```text
couchbase.status != 0x0000
```

| Status | Meaning | Filter |
|---|---|---|
| `0x0000` | Success | `couchbase.status == 0x0000` |
| `0x0001` | Key not found | `couchbase.status == 0x0001` |
| `0x0002` | Key exists | `couchbase.status == 0x0002` |
| `0x0009` | Locked | `couchbase.status == 0x0009` |

## Body size

`couchbase.total_bodylength` is extras + key + value, in bytes.

```text
couchbase.total_bodylength >= 1048576
```

1,048,576 bytes is 1 MB. A request that large is data into Couchbase. A response that large is data out.

```text
tcp.port == 11210 && couchbase.total_bodylength >= 1048576 && (couchbase.magic == 0x81 || couchbase.magic == 0x18)
```

## TCP loss on the KV port

```text
tcp.port == 11210 && tcp.analysis.lost_segment
tcp.port == 11210 && tcp.analysis.retransmission
tcp.port == 11210 && tcp.analysis.ack_lost_segment
```

Loss toward the client is a hole in packets the server sent, often the reply. Loss toward the server is a hole in packets the client sent, often the request. Limit the loss filter to one stream when a chart stake names that connection:

```text
tcp.stream == 0 && tcp.analysis.lost_segment
```

## Server time on a flex frame

When the packet carries a server duration extra:

```text
couchbase.flex_frame.frame.duration > 0.05
```

Wireshark shows that field in seconds. If the values on your build look like large integers, they are microseconds, and `50000` is about 50 ms.

## Examples

A get of one invoice, request and reply:

```text
couchbase.key.logical_key == "invoice:12345" && couchbase.opcode == 0x00
```

That document, only the calls that failed:

```text
couchbase.key.logical_key == "invoice:12345" && couchbase.status != 0x0000
```

Slow-looking sets with a large body:

```text
couchbase.opcode == 0x01 && couchbase.total_bodylength >= 1048576 && (couchbase.magic == 0x80 || couchbase.magic == 0x08)
```
