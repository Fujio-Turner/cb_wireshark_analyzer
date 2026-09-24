# Couchbase Wireshark filters

Paste these into the Wireshark display-filter bar. Combine them with `&&`. The analyzer keeps only Couchbase KV: packets whose source or destination port is **11210**.

```text
tcp.port == 11210
```

`tcp.port` is either side. A request has destination 11210. The reply has source 11210. A capture filter of `dst port 11210` keeps the requests and drops the replies, so the report can show no round trips. Use `port 11210` when recording if you want both directions.

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

## Server time is on the response

`couchbase.flex_frame.frame.duration` is **Server Recv->Send duration**. It is a response flex frame. Select the response row (magic `0x18` or `0x81`, source port 11210). Under **Flexible Frame** the frame id says **Server Recv->Send duration**. Wireshark 4.6.8 prints that value in microseconds. A value of about 56 μs means the server spent a tiny fraction of a millisecond between receiving the request and sending the reply.

```text
couchbase.flex_frame.frame.duration > 1000
```

That keeps responses where the server itself took more than about 1 ms. The packet-list **Delta time** is a different number: it is the gap from the previous packet on the connection, which includes the network. A 33 ms delta next to a 56 μs server duration means the time was spent outside the server’s receive-to-send window.

## Durability is on the request

The durability level is not on the response. The response flex frames are the server duration, the vBucket UUID, and the mutation sequence number. **Durability Requirement** is a flex frame on the request, the packet whose source is the client.

The [Couchbase display-filter reference](https://www.wireshark.org/docs/dfref/c/couchbase.html) lists:

| Field | What it is | Type | Wireshark versions |
|---|---|---|---|
| `couchbase.flex_frame.frame.durability_req` | Durability Requirement | Unsigned 8-bit | 3.0.0 to 4.6.8 |
| `couchbase.flex_frame.frame.durability_timeout` | Durability Timeout | Unsigned 16-bit | 3.0.0 to 3.0.14 |

On a pair such as opaque `0x002aa15f`, frame 16 is the Set request (`0x80`, client to port 11210) and frame 17 is the Set response with flexible framing extras (`0x18`). Open frame 16 to see if the client asked for durability. Frame 17 will not have **Durability Requirement**. If the request tree has no **Durability Requirement** line, this call did not ask the server to wait for disk. Extras that only show **Flags** and **Expiration** are a normal Set.

Find the requests that did ask for it:

```text
(couchbase.magic == 0x80 || couchbase.magic == 0x08) && couchbase.flex_frame.frame.durability_req
```

| Value | Name | What the server waits for |
|---|---|---|
| `0x01` | Majority | The write is in memory on a majority of nodes. No disk wait. |
| `0x02` | Majority and persist on master | Majority in memory, and the active node has written it to disk. |
| `0x03` | Persist to majority | The write is on disk on a majority of nodes. |

`0x02` and `0x03` are the slow ones. The response cannot leave until the disk has the write. A busy disk turns a call that would have finished in a few milliseconds into tens or hundreds of milliseconds, even when the document is small. That shows up as a high p99 on Set, Add, or Replace, and as a large delta on the response.

```text
(couchbase.magic == 0x80 || couchbase.magic == 0x08) && (couchbase.flex_frame.frame.durability_req == 0x02 || couchbase.flex_frame.frame.durability_req == 0x03)
```

To see the level on every row, select a request that has the field, right-click **Durability Requirement**, and choose **Apply as Column**. The response rows stay blank in that column, which is how you can tell you are looking at the right side of the call.

`couchbase.flex_frame.frame.durability_timeout` is the client’s limit on that wait, in milliseconds. Wireshark only had it from 3.0.0 through 3.0.14. Wireshark 4.6.8 does not, so the filter will not resolve on a current install. On those old builds it is also on the request. A timeout of a few seconds means the client was willing to sit on the disk wait for that long.

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

## A reply with no request, later in the file

A reply at the opening of the capture, with no request in front of it, is the recording starting in the middle of a call. The request was sent before the first packet.

A reply later in the file, still with no request, is a different case. Couchbase did answer. The request was on the wire. The capture kept the reply and lost the request packet.

The request and the reply travel in opposite directions. A hole in the client-to-server direction removes the request from the file. The reply comes back server-to-client and can still be recorded. In Wireshark that reply is a response magic (`0x81` or `0x18`) whose `tcp.stream` and `couchbase.opaque` never appear on a request. The chart page lists those rows under **Responses missing a request**, and marks **Start of file** only for the ones inside the opening in-flight window. **Inside** means the reply is later than that window.

The same opaque on a request that appears after that reply is a new call. Pairing does not attach the earlier reply to the later request, so the reply stays a reply with no request.

To look at one of them, take the stream and opaque from that table:

```text
tcp.stream == 0 && couchbase.opaque == 0x00ab12cd
```

You should see the response and no request. Then look for the hole on that stream:

```text
tcp.stream == 0 && tcp.analysis.lost_segment
```

A lost segment toward the server, around the same time as the reply, is the missing request. Few retransmissions next to many of those holes means the sender did not put the packet on the wire again, and the recorder did not have another copy to save.
