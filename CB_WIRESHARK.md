# Couchbase Wireshark filters

Paste these into the Wireshark display-filter bar. Combine them with `&&`. The analyzer keeps only Couchbase KV: packets whose source or destination port is **11210**.

```text
tcp.port == 11210
```

`tcp.port` is either side. A request has destination 11210. The reply has source 11210. A capture filter of `dst port 11210` keeps the requests and drops the replies, so the report can show no round trips. Use `port 11210` when recording if you want both directions. The tcpdump command, including the other Couchbase service ports, is in [CB_TCPDUMP.md](CB_TCPDUMP.md).

The analyzer marks two kinds of KV traffic. **Cluster** is port 11210 or 11207 on both ends, a DCP command (`0x50`–`0x67`), Get All VBucket Seqnos (`0x48`), a Statistics key `vbucket-seqno`, or a replication meta command (`0xa0`, `0xa2`, `0xa8`). **SDK** is an application port talking to 11210 for the other commands. A retransmission of the reply stays with that same flow.

The chart page’s slow-call table gives the `tcp.stream` and `couchbase.opaque` for each slow row. For an application call those two fields are one request and its reply. For DCP they are one stream.

## DCP

DCP is Couchbase’s replication protocol, and it is not a normal KV call. A client call is simplex: the application sends one command, the server sends one reply, and the opaque identifies that pair. DCP is full duplex. After the consumer opens a stream, the producer sends snapshots and mutations on its own, and the consumer sends buffer acknowledgements and control commands on the same TCP connection without waiting its turn.

There is no standalone Couchbase repository for the Server or DCP binary-protocol decoder. The decoder is Wireshark’s `epan/dissectors/packet-couchbase.c`. It was added in 2014 and has been maintained there since. Couchbase engineers, including Trond Norbye, Jim Walker, and Dave Rigby, send updates into Wireshark rather than keeping a fork. The [GitHub copy](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-couchbase.c) is a read-only mirror. The file to read is the [GitLab upstream](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-couchbase.c). It covers the binary protocol on port 11210, including the DCP opcodes. The behavior those fields implement is specified in kv_engine: the [DCP overview](https://github.com/couchbase/kv_engine/blob/master/docs/dcp/README.md), the [DCP protocol](https://github.com/couchbase/kv_engine/blob/master/docs/dcp/documentation/protocol.md), and the [binary protocol](https://github.com/couchbase/kv_engine/blob/master/docs/BinaryProtocol.md).

The producer sends mutations with request magic `0x80`. The consumer sends stream requests and buffer acknowledgements the other way.

The opaque on a stream request is copied onto every later command for that stream. A snapshot marker (`0x56`) and the mutations that follow it (`0x57`) share that opaque. The consumer does not send a command reply for a mutation, a deletion, an expiration, or a stream end. A snapshot marker wants a reply only when the ack flag is set:

```text
couchbase.opcode == 0x56 && couchbase.extras.flags.dcp_snapshot_marker_ack
```

Flow control is a buffer acknowledgement (`0x5d`), not a reply per mutation. Opaque `0` on that acknowledgement means the whole connection. A DCP noop (`0x5c`) is different: the producer sends it when the connection is idle, and the consumer must answer or the producer drops the connection. A stream-request response of `couchbase.status == 0x0023` is rollback.

```text
couchbase.opcode == 0x53
couchbase.opcode == 0x55
couchbase.opcode == 0x56
couchbase.opcode == 0x57
couchbase.opcode == 0x58
couchbase.opcode == 0x59
couchbase.opcode == 0x5c
couchbase.opcode == 0x5d
couchbase.opcode == 0x5d && couchbase.opaque == 0x00000000
couchbase.opcode == 0x48
couchbase.opcode == 0x10 && couchbase.key == "vbucket-seqno"
couchbase.opcode == 0xa0
couchbase.opcode == 0xa2
couchbase.opcode == 0xa8
couchbase.status == 0x0023
tcp.srcport == 11210 && tcp.dstport == 11210
```

In that order: stream request, stream end, snapshot marker, mutation, deletion, expiration, noop, buffer acknowledgement, a buffer acknowledgement for the whole connection, Get All VBucket Seqnos, the vbucket-seqno statistics poll, Get Meta, Set with Meta, Delete with Meta, rollback, and KV port to KV port.

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

## Filters the chart page copies

The copy icon writes one of these. Paste it as it is. `couchbase &&` keeps the list on Couchbase packets. The **Errors** copy is wider, because a TCP hole often has no Couchbase header.

| Where | What you get |
|---|---|
| Next to a document id | `couchbase && couchbase.key.logical_key == "invoice:12345"` |
| Next to an opaque on a slow or missing row | `tcp.stream == 121 && couchbase.opaque == 0x00c5a34d` |
| Next to a stream number | `tcp.stream == 121` |
| Next to a client address | `tcp.port == 11210 && ip.addr == 10.227.75.29` |
| Next to an opcode | `couchbase.opcode == 0x00` |
| Next to Set Stake | `tcp.port == 11210 && ip.addr == 10.227.75.29 && frame.time_relative >= 9.171 && frame.time_relative <= 9.671` |
| A bar on Packets on port 11210 | `tcp.port == 11210 && couchbase.opcode == 0x56 && (couchbase.magic == 0x80 \|\| couchbase.magic == 0x08)` |
| **Errors** = possible | the call, then `\|\|`, then the holes to and from that requester |
| Bottom of the report | the same slow-call and missing-call filters, one per line |

A statistics key such as `vbucket-seqno` is on `couchbase.key`, not the logical key. Use that field when the logical key is empty:

```text
couchbase.key == "vbucket-seqno"
```

## TCP errors

These expert flags are not Couchbase status codes. The missing-call table’s **Errors** column says `possible` when a lost segment or a lost ack is within half a second of that row. A dash means no hole that close. The copy icon is the call and those holes in one filter.

`lost_segment` is a hole in the sequence. The packet that carries the flag is the one that revealed the hole. `ack_lost_segment` is an acknowledgement of data the capture never saw. `retransmission` is the same sequence sent again. A copy that arrives within a millisecond has a tiny `tcp.analysis.rto` and is a capture duplicate, not a retry.

Every error on the KV port, then each type alone:

```text
tcp.port == 11210 && (tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment || tcp.analysis.retransmission)
tcp.port == 11210 && tcp.analysis.lost_segment
tcp.port == 11210 && tcp.analysis.ack_lost_segment
tcp.port == 11210 && tcp.analysis.retransmission && tcp.analysis.rto >= 0.001
tcp.port == 11210 && tcp.analysis.retransmission && tcp.analysis.rto < 0.001
```

The last line is the capture duplicate: the same segment recorded twice. Leave it out when you are looking for a hole next to a missing call. The page does.

By direction. Loss toward the client is the server sending, source port 11210. Loss toward the server is the client sending, destination port 11210. The same split works for a lost ack. Swap the flag.

```text
tcp.srcport == 11210 && tcp.analysis.lost_segment
tcp.dstport == 11210 && tcp.analysis.lost_segment
tcp.srcport == 11210 && tcp.analysis.ack_lost_segment
tcp.dstport == 11210 && tcp.analysis.ack_lost_segment
```

By machine. `ip.addr` matches the address on either side, so this is every KV packet to or from that host. `ipv6.addr` is the same test when the address has a colon.

```text
tcp.port == 11210 && ip.addr == 10.227.75.29
tcp.port == 11210 && ip.addr == 10.227.75.29 && (tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment)
```

By connection, then by one stream and one direction:

```text
tcp.stream == 121 && (tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment)
tcp.stream == 121 && tcp.srcport == 11210 && tcp.analysis.lost_segment
tcp.stream == 121 && tcp.dstport == 11210 && tcp.analysis.lost_segment
```

By time. `frame.time_relative` is seconds from the first packet. This is the opening half-second, then the close of a file that ends at 9.535 s, then an arbitrary window around one row:

```text
tcp.port == 11210 && frame.time_relative >= 0 && frame.time_relative <= 0.5 && (tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment)
tcp.port == 11210 && frame.time_relative >= 9.0 && frame.time_relative <= 9.535 && (tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment)
tcp.port == 11210 && ip.addr == 10.227.75.29 && frame.time_relative >= 9.371 && frame.time_relative <= 9.471 && tcp.analysis.lost_segment
```

The call by itself, then the call narrowed to one command:

```text
tcp.stream == 121 && couchbase.opaque == 0x00c5a34d
tcp.stream == 121 && couchbase.key.logical_key == "querycache::GetManifestByDevice::8936b2d780a369d2763196f953330bf0"
tcp.stream == 121 && (couchbase.opaque == 0x00c5a34d || couchbase.key.logical_key == "querycache::GetManifestByDevice::8936b2d780a369d2763196f953330bf0")
tcp.stream == 121 && couchbase.opaque == 0x00c5a34d && couchbase.opcode == 0x00
```

What the **Errors** copy actually writes. The first parenthesis is the document and the opaque, so the request stays in the list. The second is holes to and from that machine in the surrounding time, on any of its connections, not every host in the file. `||` keeps both. Scroll the packet list. The gap between the request row and the flagged row is the distance.

Both flags, which is the usual copy:

```text
(tcp.stream == 121 && (couchbase.opaque == 0x00c5a34d || couchbase.key.logical_key == "querycache::GetManifestByDevice::8936b2d780a369d2763196f953330bf0")) || (tcp.port == 11210 && ip.addr == 10.227.75.29 && frame.time_relative >= 0 && frame.time_relative <= 0.263 && (tcp.analysis.ack_lost_segment || tcp.analysis.lost_segment))
```

Only a lost segment, when that is the only flag near the row:

```text
(tcp.stream == 121 && (couchbase.opaque == 0x00c5a34d || couchbase.key.logical_key == "querycache::GetManifestByDevice::8936b2d780a369d2763196f953330bf0")) || (tcp.port == 11210 && ip.addr == 10.227.75.29 && frame.time_relative >= 9.371 && frame.time_relative <= 9.585 && tcp.analysis.lost_segment)
```

Only a lost ack:

```text
(tcp.stream == 121 && couchbase.opaque == 0x00c5a34d) || (tcp.port == 11210 && ip.addr == 10.227.75.29 && frame.time_relative >= 0 && frame.time_relative <= 0.263 && tcp.analysis.ack_lost_segment)
```

No document id on the row, so the call half is only the opaque. An IPv6 requester uses `ipv6.addr` in that same position.

```text
(tcp.stream == 9 && couchbase.opaque == 0x14006e8d) || (tcp.port == 11210 && ipv6.addr == fe80::1 && frame.time_relative >= 0 && frame.time_relative <= 0.118 && tcp.analysis.ack_lost_segment)
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

The request and the reply travel in opposite directions. A hole in the client-to-server direction removes the request from the file. The reply comes back server-to-client and can still be recorded. In Wireshark that reply is a response magic (`0x81` or `0x18`) whose `tcp.stream` and `couchbase.opaque` never appear on a request. The chart page shows up to ten of those rows under **Responses missing a request**, spaced across the capture rather than taken from the start of the file. **Start of file** is marked only for the ones inside the opening in-flight window. **Inside** means the reply is later than that window. The same limit applies to **Requests missing a response**. Every unanswered request is in `orphans.tsv` next to the page.

The same opaque on a request that appears after that reply is a new call. Pairing does not attach the earlier reply to the later request, so the reply stays a reply with no request.

A Statistics request (`couchbase.opcode == 0x10`), including key `vbucket-seqno`, is not one of those. The server answers with one response packet per stat line, hundreds of them, every packet repeating the request opaque, and a final packet with an empty key ends the list. The client often sends that same opaque again a second later for the next poll. Those packets are one call. The call is finished at the last packet. They are not lost replies and they are not a retry.

DCP is a different reuse of the opaque. On a replication stream the opaque is the stream id. A snapshot marker (`0x56`) and a mutation (`0x57`) often share one TCP packet and that id. The snapshot ack flag is usually clear, so no `0x81` reply is expected. A later packet with the same key and the same opaque is the next mutation (sequence number and revision both move), not a second try of the first packet.

To look at one of them, take the stream and opaque from that table:

```text
tcp.stream == 0 && couchbase.opaque == 0x00ab12cd
```

You should see the response and no request. Then look for the hole on that stream:

```text
tcp.stream == 0 && tcp.analysis.lost_segment
```

A lost segment toward the server, around the same time as the reply, is the missing request. Few retransmissions next to many of those holes means the sender did not put the packet on the wire again, and the recorder did not have another copy to save.
