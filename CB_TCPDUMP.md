# Capture Couchbase traffic with tcpdump

Run this on the Linux host that has the Couchbase address. A laptop only sees its own packets. The capture needs root. `port` matches either direction, so a request and its reply are both saved. `dst port 11210` keeps the requests and drops the replies.

This analyzer reads the plain KV traffic on **11210**. The command below also records the other Couchbase service ports so the same file can be opened in Wireshark for the UI, Query, Search, and Views. TLS on **11207** is in the file, and it is not decrypted here.

## 1. Find the interface

```bash
ip route | grep default
```

The interface is the word after `dev`. In this example it is **eth0**:

```text
default via 10.128.0.1 dev eth0 proto dhcp src 10.128.0.5
```

If the node has more than one address, `ip a` lists each interface above its addresses. Use the name above the Couchbase IP (`eth0`, `ens33`, `enp3s0`, and so on).

## 2. Start the capture

Replace `eth0` with the interface from the step above. Replace `filename` with a name for this capture.

```bash
sudo tcpdump -i eth0 -s 0 -W 2 -C 500 -w filename.pcap port 11210 or port 8091 or port 8092 or port 8093 or port 8094 or port 11207
```

| Flag | What it does |
| --- | --- |
| `-i eth0` | Listen on that interface. |
| `-s 0` | Save the whole packet, not a shortened copy. |
| `-C 500` | Start a new file after about 500 MB (500 million bytes). |
| `-W 2` | Keep two files, then overwrite the older one. The capture stays near 1 GB. |
| `-w filename.pcap` | Write a pcap. With `-C`, the names are `filename.pcap0` and `filename.pcap1`. |

| Port | Service |
| --- | --- |
| 11210 | KV, memcached binary, plain. This is the traffic the analyzer charts. |
| 11207 | KV over TLS. |
| 8091 | Web console and REST. |
| 8092 | Views. |
| 8093 | Query. |
| 8094 | Search. |

The terminal looks idle while tcpdump is writing. That is the capture running.

## 3. Check the file, then stop

In a second terminal:

```bash
ls -lh filename.pcap*
```

The size should grow. When the event you care about is in the file, go back to the tcpdump terminal and press **Ctrl+C**.

Open the pcap in Wireshark with the filters in [CB_WIRESHARK.md](CB_WIRESHARK.md), or pass it to `analyze_capture.py`. The analyzer uses the packets on port 11210.
