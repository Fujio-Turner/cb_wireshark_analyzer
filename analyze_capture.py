#!/usr/bin/env python3
"""Match Couchbase requests and responses in a Wireshark dump.

The script counts. A model writes the note from those counts. The default is a
local Ollama server (config.json, qwen3.8:27b-mlx). --provider openai sends the
same brief to an OpenAI-compatible chat API. Pass --no-ai to keep the counted
note only.
Pass --dry-run to print the plan without writing files or calling the model.

Input is a pcap/pcapng, a tshark field export (.tsv or .csv), or a directory
containing them. A request export alone has no responses and, on collections,
an empty couchbase.key. When a pcap sits next to that export, the pcap is used.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_OLLAMA = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen3.8:27b-mlx"
_LOCAL_API_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
DEFAULT_TIMEOUT = 600
TABLE_TOKEN = "{{UNANSWERED_TABLE}}"

# Wireshark client opcode labels from packet-couchbase.c (client_opcode_vals).
# The field reference lists couchbase.opcode but not these values.
OPCODES = {
    0x00: 'Get',
    0x01: 'Set',
    0x02: 'Add',
    0x03: 'Replace',
    0x04: 'Delete',
    0x05: 'Increment',
    0x06: 'Decrement',
    0x07: 'Quit',
    0x08: 'Flush',
    0x09: 'Get Quietly',
    0x0A: 'NOOP',
    0x0B: 'Version',
    0x0C: 'Get Key',
    0x0D: 'Get Key Quietly',
    0x0E: 'Append',
    0x0F: 'Prepend',
    0x10: 'Statistics',
    0x11: 'Set Quietly',
    0x12: 'Add Quietly',
    0x13: 'Replace Quietly',
    0x14: 'Delete Quietly',
    0x15: 'Increment Quietly',
    0x16: 'Decrement Quietly',
    0x17: 'Quit Quietly',
    0x18: 'Flush Quietly',
    0x19: 'Append Quietly',
    0x1A: 'Prepend Quietly',
    0x1B: 'Verbosity',
    0x1C: 'Touch',
    0x1D: 'Get and Touch',
    0x1E: 'Gat and Touch Quietly',
    0x1F: 'Hello',
    0x20: 'List SASL Mechanisms',
    0x21: 'SASL Authenticate',
    0x22: 'SASL Step',
    0x23: 'IOCTL Get',
    0x24: 'IOCTL Set',
    0x25: 'Config Validate',
    0x26: 'Config Reload',
    0x27: 'Audit Put',
    0x28: 'Audit Config Reload',
    0x29: 'Shutdown',
    0x2D: 'Set Active Encryption Keys',
    0x2E: 'Prune Encryption Keys',
    0x30: 'Range Get',
    0x31: 'Range Set',
    0x32: 'Range Set Quietly',
    0x33: 'Range Append',
    0x34: 'Range Append Quietly',
    0x35: 'Range Prepend',
    0x36: 'Range Prepend Quietly',
    0x37: 'Range Delete',
    0x38: 'Range Delete Quietly',
    0x39: 'Range Increment',
    0x3A: 'Range Increment Quietly',
    0x3B: 'Range Decrement',
    0x3C: 'Range Decrement Quietly',
    0x3D: 'Set VBucket',
    0x3E: 'Get VBucket',
    0x3F: 'Delete VBucket',
    0x40: 'TAP Connect',
    0x41: 'TAP Mutation',
    0x42: 'TAP Delete',
    0x43: 'TAP Flush',
    0x44: 'TAP Opaque',
    0x45: 'TAP VBucket Set',
    0x46: 'TAP Checkpoint Start',
    0x47: 'TAP Checkpoint End',
    0x48: 'Get All VBucket Seqnos',
    0x49: 'GetEx',
    0x4A: 'GetEx Replica',
    0x50: 'DCP Open Connection',
    0x51: 'DCP Add Stream',
    0x52: 'DCP Close Stream',
    0x53: 'DCP Stream Request',
    0x54: 'DCP Get Failover Log',
    0x55: 'DCP Stream End',
    0x56: 'DCP Snapshot Marker',
    0x57: 'DCP (Key) Mutation',
    0x58: 'DCP (Key) Deletion',
    0x59: 'DCP (Key) Expiration',
    0x5A: 'DCP Flush',
    0x5B: 'DCP Set VBucket State',
    0x5C: 'DCP NOOP',
    0x5D: 'DCP Buffer Acknowledgement',
    0x5E: 'DCP Control',
    0x5F: 'DCP System Event',
    0x60: 'DCP Prepare',
    0x61: 'DCP Seqno Acknowledgement',
    0x62: 'DCP Commit',
    0x63: 'DCP Abort',
    0x64: 'DCP Seqno Advanced',
    0x65: 'DCP Out of Sequence Order Snapshot',
    0x66: 'DCP Cache Transfer',
    0x67: 'DCP Cache Transfer End',
    0x70: 'Get Fusion Storage Snapshot',
    0x71: 'Release Fusion Storage Snapshot',
    0x72: 'Mount Fusion VBucket',
    0x73: 'Unmount Fusion VBucket',
    0x74: 'Sync Fusion Logstore',
    0x75: 'Start Fusion Uploader',
    0x76: 'Stop Fusion Uploader',
    0x77: 'Delete Fusion Namespace',
    0x78: 'Get Fusion Namespaces',
    0x80: 'Stop Persistence',
    0x81: 'Start Persistence',
    0x82: 'Set Parameter',
    0x83: 'Get Replica',
    0x85: 'Create Bucket',
    0x86: 'Delete Bucket',
    0x87: 'List Buckets',
    0x88: 'Expand Bucket',
    0x89: 'Select Bucket',
    0x90: 'Start Replication',
    0x91: 'Observe Sequence Number',
    0x92: 'Observe',
    0x93: 'Evict Key',
    0x94: 'Get Locked',
    0x95: 'Unlock Key',
    0x96: 'Sync',
    0x97: 'Last Closed Checkpoint',
    0x98: 'Restore File',
    0x99: 'Restore Abort',
    0x9A: 'Restore Complete',
    0x9B: 'Online Update Start',
    0x9C: 'Online Update Complete',
    0x9D: 'Online Update Revert',
    0x9E: 'Deregister TAP Client',
    0x9F: 'Reset Replication Chain',
    0xA0: 'Get Meta',
    0xA1: 'Get Meta Quietly',
    0xA2: 'Set with Meta',
    0xA3: 'Set with Meta Quietly',
    0xA4: 'Add with Meta',
    0xA5: 'Add with Meta Quietly',
    0xA6: 'Snapshot VBuckets States',
    0xA7: 'VBucket Batch Count',
    0xA8: 'Delete with Meta',
    0xA9: 'Delete with Meta Quietly',
    0xAA: 'Create Checkpoint',
    0xAC: 'Notify VBucket Update',
    0xAD: 'Enable Traffic',
    0xAE: 'Disable Traffic',
    0xAF: 'Ifconfig',
    0xB0: 'Change VBucket Filter',
    0xB1: 'Checkpoint Persistence',
    0xB2: 'Return Meta',
    0xB3: 'Compact Database',
    0xB4: 'Set Cluster Config',
    0xB5: 'Get Cluster Config',
    0xB6: 'Get Random Key',
    0xB7: 'Seqno Persistence',
    0xB8: 'Get Keys',
    0xB9: "Set Collection's Manifest",
    0xBA: "Get Collection's Manifest",
    0xBB: 'Get Collection ID',
    0xBC: 'Get Scope ID',
    0xC1: 'Set Drift Counter State',
    0xC2: 'Get Adjusted Time',
    0xC5: 'Subdoc Get',
    0xC6: 'Subdoc Exists',
    0xC7: 'Subdoc Dictionary Add',
    0xC8: 'Subdoc Dictionary Upsert',
    0xC9: 'Subdoc Delete',
    0xCA: 'Subdoc Replace',
    0xCB: 'Subdoc Array Push Last',
    0xCC: 'Subdoc Array Push First',
    0xCD: 'Subdoc Array Insert',
    0xCE: 'Subdoc Array Add Unique',
    0xCF: 'Subdoc Counter',
    0xD0: 'Subdoc Multipath Lookup',
    0xD1: 'Subdoc Multipath Mutation',
    0xD2: 'Subdoc Get Count',
    0xD3: 'Subdoc Replace Body With Xattr',
    0xDA: 'RangeScan Create',
    0xDB: 'RangeScan Continue',
    0xDC: 'RangeScan Cancel',
    0xE0: 'Prepare Snapshot',
    0xE1: 'Release Snapshot',
    0xE2: 'Download Snapshot',
    0xE3: 'Get File Fragment',
    0xF0: 'Scrub',
    0xF1: 'isasl Refresh',
    0xF2: 'SSL Certificates Refresh',
    0xF3: 'Internal Timer Control',
    0xF4: 'Set Control Token',
    0xF5: 'Get Control Token',
    0xF6: 'Update External User Permissions',
    0xF7: 'RBAC Refresh',
    0xF8: 'Auth Provider',
    0xFB: 'Drop Privilege',
    0xFC: 'Adjust Timeofday',
    0xFD: 'EWOULDBLOCK Control',
    0xFE: 'Get Error Map',
}

# KV only. tcp.port is either side, so a reply leaving 11210 stays in.
KV_PORT = "11210"
KV_PORTS = {"11210", "11207"}
# DCP is the in-cluster replication stream. Meta commands are XDCR.
_CLUSTER_OPCODES = {f"0x{code:02x}" for code in range(0x50, 0x68)} | {
    "0x48", "0xa0", "0xa1", "0xa2", "0xa3", "0xa4", "0xa5", "0xa8",
}


PACKET_TYPE_ORDER = (
    "Couchbase",
    "Lost segment",
    "Retransmission",
    "Ack lost segment",
    "Other",
)


# A real TCP retransmission waits out a timeout. A second copy within a
# millisecond is the same segment recorded twice.
_DUPLICATE_RTO_SECONDS = 0.001


def _rto_seconds(value: str) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def is_capture_duplicate(retrans: bool, rto: float | None) -> bool:
    """Wireshark's suspected retransmission with no real timeout.

    The expert info fires when the same sequence number appears again. On a
    span or a double-fed capture that happens in the same microsecond. TCP
    cannot retransmit that fast.
    """
    if not retrans:
        return False
    return rto is None or rto < _DUPLICATE_RTO_SECONDS


def packet_kind(
    has_couchbase: bool,
    lost: bool,
    retrans: bool,
    ack: bool,
    opcode: str = "",
    is_response: bool = False,
    tcp_len: int = 0,
    duplicate: bool = False,
) -> str:
    """One bar per packet. A Couchbase header names the command.

    A capture duplicate is the same segment seen twice. It is not a retry.
    Retransmission is a resend that waited out a timeout, and only when the
    segment has no Couchbase header. The retry line on the loss chart counts
    those real resends.
    """
    if duplicate:
        return "Capture duplicate"
    if has_couchbase:
        side = "response" if is_response else "request"
        return f"{opcode or 'Couchbase'} {side}"
    if lost:
        return "Lost segment"
    if retrans:
        return "Retransmission"
    if ack:
        return "Ack lost segment"
    if tcp_len <= 0:
        return "TCP ACK"
    return "TCP data segment"


def _frame_command(cols: list[str]) -> tuple[str, bool]:
    """First command in a row whose Couchbase columns did not line up."""
    magic_at = _PREFIX_COLUMNS
    opcode_at = _PREFIX_COLUMNS + 1
    if len(cols) <= opcode_at or not cols[magic_at]:
        return "", False
    magic_text = cols[magic_at].split(FIELD_AGG)[0]
    opcode_text = cols[opcode_at].split(FIELD_AGG)[0] if cols[opcode_at] else ""
    try:
        magic_int = int(magic_text, 16) if magic_text.lower().startswith("0x") else int(magic_text or "0")
    except ValueError:
        magic_int = 0
    name = opcode_name(hex_int(opcode_text, 2)) if opcode_text else ""
    return name, magic_int in CLIENT_RES_MAGIC


def on_kv_port(sport: str, dport: str) -> bool:
    return str(sport) == KV_PORT or str(dport) == KV_PORT


def _keep_kv(messages: list[dict]) -> list[dict]:
    kept = []
    for msg in messages:
        sport = msg.get("sport") or ""
        dport = msg.get("dport") or ""
        if not sport and not dport:
            kept.append(msg)
        elif on_kv_port(sport, dport):
            kept.append(msg)
    return kept


# Plain descriptions for the commands people meet on port 11210.
# Names stay as Wireshark prints them. The chart tooltips show these sentences.
OPCODE_DESCRIPTIONS = {
    0x00: "Retrieves a document.",
    0x01: "Stores a document unconditionally.",
    0x02: "Stores a document only if it does not exist.",
    0x03: "Stores a document only if it already exists.",
    0x04: "Removes a document.",
    0x05: "Increments a numeric counter.",
    0x06: "Decrements a numeric counter.",
    0x07: "Closes the connection.",
    0x08: "Flushes the bucket, when that is enabled.",
    0x09: "Quiet Get. No response when the key does not exist.",
    0x0A: "No-op. Keep-alive.",
    0x0B: "Gets the server version.",
    0x0C: "Get, and return the key in the response.",
    0x0D: "Quiet Get, and return the key.",
    0x0E: "Appends data to an existing document.",
    0x0F: "Prepends data to an existing document.",
    0x10: "Retrieves server statistics. Key vbucket-seqno is the DCP high-seqno poll.",
    0x11: "Quiet Set. No response on success.",
    0x12: "Quiet Add. No response on success.",
    0x13: "Quiet Replace. No response on success.",
    0x14: "Quiet Delete. No response on success.",
    0x15: "Quiet Increment. No response on success.",
    0x16: "Quiet Decrement. No response on success.",
    0x17: "Quiet Quit. No response on success.",
    0x18: "Quiet Flush. No response on success.",
    0x19: "Quiet Append. No response on success.",
    0x1A: "Quiet Prepend. No response on success.",
    0x1B: "Sets logging verbosity.",
    0x1C: "Updates a document's expiration time.",
    0x1D: "Get and Touch. Retrieves the document and updates its expiration.",
    0x1E: "Quiet Get and Touch.",
    0x1F: "Hello. Client capability negotiation.",
    0x20: "Lists supported SASL authentication mechanisms.",
    0x21: "Starts SASL authentication.",
    0x22: "Continues SASL authentication.",
    0x23: "IOCTL Get.",
    0x24: "IOCTL Set.",
    0x25: "Validates configuration.",
    0x26: "Reloads configuration.",
    0x27: "Writes an audit event.",
    0x28: "Reloads audit configuration.",
    0x29: "Shuts the server down.",
    0x30: "Replica Get.",
    0x31: "Replica Set.",
    0x32: "Quiet Replica Set.",
    0x33: "Replica Append.",
    0x34: "Quiet Replica Append.",
    0x35: "Replica Prepend.",
    0x36: "Quiet Replica Prepend.",
    0x37: "Replica Delete.",
    0x38: "Quiet Replica Delete.",
    0x39: "Replica Increment.",
    0x3A: "Quiet Replica Increment.",
    0x3B: "Replica Decrement.",
    0x3C: "Quiet Replica Decrement.",
    0x3D: "Sets a vBucket state.",
    0x3E: "Reads a vBucket state.",
    0x3F: "Deletes a vBucket.",
    0x40: "TAP Connect. Legacy replication.",
    0x41: "TAP Mutation. Legacy replication.",
    0x42: "TAP Delete. Legacy replication.",
    0x43: "TAP Flush. Legacy replication.",
    0x44: "TAP Opaque. Legacy replication.",
    0x45: "TAP vBucket set. Legacy replication.",
    0x46: "TAP checkpoint start. Legacy replication.",
    0x47: "TAP checkpoint end. Legacy replication.",
    0x50: "DCP Open. Starts a streaming connection.",
    0x51: "DCP add stream.",
    0x52: "DCP close stream.",
    0x53: "DCP stream request. Its opaque is copied onto every later message for that stream.",
    0x54: "DCP get failover log.",
    0x55: "DCP stream end. The consumer does not reply.",
    0x56: "DCP snapshot marker. A reply is required only when the ack flag 0x08 is set.",
    0x57: "DCP mutation. The consumer does not reply. Flow control is a later buffer ack.",
    0x58: "DCP deletion. The consumer does not reply.",
    0x59: "DCP expiration. The consumer does not reply.",
    0x5A: "DCP flush.",
    0x5B: "DCP set vBucket state.",
    0x5C: "DCP noop. The producer sends it, and the consumer must answer or the producer drops the connection.",
    0x5D: "DCP buffer acknowledgement. The producer does not answer. Opaque 0 is the whole connection.",
    0x5E: "DCP control.",
    0x83: "Requests a document from a replica.",
    0x89: "Selects the bucket for this connection.",
    0x91: "Checks durability by sequence number.",
    0x92: "Legacy durability check.",
    0x94: "Fetches a document and applies a pessimistic lock.",
    0x95: "Unlocks a previously locked document.",
    0xA0: "Get with meta. Used by cross-datacenter replication.",
    0xA1: "Quiet Get with meta.",
    0xA2: "Set with meta. Used by cross-datacenter replication.",
    0xA3: "Quiet Set with meta.",
    0xA4: "Add with meta.",
    0xA5: "Quiet Add with meta.",
    0xA8: "Delete with meta.",
    0xA9: "Quiet Delete with meta.",
    0xB4: "Pushes an updated cluster map.",
    0xB5: "Pulls the active cluster map.",
    0xC5: "Sub-document Get. Reads one JSON path.",
    0xC6: "Sub-document Exists. Checks one JSON path.",
    0xC7: "Sub-document dictionary add.",
    0xC8: "Sub-document dictionary upsert.",
    0xC9: "Sub-document delete.",
    0xCA: "Sub-document replace.",
    0xCB: "Sub-document array push last.",
    0xCC: "Sub-document array push first.",
    0xCD: "Sub-document array insert.",
    0xCE: "Sub-document array add unique.",
    0xCF: "Sub-document counter.",
    0xD0: "Sub-document multi lookup. Reads several JSON paths.",
    0xD1: "Sub-document multi mutation. Changes several JSON paths.",
    0xD2: "Sub-document get count.",
}


def opcode_description(opcode: str) -> str:
    text = str(opcode or "").strip()
    try:
        number = int(text, 16) if text.lower().startswith("0x") else int(text)
    except (TypeError, ValueError):
        return ""
    return OPCODE_DESCRIPTIONS.get(number, "")


STATUS = {
    0x00: "success",
    0x01: "key not found",
    0x02: "key exists",
    0x03: "value too large",
    0x04: "invalid arguments",
    0x05: "not stored",
    0x06: "non-numeric",
    0x07: "not my vbucket",
    0x08: "authentication error",
    0x09: "locked",
    0x81: "unknown command",
    0x82: "out of memory",
    0x83: "not supported",
    0x84: "internal error",
    0x85: "busy",
    0x86: "temporary failure",
    0x23: "rollback",
}

CLIENT_REQ_MAGIC = {0x80, 0x08}
CLIENT_RES_MAGIC = {0x81, 0x18}
MAGIC_ROLE = {
    0x80: "request",
    0x08: "request, flexible framing",
    0x81: "response",
    0x18: "response, flexible framing",
    0x82: "server request",
    0x83: "server response",
}

COLUMN_ALIASES = {
    "frame": ("frame.number", "frame", "no.", "no", "number"),
    "time": ("frame.time_relative", "time", "time_relative", "frame.time"),
    "stream": ("tcp.stream", "stream"),
    "src": ("ip.src", "src", "source"),
    "sport": ("tcp.srcport", "srcport", "src_port", "source port"),
    "dst": ("ip.dst", "dst", "destination"),
    "dport": ("tcp.dstport", "dstport", "dst_port", "destination port"),
    "opcode": ("couchbase.opcode", "opcode"),
    "opaque": ("couchbase.opaque", "opaque"),
    "key": ("couchbase.key.logical_key", "logical_key", "couchbase.key", "key"),
    "status": ("couchbase.status", "status"),
    "magic": ("couchbase.magic", "magic"),
}

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def log(message: str) -> None:
    print(message, file=sys.stderr)


# DCP is full duplex. The producer sends request-magic packets that are not
# RPCs. kv_engine docs/dcp: the consumer does not reply to stream end, mutation,
# deletion, expiration, or a snapshot marker unless snapshot-type flag 0x08 (Ack)
# is set. Buffer acknowledgement's response is unused. Seqno acknowledged has
# no success response. System event, prepare, commit, abort, seqno advanced,
# OSO snapshot, and cache transfer are producer data. Noop is not in this set:
# the consumer must answer it.
_NO_REPLY_OPCODES = {
    0x55, 0x56, 0x57, 0x58, 0x59, 0x5D,
    0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
}


# Statistics (0x10) answers with one packet per stat line, then an empty
# terminator. Every packet repeats the request opaque. vbucket-seqno does this.
_MULTI_RESPONSE_OPCODES = {0x10}


def _opcode_number(opcode: str) -> int | None:
    text = str(opcode or "").strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None


def _flag_set(value) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def expects_reply(opcode: str, snapshot_ack=False) -> bool:
    number = _opcode_number(opcode)
    if number is None:
        return True
    # Snapshot marker replies only when the ack flag (0x08) is set.
    if number == 0x56:
        return bool(snapshot_ack)
    return number not in _NO_REPLY_OPCODES


def is_multi_response(opcode: str) -> bool:
    """One request, many response packets, one opaque."""
    return _opcode_number(opcode) in _MULTI_RESPONSE_OPCODES


def traffic_role(sport: str, dport: str, opcode: str = "", key: str = "") -> str:
    """Cluster is node-to-node, DCP, or replication meta. SDK is an app port to KV."""
    if str(sport or "") in KV_PORTS and str(dport or "") in KV_PORTS:
        return "cluster"
    if str(opcode or "").lower() in _CLUSTER_OPCODES:
        return "cluster"
    # Stats key vbucket-seqno is the DCP poll for the high sequence number.
    if _opcode_number(opcode) == 0x10 and str(key or "").startswith("vbucket-seqno"):
        return "cluster"
    return "sdk"


def cluster_endpoints(requests: list[dict]) -> set[str]:
    """Ephemeral ports that carried a cluster command. The reply comes back from the KV port."""
    ends: set[str] = set()
    for msg in requests:
        if traffic_role(msg.get("sport") or "", msg.get("dport") or "", msg.get("opcode") or "", msg.get("key") or "") != "cluster":
            continue
        for port in (str(msg.get("sport") or ""), str(msg.get("dport") or "")):
            if port and port not in KV_PORTS:
                ends.add(port)
    return ends


def flow_role(sport: str, dport: str, cluster_ends: set[str]) -> str:
    sport, dport = str(sport or ""), str(dport or "")
    if sport in KV_PORTS and dport in KV_PORTS:
        return "cluster"
    other = dport if sport in KV_PORTS else sport if dport in KV_PORTS else ""
    if other and other in cluster_ends:
        return "cluster"
    return "sdk"


def opcode_name(opcode: str, learned: dict[str, str] | None = None) -> str:
    if learned and opcode in learned:
        return learned[opcode]
    try:
        return OPCODES.get(int(opcode, 16), opcode)
    except (TypeError, ValueError):
        return opcode or ""


def status_name(status: str) -> str:
    if not status:
        return ""
    try:
        return STATUS.get(int(status, 16), status)
    except (TypeError, ValueError):
        return status


# extras + key + value. 1 MB is the size where a call often slows down.
LARGE_BODY_BYTES = 1_048_576


def body_len(value) -> int:
    text = "" if value is None else str(value).strip()
    if not text:
        return 0
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(float(text))
    except ValueError:
        return 0


def hex_int(value, width: int) -> str:
    if value is None or value == "":
        return ""
    text = str(value).strip()
    if "," in text:
        return text
    number = int(text, 16) if text.lower().startswith("0x") else int(float(text))
    return f"0x{number:0{width}x}"


def first(value):
    if isinstance(value, list):
        return value[0] if value else ""
    return value


def field(item: dict, suffix: str):
    """EK flattens fields to couchbase_couchbase_<suffix>."""
    if not isinstance(item, dict):
        return None
    direct = (
        f"couchbase_couchbase_{suffix}",
        f"couchbase_{suffix}",
        suffix,
    )
    for key in direct:
        if key in item and item[key] not in (None, ""):
            return item[key]
    tail = "_" + suffix
    for key, val in item.items():
        if key.endswith(tail) and val not in (None, ""):
            return val
    return None


def key_family(key: str) -> str:
    if not key:
        return "(no key)"
    parts = key.split("::")
    if len(parts) >= 2:
        return "::".join(parts[:2])
    return parts[0]


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    index = (len(ordered) - 1) * p
    low = int(index)
    high = min(low + 1, len(ordered) - 1)
    frac = index - low
    return ordered[low] * (1 - frac) + ordered[high] * frac


def fmt_secs(value: float) -> str:
    return f"{value:.3f}"


def fmt_ms(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value * 1000:.1f} ms"


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    head = "| " + " | ".join(headers) + " |"
    rule = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return "\n".join([head, rule, *body])


def backtick(text: str) -> str:
    return "`" + text.replace("|", "\\|") + "`"


def find_tshark(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    found = shutil.which("tshark")
    if found:
        return found
    mac = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
    if mac.exists():
        return str(mac)
    return None


def find_capinfos(tshark: str | None) -> str | None:
    if tshark:
        sibling = Path(tshark).with_name("capinfos")
        if sibling.exists():
            return str(sibling)
    found = shutil.which("capinfos")
    return found


def is_pcap(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith((".pcap", ".pcapng", ".pcap.gz", ".pcapng.gz"))


def is_table(path: Path) -> bool:
    return path.suffix.lower() in {".tsv", ".csv", ".txt", ".tsx"}


def file_md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prefer_plain_pcaps(paths: list[Path]) -> list[Path]:
    """A .pcap.gz next to the same capture's .pcap is the compressed copy, not a second capture."""
    plain = [path for path in paths if not path.name.lower().endswith(".gz")]
    return plain or paths


def _choose_rep(members: list[Path]) -> tuple[Path, list[Path]]:
    plain = [path for path in members if not path.name.lower().endswith(".gz")]
    rep = sorted(plain or members, key=lambda path: path.name)[0]
    return rep, sorted(members, key=lambda path: path.name)


def unique_pcaps(paths: list[Path]) -> list[tuple[Path, list[Path]]]:
    """Group capture files by content. Hash only files that share a size."""
    paths = prefer_plain_pcaps(paths)
    if not paths:
        return []
    if len(paths) == 1:
        return [_choose_rep(paths)]
    by_size: dict[int, list[Path]] = defaultdict(list)
    for path in paths:
        by_size[path.stat().st_size].append(path)
    chosen = []
    for group in by_size.values():
        if len(group) == 1:
            chosen.append(_choose_rep(group))
            continue
        by_hash: dict[str, list[Path]] = defaultdict(list)
        for path in group:
            by_hash[file_md5(path)].append(path)
        for members in by_hash.values():
            chosen.append(_choose_rep(members))
    return sorted(chosen, key=lambda item: item[0].name)


def parse_capinfos_text(text: str) -> tuple[float | None, int | None]:
    """Pull duration and packet count out of capinfos' text report.

    The summary line is rounded ("82 k"). The per-interface line is the exact count.
    """
    duration = None
    packets = None
    match = re.search(r"Capture duration:\s+([0-9.]+)", text)
    if match:
        duration = float(match.group(1))
    match = re.search(r"Number of packets\s*=\s*([0-9,]+)", text)
    if match:
        packets = int(match.group(1).replace(",", ""))
    else:
        match = re.search(r"Number of packets:\s+([0-9.,]+)\s*(k|m)?", text, re.I)
        if match:
            number = float(match.group(1).replace(",", ""))
            unit = (match.group(2) or "").lower()
            if unit == "k":
                number *= 1000
            elif unit == "m":
                number *= 1_000_000
            packets = int(number)
    return duration, packets


def read_capinfos(capinfos: str, pcap: Path) -> tuple[float | None, int | None]:
    proc = subprocess.run(
        [capinfos, str(pcap)],
        check=False,
        capture_output=True,
        text=True,
    )
    return parse_capinfos_text(proc.stdout or "")


def _message_from_item(item: dict, frame: dict, ip: dict, tcp: dict) -> dict | None:
    magic_raw = field(item, "magic")
    if magic_raw is None:
        return None
    try:
        magic = int(first(magic_raw))
    except (TypeError, ValueError):
        return None
    key = first(field(item, "key_logical_key")) or first(field(item, "key")) or ""
    if isinstance(key, str):
        key = key.strip()
    status_raw = field(item, "status")
    return {
        "frame": str(first(frame.get("frame_frame_number", ""))),
        "time": float(first(frame.get("frame_frame_time_relative", 0)) or 0),
        "stream": str(first(tcp.get("tcp_tcp_stream", ""))),
        "src": str(first(ip.get("ip_ip_src", ""))),
        "sport": str(first(tcp.get("tcp_tcp_srcport", ""))),
        "dst": str(first(ip.get("ip_ip_dst", ""))),
        "dport": str(first(tcp.get("tcp_tcp_dstport", ""))),
        "opcode": hex_int(first(field(item, "opcode")), 2),
        "opaque": hex_int(first(field(item, "opaque")), 8),
        "key": key if isinstance(key, str) else str(key),
        "status": hex_int(first(status_raw), 4) if status_raw not in (None, "") else "",
        "body": body_len(first(field(item, "total_bodylength"))),
        "magic": magic,
        "snapshot_ack": _flag_set(first(field(item, "dcp_snapshot_marker_ack"))),
    }


# Unit separator. Commas appear in document keys, so they cannot join repeated fields.
FIELD_AGG = "\x1f"
_FIELD_COLUMNS = (
    "frame.number",
    "frame.time_relative",
    "tcp.stream",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "couchbase.magic",
    "couchbase.opcode",
    "couchbase.opaque",
    "couchbase.key.logical_key",
    "couchbase.key",
    "couchbase.status",
    "couchbase.total_bodylength",
    "couchbase.extras.flags.dcp_snapshot_marker_ack",
    "tcp.analysis.lost_segment",
    "tcp.analysis.retransmission",
    "tcp.analysis.ack_lost_segment",
    "tcp.len",
    "tcp.analysis.rto",
)
# Couchbase columns, then the three frame-level TCP flags. Flags are not repeated per message.
_PREFIX_COLUMNS = 7
_CB_COLUMNS = 8
_FLAG_COLUMNS = 3


def iter_tshark(cmd: list[str]):
    """Stream tshark stdout. One process, one read of the capture."""
    stderr_file = tempfile.NamedTemporaryFile(prefix="tshark-", suffix=".err", delete=False)
    stderr_path = Path(stderr_file.name)
    stderr_file.close()
    stderr_handle = open(stderr_path, "w")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr_handle)
    assert proc.stdout is not None
    try:
        for raw in proc.stdout:
            yield raw.decode("utf-8", "replace").rstrip("\n")
        code = proc.wait()
        if code != 0:
            stderr_handle.close()
            tail = stderr_path.read_text(errors="replace")[-2000:]
            raise SystemExit(f"tshark exited {code}\n{tail}")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        stderr_handle.close()
        stderr_path.unlink(missing_ok=True)


def _split_repeated(value: str) -> list[str] | None:
    """None means this column is absent on every message in the frame."""
    if value == "":
        return None
    return value.split(FIELD_AGG)


def _loss_event(time_raw: str, stream: str, sport: str, dport: str, lost: str, retrans: str, ack: str) -> dict | None:
    if not (lost or retrans or ack):
        return None
    try:
        when = float(time_raw) if time_raw else 0.0
    except ValueError:
        when = None
    return {
        "time": when,
        "stream": stream,
        "sport": sport,
        "dport": dport,
        "lost": bool(lost),
        "retrans": bool(retrans),
        "ack": bool(ack),
    }


def messages_from_field_line(line: str) -> tuple[list[dict], str | None, dict | None]:
    """One tshark fields row, plus a TCP-gap event when this frame carries one.

    The frame number comes back when Couchbase columns do not line up. tshark drops a
    repeated field that one message lacks, which shifts the rest. Those frames are
    re-read on their own. A blank column means every message lacks it. TCP flags stay
    frame-level, so a short flag column is not a shift.
    """
    width = _PREFIX_COLUMNS + _CB_COLUMNS + _FLAG_COLUMNS
    cols = line.split("\t")
    if len(cols) < width:
        cols.extend([""] * (width - len(cols)))
    frame, time_raw, stream, src, sport, dst, dport = cols[:_PREFIX_COLUMNS]
    flag_at = _PREFIX_COLUMNS + _CB_COLUMNS
    loss = _loss_event(time_raw, stream, sport, dport, cols[flag_at], cols[flag_at + 1], cols[flag_at + 2])
    magic, opcode, opaque, key, raw_key, status, body, ack = (
        _split_repeated(col) for col in cols[_PREFIX_COLUMNS:flag_at]
    )
    present = [len(values) for values in (magic, opcode, opaque) if values]
    if not present:
        return [], None, loss
    count = max(present)
    repeated = (magic, opcode, opaque, key, raw_key, status, body, ack)
    if any(values is not None and len(values) != count for values in repeated):
        return [], frame or None, loss

    def at(values: list[str] | None, index: int) -> str:
        if values is None:
            return ""
        return values[index]

    try:
        when = float(time_raw) if time_raw else 0.0
    except ValueError:
        when = 0.0
    messages = []
    for index in range(count):
        magic_text = at(magic, index)
        try:
            magic_int = int(magic_text, 16) if magic_text.lower().startswith("0x") else int(magic_text or "0")
        except ValueError:
            continue
        messages.append(
            {
                "frame": frame,
                "time": when,
                "stream": stream,
                "src": src,
                "sport": sport,
                "dst": dst,
                "dport": dport,
                "opcode": hex_int(at(opcode, index), 2),
                "opaque": hex_int(at(opaque, index), 8),
                "key": at(key, index) or at(raw_key, index),
                "status": hex_int(at(status, index), 4) if at(status, index) else "",
                "body": body_len(at(body, index)),
                "magic": magic_int,
                "snapshot_ack": _flag_set(at(ack, index)),
            }
        )
    return messages, None, loss


def _keep_client_message(message: dict | None, requests: list[dict], responses: list[dict], magics: Counter) -> None:
    if message is None:
        return
    magics[message["magic"]] += 1
    if message["magic"] in CLIENT_REQ_MAGIC:
        requests.append(message)
    elif message["magic"] in CLIENT_RES_MAGIC:
        responses.append(message)


def _iter_ek_messages(pcap: Path, tshark: str, display: str):
    cmd = [
        tshark,
        "-n",
        "-r",
        str(pcap),
        "-Y",
        display,
        "-T",
        "ek",
        # -J includes values. -j only emits {"filtered": "field.name"}.
        "-J",
        "frame",
        "-J",
        "ip",
        "-J",
        "tcp",
        "-J",
        "couchbase",
    ]
    for line in iter_tshark(cmd):
        if '"layers"' not in line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        layers = obj.get("layers") or {}
        cb = layers.get("couchbase")
        if not cb:
            continue
        frame = layers.get("frame") or {}
        ip = layers.get("ip") or {}
        tcp = layers.get("tcp") or {}
        items = cb if isinstance(cb, list) else [cb]
        for item in items:
            message = _message_from_item(item, frame, ip, tcp)
            if message is not None:
                yield message


def load_pcap(pcap: Path, tshark: str) -> tuple[list[dict], list[dict], Counter, list[dict], Counter]:
    """One fields pass for every packet on port 11210.

    JSON is only for the rare frame whose Couchbase columns do not line up.
    """
    cmd = [
        tshark,
        "-n",
        "-r",
        str(pcap),
        "-Y",
        f"tcp.port == {KV_PORT}",
        "-T",
        "fields",
    ]
    for name in _FIELD_COLUMNS:
        cmd.extend(("-e", name))
    cmd.extend(
        (
            "-E",
            f"aggregator={FIELD_AGG}",
            "-E",
            "occurrence=a",
            "-E",
            "separator=\t",
        )
    )
    log(f"reading port {KV_PORT} packets from {pcap.name}")
    requests: list[dict] = []
    responses: list[dict] = []
    magics: Counter = Counter()
    loss_events: list[dict] = []
    packet_types: Counter = Counter()
    redo: list[str] = []
    for line in iter_tshark(cmd):
        if not line:
            continue
        messages, bad_frame, loss = messages_from_field_line(line)
        cols = line.split("\t")
        tcp_len_at = _PREFIX_COLUMNS + _CB_COLUMNS + _FLAG_COLUMNS
        tcp_len = 0
        if len(cols) > tcp_len_at and cols[tcp_len_at]:
            try:
                tcp_len = int(cols[tcp_len_at])
            except ValueError:
                tcp_len = 0
        opcode = ""
        is_response = False
        has_couchbase = bool(messages) or bad_frame is not None
        if messages:
            opcode = opcode_name(messages[0].get("opcode") or "")
            is_response = messages[0].get("magic") in CLIENT_RES_MAGIC
        elif has_couchbase:
            opcode, is_response = _frame_command(cols)
        rto_at = tcp_len_at + 1
        rto = _rto_seconds(cols[rto_at] if len(cols) > rto_at else "")
        raw_retrans = bool(loss and loss.get("retrans"))
        duplicate = is_capture_duplicate(raw_retrans, rto)
        if loss and duplicate:
            loss["retrans"] = False
            loss["duplicate"] = True
        kind = packet_kind(
            has_couchbase,
            bool(loss and loss.get("lost")),
            bool(loss and loss.get("retrans")),
            bool(loss and loss.get("ack")),
            opcode,
            is_response,
            tcp_len,
            duplicate,
        )
        packet_types[kind] += 1
        if loss and on_kv_port(loss.get("sport", ""), loss.get("dport", "")):
            loss_events.append(loss)
        if bad_frame is not None:
            if bad_frame:
                redo.append(bad_frame)
            continue
        for message in messages:
            if on_kv_port(message.get("sport", ""), message.get("dport", "")):
                _keep_client_message(message, requests, responses, magics)
    if redo:
        log(f"re-reading {len(redo)} frames whose Couchbase columns did not line up, in one pass")
        wanted = set(redo)
        for message in _iter_ek_messages(pcap, tshark, f"tcp.port == {KV_PORT} && couchbase"):
            if str(message.get("frame") or "") not in wanted:
                continue
            if on_kv_port(message.get("sport", ""), message.get("dport", "")):
                _keep_client_message(message, requests, responses, magics)
    if not requests and not responses:
        raise SystemExit(f"No Couchbase client requests or responses in {pcap}")
    return requests, responses, magics, loss_events, packet_types


def lookup_host(ip: str) -> str:
    """Reverse DNS for a Couchbase address. Empty when the name is unknown."""
    if not ip:
        return ""
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(0.4)
        name = socket.getfqdn(ip)
    except OSError:
        return ""
    finally:
        socket.setdefaulttimeout(previous)
    if not name or name == ip:
        return ""
    return name


def couchbase_server(requests: list[dict]) -> dict:
    ranked = Counter(
        (msg.get("dst") or "", str(msg.get("dport") or "")) for msg in requests
    ).most_common(1)
    if not ranked or not ranked[0][0][0]:
        return {}
    ip, port = ranked[0][0]
    host = lookup_host(ip)
    return {"ip": ip, "port": port, "host": host or ip}


def server_label(server: dict | None) -> str:
    server = server or {}
    host = server.get("host") or ""
    ip = server.get("ip") or ""
    if host and ip and host != ip:
        return f"{host} ({ip})"
    return host or ip


def couchbase_ports(requests: list[dict]) -> list[str]:
    counts = Counter(msg["dport"] for msg in requests if msg.get("dport"))
    return [port for port, _ in counts.most_common()]


def summarize_loss(events: list[dict], ports: list[str]) -> dict:
    """Keep gap events on the Couchbase ports. One packet can carry more than one flag."""
    if not ports:
        return {"available": False}
    portset = set(ports)
    lost = retrans = ack_lost = 0
    by_stream: Counter = Counter()
    by_direction = Counter()
    times: dict[str, list[float]] = defaultdict(list)
    for event in events:
        if event["sport"] not in portset and event["dport"] not in portset:
            continue
        if event["lost"]:
            lost += 1
            by_stream[event["stream"]] += 1
            if event["time"] is not None:
                times[event["stream"]].append(event["time"])
            direction = "server_to_client" if event["sport"] in portset else "client_to_server"
            by_direction[direction] += 1
        if event["retrans"]:
            retrans += 1
        if event["ack"]:
            ack_lost += 1
    for stream_times in times.values():
        stream_times.sort()
    return {
        "available": True,
        "ports": ports,
        "lost_segments": lost,
        "retransmissions": retrans,
        "ack_lost_segments": ack_lost,
        "lost_by_stream": dict(by_stream.most_common()),
        "client_to_server": by_direction["client_to_server"],
        "server_to_client": by_direction["server_to_client"],
        "_times": times,
    }


def _ms(value: float | None) -> float | None:
    if value is None:
        return None
    return round(value * 1000, 3)


def _bucket_count(capture_end: float, width: float) -> int:
    if capture_end <= 0:
        return 1
    return int(capture_end / width) + 1


def _bucket_index(when: float, width: float, count: int) -> int:
    if when < 0:
        when = 0
    index = int(when / width + 1e-9)
    if index >= count:
        return count - 1
    return index


def _bucket_key(width: float) -> str:
    if float(width).is_integer():
        return str(int(width))
    return str(width)


def _bucket_time(index: int, width: float) -> float:
    value = index * width
    if float(width).is_integer():
        return float(int(value))
    return round(value, 1)


def _rtt_histogram(samples: list[float]) -> list[dict]:
    edges = [0, 20, 30, 40, 50, 100, 250, 1000]
    counts = [0] * len(edges)
    labels = [f"{edges[i]}–{edges[i + 1]}" for i in range(len(edges) - 1)] + [f"{edges[-1]}+"]
    for gap in samples:
        value = gap * 1000
        placed = False
        for index in range(len(edges) - 1):
            if edges[index] <= value < edges[index + 1]:
                counts[index] += 1
                placed = True
                break
        if not placed:
            counts[-1] += 1
    return [{"label": labels[index], "count": counts[index]} for index in range(len(edges))]


def _role_histogram(matched_rtts: list[tuple]) -> list[dict]:
    """One band list. count is both sides. sdk and cluster stay separate."""
    all_gaps = []
    sdk_gaps = []
    cluster_gaps = []
    for _when, gap, *rest in matched_rtts:
        role = rest[-1] if rest else ""
        all_gaps.append(gap)
        if role == "cluster":
            cluster_gaps.append(gap)
        else:
            sdk_gaps.append(gap)
    rows = _rtt_histogram(all_gaps)
    sdk = {row["label"]: row["count"] for row in _rtt_histogram(sdk_gaps)}
    cluster = {row["label"]: row["count"] for row in _rtt_histogram(cluster_gaps)}
    for row in rows:
        row["sdk"] = sdk[row["label"]]
        row["cluster"] = cluster[row["label"]]
    return rows


def _rtt_summary(samples: list[float]) -> dict:
    if not samples:
        return {
            "rtt_n": 0,
            "rtt_min": None,
            "rtt_max": None,
            "rtt_median": None,
            "rtt_p90": None,
            "rtt_p95": None,
            "rtt_p99": None,
        }
    return {
        "rtt_n": len(samples),
        "rtt_min": _ms(min(samples)),
        "rtt_max": _ms(max(samples)),
        "rtt_median": _ms(statistics.median(samples)),
        "rtt_p90": _ms(percentile(samples, 0.90)),
        "rtt_p95": _ms(percentile(samples, 0.95)),
        "rtt_p99": _ms(percentile(samples, 0.99)),
    }


def build_charts(
    requests: list[dict],
    paired: dict,
    loss_events: list[dict],
    ports: list[str],
    capture_end: float,
    packet_types: Counter | None = None,
) -> dict:
    """Aggregates for the chart page at 0.5, 1, 5, and 10 second buckets."""
    matched_rtts: list[tuple] = []
    ip_rtts: dict[str, list[float]] = defaultdict(list)
    ip_over_100: Counter = Counter()
    for req, resp in paired["matched"]:
        gap = resp["time"] - req["time"]
        if gap < 0:
            continue
        client_ip = req.get("src") or "(unknown)"
        ip_rtts[client_ip].append(gap)
        if gap >= 0.1:
            ip_over_100[client_ip] += 1
        matched_rtts.append((
            req["time"],
            gap,
            req.get("key") or "",
            req.get("opcode") or "",
            int(req.get("body") or 0),
            int(resp.get("body") or 0),
            req.get("opaque") or "",
            str(req.get("stream") or ""),
            req.get("src") or "",
            traffic_role(req.get("sport") or "", req.get("dport") or "", req.get("opcode") or "", req.get("key") or ""),
        ))

    portset = set(ports)
    ends = cluster_endpoints(requests)
    timed_loss = []
    for event in loss_events:
        if portset and event["sport"] not in portset and event["dport"] not in portset:
            continue
        if not portset:
            continue
        if event["time"] is None:
            continue
        timed_loss.append(event)

    widths = (0.5, 1, 5, 10)
    series: dict[str, list[dict]] = {}
    for width in widths:
        count = _bucket_count(capture_end, width)
        requests_n = [0] * count
        matched_n = [0] * count
        unanswered_n = [0] * count
        resp_only_n = [0] * count
        lost_n = [0] * count
        lost_c2s = [0] * count
        lost_s2c = [0] * count
        retrans_n = [0] * count
        ack_n = [0] * count
        opcode_n: list[Counter] = [Counter() for _ in range(count)]
        samples: list[list[float]] = [[] for _ in range(count)]
        sdk_requests_n = [0] * count
        cluster_requests_n = [0] * count
        sdk_unanswered_n = [0] * count
        cluster_unanswered_n = [0] * count
        sdk_retrans_n = [0] * count
        cluster_retrans_n = [0] * count
        sdk_samples: list[list[float]] = [[] for _ in range(count)]
        cluster_samples: list[list[float]] = [[] for _ in range(count)]
        body_in_max = [0] * count
        body_out_max = [0] * count
        body_in_sum = [0] * count
        body_out_sum = [0] * count
        body_large = [0] * count

        def note_body(msg: dict, maxima: list[int], totals: list[int]) -> None:
            size = int(msg.get("body") or 0)
            index = _bucket_index(msg["time"], width, count)
            totals[index] += size
            if size > maxima[index]:
                maxima[index] = size
            if size >= LARGE_BODY_BYTES:
                body_large[index] += 1

        for msg in requests:
            index = _bucket_index(msg["time"], width, count)
            requests_n[index] += 1
            opcode_n[index][opcode_name(msg.get("opcode") or "")] += 1
            if traffic_role(msg.get("sport") or "", msg.get("dport") or "", msg.get("opcode") or "", msg.get("key") or "") == "cluster":
                cluster_requests_n[index] += 1
            else:
                sdk_requests_n[index] += 1
            note_body(msg, body_in_max, body_in_sum)
        for _req, resp in paired["matched"]:
            note_body(resp, body_out_max, body_out_sum)
        for msg in paired["resp_only"]:
            note_body(msg, body_out_max, body_out_sum)
        for when, gap, _key, _opcode, _body_in, _body_out, _opaque, _stream, _requester, role in matched_rtts:
            index = _bucket_index(when, width, count)
            matched_n[index] += 1
            samples[index].append(gap)
            if role == "cluster":
                cluster_samples[index].append(gap)
            else:
                sdk_samples[index].append(gap)
        for msg in paired["unanswered"]:
            index = _bucket_index(msg["time"], width, count)
            unanswered_n[index] += 1
            if traffic_role(msg.get("sport") or "", msg.get("dport") or "", msg.get("opcode") or "", msg.get("key") or "") == "cluster":
                cluster_unanswered_n[index] += 1
            else:
                sdk_unanswered_n[index] += 1
        for msg in paired["resp_only"]:
            resp_only_n[_bucket_index(msg["time"], width, count)] += 1
        for event in timed_loss:
            index = _bucket_index(event["time"], width, count)
            if event["lost"]:
                lost_n[index] += 1
                if event["sport"] in portset:
                    lost_s2c[index] += 1
                else:
                    lost_c2s[index] += 1
            if event["retrans"]:
                retrans_n[index] += 1
                if flow_role(event.get("sport") or "", event.get("dport") or "", ends) == "cluster":
                    cluster_retrans_n[index] += 1
                else:
                    sdk_retrans_n[index] += 1
            if event["ack"]:
                ack_n[index] += 1
        rows = []
        for index in range(count):
            row = {
                "t": _bucket_time(index, width),
                "requests": requests_n[index],
                "matched": matched_n[index],
                "unanswered": unanswered_n[index],
                "resp_only": resp_only_n[index],
                "lost": lost_n[index],
                "lost_c2s": lost_c2s[index],
                "lost_s2c": lost_s2c[index],
                "retrans": retrans_n[index],
                "sdk_requests": sdk_requests_n[index],
                "cluster_requests": cluster_requests_n[index],
                "sdk_unanswered": sdk_unanswered_n[index],
                "cluster_unanswered": cluster_unanswered_n[index],
                "sdk_retrans": sdk_retrans_n[index],
                "cluster_retrans": cluster_retrans_n[index],
                "sdk_n": (sdk_summary := _rtt_summary(sdk_samples[index]))["rtt_n"],
                "sdk_median": sdk_summary["rtt_median"],
                "sdk_p90": sdk_summary["rtt_p90"],
                "sdk_p99": sdk_summary["rtt_p99"],
                "sdk_min": sdk_summary["rtt_min"],
                "sdk_max": sdk_summary["rtt_max"],
                "cluster_n": (cluster_summary := _rtt_summary(cluster_samples[index]))["rtt_n"],
                "cluster_median": cluster_summary["rtt_median"],
                "cluster_p90": cluster_summary["rtt_p90"],
                "cluster_p99": cluster_summary["rtt_p99"],
                "cluster_min": cluster_summary["rtt_min"],
                "cluster_max": cluster_summary["rtt_max"],
                "ack_lost": ack_n[index],
                "opcodes": dict(opcode_n[index]),
                "body_in_max": body_in_max[index],
                "body_out_max": body_out_max[index],
                "body_in_bytes": body_in_sum[index],
                "body_out_bytes": body_out_sum[index],
                "body_large": body_large[index],
            }
            row.update(_rtt_summary(samples[index]))
            rows.append(row)
        series[_bucket_key(width)] = rows

    by_ip: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    by_conn: dict[tuple[str, str], list] = {}
    by_opcode: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    by_key: Counter = Counter()
    key_unanswered: Counter = Counter()
    opcode_rtts: dict[str, list[float]] = defaultdict(list)
    unanswered_keys = {id(msg) for msg in paired["unanswered"]}
    for msg in requests:
        ip = msg.get("src") or "(unknown)"
        port = str(msg.get("sport") or "")
        opcode = msg.get("opcode") or ""
        by_ip[ip][0] += 1
        by_opcode[opcode][0] += 1
        conn = by_conn.get((ip, port))
        if conn is None:
            conn = [0, 0, str(msg.get("stream") or ""), 0, 0]
            by_conn[(ip, port)] = conn
        conn[0] += 1
        if traffic_role(port, msg.get("dport") or "", opcode, msg.get("key") or "") == "cluster":
            conn[4] += 1
        else:
            conn[3] += 1
        key = msg.get("key") or ""
        if key:
            by_key[key] += 1
        if id(msg) in unanswered_keys:
            by_ip[ip][1] += 1
            by_opcode[opcode][1] += 1
            conn[1] += 1
            if key:
                key_unanswered[key] += 1
    for _when, gap, _key, opcode, _body_in, _body_out, _opaque, _stream, _requester, _role in matched_rtts:
        opcode_rtts[opcode].append(gap)

    ranked_calls = sorted(
        (
            (when, gap, key, opcode, body_in, body_out, opaque, stream, requester, role)
            for when, gap, key, opcode, body_in, body_out, opaque, stream, requester, role in matched_rtts
            if key
        ),
        key=lambda item: (-item[1], item[0]),
    )
    slowest = [
        {
            "key": key,
            "time_ms": _ms(gap),
            "seconds": round(when, 3),
            "body_bytes": max(body_in, body_out),
            "opaque": opaque,
            "opcode": opcode,
            "stream": stream,
            "requester": requester,
            "role": role,
        }
        for when, gap, key, opcode, body_in, body_out, opaque, stream, requester, role in ranked_calls[:10]
    ]
    all_rtts = [gap for _when, gap, _key, _opcode, _body_in, _body_out, _opaque, _stream, _requester, _role in matched_rtts]
    overall = _rtt_summary(all_rtts)
    all_ms = [gap * 1000 for gap in all_rtts]
    gap_window = _in_flight_window(matched_rtts)

    def _side(msg: dict) -> str:
        role = traffic_role(
            msg.get("sport") or "",
            msg.get("dport") or "",
            msg.get("opcode") or "",
            msg.get("key") or "",
        )
        return "cluster" if role == "cluster" else "sdk"

    unanswered_by_role: dict[str, list] = {"sdk": [], "cluster": []}
    resp_only_by_role: dict[str, list] = {"sdk": [], "cluster": []}
    for msg in paired["unanswered"]:
        unanswered_by_role[_side(msg)].append(msg)
    for msg in paired["resp_only"]:
        resp_only_by_role[_side(msg)].append(msg)
    loss_marks = _loss_marks(timed_loss, ports)
    return {
        "capture_seconds": round(capture_end, 3),
        "buckets": series,
        "rtt_overall_ms": overall,
        "slow_ms": {
            "matched": len(all_ms),
            "over_50": sum(1 for value in all_ms if value >= 50),
            "over_100": sum(1 for value in all_ms if value >= 100),
            "over_250": sum(1 for value in all_ms if value >= 250),
        },
        "rtt_histogram": _role_histogram(matched_rtts),
        "by_requester_ip": [
            {"ip": ip, "requests": counts[0], "unanswered": counts[1]}
            for ip, counts in sorted(by_ip.items(), key=lambda item: item[1][0], reverse=True)
        ],
        "clients": _client_rows(by_ip, by_conn, ip_rtts, ip_over_100),
        "by_connection": [
            {
                "ip": ip,
                "port": port,
                "stream": slot[2],
                "requests": slot[0],
                "unanswered": slot[1],
                "unanswered_pct": round(100 * slot[1] / slot[0], 1) if slot[0] else 0,
                "role": _connection_role(slot),
            }
            for (ip, port), slot in sorted(by_conn.items(), key=lambda item: item[1][0], reverse=True)
        ],
        "traffic": _traffic_summary(requests, paired, loss_events),
        "by_opcode": [
            {
                "opcode": opcode,
                "name": opcode_name(opcode),
                "requests": counts[0],
                "unanswered": counts[1],
                "median_ms": (summary := _rtt_summary(opcode_rtts[opcode]))["rtt_median"],
                "p99_ms": summary["rtt_p99"],
                "description": opcode_description(opcode),
                "role": "cluster" if str(opcode or "").lower() in _CLUSTER_OPCODES else "sdk",
                "expects_reply": expects_reply(opcode),
            }
            for opcode, counts in sorted(by_opcode.items(), key=lambda item: item[1][0], reverse=True)
        ],
        "top_requested": [
            {"key": key, "count": count, "unanswered": key_unanswered[key]}
            for key, count in by_key.most_common(10)
        ],
        "top_slowest": slowest,
        "missing_response": _annotate_gap_errors(_ten_gaps(paired["unanswered"], capture_end, gap_window, at_start=False), loss_marks),
        "missing_response_total": len(paired["unanswered"]),
        "missing_request": _annotate_gap_errors(_ten_gaps(paired["resp_only"], capture_end, gap_window, at_start=True), loss_marks),
        "missing_request_total": len(paired["resp_only"]),
        "missing_response_sdk": _annotate_gap_errors(_ten_gaps(unanswered_by_role["sdk"], capture_end, gap_window, at_start=False), loss_marks),
        "missing_response_sdk_total": len(unanswered_by_role["sdk"]),
        "missing_response_cluster": _annotate_gap_errors(_ten_gaps(unanswered_by_role["cluster"], capture_end, gap_window, at_start=False), loss_marks),
        "missing_response_cluster_total": len(unanswered_by_role["cluster"]),
        "missing_request_sdk": _annotate_gap_errors(_ten_gaps(resp_only_by_role["sdk"], capture_end, gap_window, at_start=True), loss_marks),
        "missing_request_sdk_total": len(resp_only_by_role["sdk"]),
        "missing_request_cluster": _annotate_gap_errors(_ten_gaps(resp_only_by_role["cluster"], capture_end, gap_window, at_start=True), loss_marks),
        "missing_request_cluster_total": len(resp_only_by_role["cluster"]),
        "server": couchbase_server(requests),
        "packet_types": [
            {"name": name, "count": int(count)}
            for name, count in (packet_types or Counter()).most_common()
            if count
        ],
    }


def _in_flight_window(matched_rtts: list[tuple]) -> float:
    gaps = [gap for _when, gap, *_rest in matched_rtts if gap >= 0]
    return max(gaps) if gaps else 1.0


def _spread_rows(rows: list[dict], limit: int) -> list[dict]:
    """Rows spaced from the earliest to the latest. The list stays in time order."""
    if limit <= 0 or not rows:
        return []
    if len(rows) <= limit:
        return list(rows)
    if limit == 1:
        return [rows[len(rows) // 2]]
    picked = []
    last_index = -1
    span = len(rows) - 1
    for step in range(limit):
        index = round(step * span / (limit - 1))
        if index == last_index:
            continue
        picked.append(rows[index])
        last_index = index
    return picked


def _connection_role(slot: list) -> str:
    sdk = slot[3] if len(slot) > 3 else 0
    cluster = slot[4] if len(slot) > 4 else 0
    if cluster and not sdk:
        return "cluster"
    if sdk and not cluster:
        return "sdk"
    if cluster and sdk:
        return "mixed"
    return "sdk"


def _traffic_summary(requests: list[dict], paired: dict, loss_events: list[dict]) -> dict:
    """SDK is an application port to KV. Cluster is node-to-node or replication."""
    rows = {
        "sdk": {"requests": 0, "unanswered": 0, "no_reply": 0, "matched": 0, "retrans": 0, "lost": 0},
        "cluster": {"requests": 0, "unanswered": 0, "no_reply": 0, "matched": 0, "retrans": 0, "lost": 0},
    }
    unanswered = {id(msg) for msg in paired["unanswered"]}
    role_rtts: dict[str, list[float]] = {"sdk": [], "cluster": []}
    for msg in requests:
        role = traffic_role(msg.get("sport") or "", msg.get("dport") or "", msg.get("opcode") or "", msg.get("key") or "")
        rows[role]["requests"] += 1
        if not expects_reply(msg.get("opcode") or "", msg.get("snapshot_ack")):
            rows[role]["no_reply"] += 1
        elif id(msg) in unanswered:
            rows[role]["unanswered"] += 1
    for req, resp in paired["matched"]:
        if resp["time"] < req["time"]:
            continue
        role = traffic_role(req.get("sport") or "", req.get("dport") or "", req.get("opcode") or "", req.get("key") or "")
        rows[role]["matched"] += 1
        role_rtts[role].append(resp["time"] - req["time"])
    cluster_ends = cluster_endpoints(requests)
    for event in loss_events:
        role = flow_role(event.get("sport") or "", event.get("dport") or "", cluster_ends)
        if event.get("retrans"):
            rows[role]["retrans"] += 1
        if event.get("lost"):
            rows[role]["lost"] += 1
    for role, samples in role_rtts.items():
        summary = _rtt_summary(samples)
        rows[role]["median_ms"] = summary["rtt_median"]
        rows[role]["p99_ms"] = summary["rtt_p99"]
    return rows


def _client_rows(
    by_ip: dict[str, list[int]],
    by_conn: dict[tuple[str, str], list],
    ip_rtts: dict[str, list[float]],
    ip_over_100: Counter,
) -> list[dict]:
    """One row per client address. Ports stay on by_connection; this row is the machine."""
    connections: Counter = Counter()
    for ip, _port in by_conn:
        connections[ip] += 1
    rows = []
    for ip, counts in by_ip.items():
        requests, unanswered = counts
        summary = _rtt_summary(ip_rtts.get(ip) or [])
        rows.append({
            "ip": ip,
            "requests": requests,
            "unanswered": unanswered,
            "unanswered_pct": round(100 * unanswered / requests, 1) if requests else 0,
            "connections": connections[ip],
            "matched": summary["rtt_n"],
            "median_ms": summary["rtt_median"],
            "p99_ms": summary["rtt_p99"],
            "over_100": ip_over_100[ip],
        })
    rows.sort(key=lambda row: (row["unanswered"], row["requests"]), reverse=True)
    return rows


def _ten_gaps(messages: list[dict], capture_end: float, window: float, *, at_start: bool) -> list[dict]:
    """Up to ten missing calls, spaced across the file.

    Interior rows are preferred. Edge rows fill in only when fewer than ten
    calls sit away from the open or the close. A long list is not copied into
    the page.
    """
    rows = []
    for msg in messages:
        seconds = round(float(msg["time"]), 3)
        left = round(capture_end - float(msg["time"]), 3)
        if at_start:
            where = "start" if seconds <= window else "inside"
        elif left <= window:
            where = "end"
        elif seconds <= window:
            where = "start"
        else:
            where = "inside"
        # A missing reply was sent by src. A reply with no request was sent back to dst.
        requester = msg.get("dst") if at_start else msg.get("src")
        rows.append({
            "seconds": seconds,
            "seconds_left": left,
            "stream": str(msg.get("stream") or ""),
            "opaque": msg.get("opaque") or "",
            "opcode": opcode_name(msg.get("opcode") or ""),
            "key": msg.get("key") or "",
            "status": msg.get("status") or "",
            "requester": str(requester or ""),
            "at_edge": where != "inside",
            "where": where,
            "role": traffic_role(msg.get("sport") or "", msg.get("dport") or "", msg.get("opcode") or "", msg.get("key") or ""),
        })
    interior = [row for row in rows if not row["at_edge"]]
    edge = [row for row in rows if row["at_edge"]]
    interior.sort(key=lambda row: row["seconds"])
    edge.sort(key=lambda row: row["seconds"])
    chosen = _spread_rows(interior, 10)
    if len(chosen) < 10:
        chosen.extend(_spread_rows(edge, 10 - len(chosen)))
    chosen.sort(key=lambda row: row["seconds"])
    return chosen


_ERROR_WINDOW_SECONDS = 0.5


def _loss_marks(events: list[dict], ports: list[str]) -> list[tuple]:
    """Lost segments and lost acks. Capture duplicates are not errors."""
    portset = {str(port) for port in ports}
    marks = []
    for event in events:
        if event.get("time") is None or event.get("duplicate"):
            continue
        flags = []
        if event.get("lost"):
            flags.append("tcp.analysis.lost_segment")
        if event.get("ack"):
            flags.append("tcp.analysis.ack_lost_segment")
        if not flags:
            continue
        toward_client = str(event.get("sport") or "") in portset
        marks.append((
            float(event["time"]),
            str(event.get("stream") or ""),
            toward_client,
            tuple(flags),
        ))
    marks.sort()
    return marks


def _annotate_gap_errors(rows: list[dict], marks: list[tuple], window: float = _ERROR_WINDOW_SECONDS) -> list[dict]:
    """Mark a missing call when a TCP hole sits within half a second of it.

    Same stream is preferred. Otherwise any hole in that half-second still
    counts, because the chart shows the loss and the missing call together.
    """
    for row in rows:
        when = float(row["seconds"])
        near = [mark for mark in marks if abs(mark[0] - when) <= window]
        same = [mark for mark in near if mark[1] and mark[1] == str(row.get("stream") or "")]
        chosen = same or near
        if not chosen:
            row["error"] = ""
            row["error_filter"] = ""
            continue
        times = [mark[0] for mark in chosen]
        start = max(0.0, round(min(when, min(times)) - 0.05, 3))
        end = round(max(when, max(times)) + 0.05, 3)
        flags = []
        for mark in chosen:
            for flag in mark[3]:
                if flag not in flags:
                    flags.append(flag)
        flag_text = flags[0] if len(flags) == 1 else "(" + " || ".join(flags) + ")"
        # Errors to and from this machine, both directions, not every host in the file.
        hole = ["tcp.port == 11210"]
        requester = str(row.get("requester") or "")
        if requester:
            addr = "ipv6.addr" if ":" in requester else "ip.addr"
            hole.append(f"{addr} == {requester}")
        elif same:
            hole.append(f"tcp.stream == {row['stream']}")
        hole.append(f"frame.time_relative >= {start}")
        hole.append(f"frame.time_relative <= {end}")
        hole.append(flag_text)
        call = _call_filter(row)
        hole_text = " && ".join(hole)
        row["error"] = "possible"
        row["error_filter"] = f"{call} || ({hole_text})" if call else hole_text
    return rows


def _filter_quote(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _call_filter(row: dict) -> str:
    """The suspected call, so it shows in the same packet list as the hole."""
    pieces = []
    opaque = str(row.get("opaque") or "")
    if opaque:
        pieces.append(f"couchbase.opaque == {opaque}")
    key = str(row.get("key") or "")
    if key:
        pieces.append(f'couchbase.key.logical_key == "{_filter_quote(key)}"')
    if not pieces:
        return ""
    call = pieces[0] if len(pieces) == 1 else "(" + " || ".join(pieces) + ")"
    stream = str(row.get("stream") or "")
    if stream:
        return f"(tcp.stream == {stream} && {call})"
    return f"({call})"


def gap_counts(unanswered: list[dict], loss: dict) -> dict[str, int]:
    times: dict[str, list[float]] = loss.get("_times") or {}
    counts = {}
    for window in (0.05, 0.25, 1.0, 2.5):
        hits = 0
        for msg in unanswered:
            arr = times.get(str(msg["stream"]))
            if not arr:
                continue
            index = bisect.bisect_left(arr, msg["time"])
            if index < len(arr) and arr[index] <= msg["time"] + window:
                hits += 1
        counts[str(window)] = hits
    return counts


def sniff_delimiter(path: Path) -> str:
    first = path.read_bytes()[:8192].splitlines()[0] if path.stat().st_size else b""
    if b"\t" in first:
        return "\t"
    return ","


def is_number(text: str) -> bool:
    try:
        float(text)
        return True
    except ValueError:
        return False


def map_header(cells: list[str]) -> dict[str, int]:
    lookup = {cell.strip().lower(): index for index, cell in enumerate(cells)}
    found = {}
    for name, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in lookup:
                found[name] = lookup[alias]
                break
    return found


def split_joined(value: str, count: int) -> list[str]:
    if count <= 1:
        return [value]
    if value == "":
        return [""] * count
    parts = value.split(",")
    if len(parts) < count:
        parts.extend([""] * (count - len(parts)))
    return parts[:count]


def rows_to_messages(rows: list[list[str]], columns: dict[str, int] | None, kind: str) -> list[dict]:
    messages = []
    for cells in rows:
        def col(name: str, positional: int | None = None) -> str:
            if columns and name in columns and columns[name] < len(cells):
                return cells[columns[name]]
            if positional is not None and positional < len(cells):
                return cells[positional]
            return ""

        if columns:
            opaque_raw = col("opaque")
            opcode_raw = col("opcode")
            key_raw = col("key")
            status_raw = col("status")
            frame = col("frame")
            time_raw = col("time") or "0"
            stream = col("stream")
            src, sport, dst, dport = col("src"), col("sport"), col("dst"), col("dport")
            magic_raw = col("magic")
        elif kind == "request":
            # frame, time, stream, src, sport, dst, dport, opcode, opaque, key
            frame, time_raw, stream = cells[0], cells[1], cells[2]
            src, sport, dst, dport = cells[3], cells[4], cells[5], cells[6]
            opcode_raw, opaque_raw = cells[7], cells[8]
            key_raw = cells[9] if len(cells) > 9 else ""
            status_raw = ""
            magic_raw = ""
        else:
            # frame, time, stream, opcode, opaque, status
            frame, time_raw, stream = cells[0], cells[1], cells[2]
            opcode_raw, opaque_raw, status_raw = cells[3], cells[4], cells[5] if len(cells) > 5 else ""
            src = sport = dst = dport = key_raw = magic_raw = ""

        opaques = [part for part in opaque_raw.split(",") if part != ""] or [""]
        opcodes = split_joined(opcode_raw, len(opaques))
        keys = split_joined(key_raw, len(opaques))
        statuses = split_joined(status_raw, len(opaques))
        try:
            when = float(time_raw)
        except ValueError:
            when = 0.0
        magic = None
        if magic_raw and "," not in magic_raw:
            try:
                magic = int(magic_raw, 16) if str(magic_raw).lower().startswith("0x") else int(float(magic_raw))
            except ValueError:
                magic = None
        for index, opaque in enumerate(opaques):
            messages.append(
                {
                    "frame": frame,
                    "time": when,
                    "stream": stream,
                    "src": src,
                    "sport": sport,
                    "dst": dst,
                    "dport": dport,
                    "opcode": hex_int(opcodes[index], 2) if opcodes[index] else "",
                    "opaque": hex_int(opaque, 8) if opaque else "",
                    "key": keys[index],
                    "status": hex_int(statuses[index], 4) if statuses[index] else "",
                    "magic": magic if magic is not None else (0x80 if kind == "request" else 0x18),
                }
            )
    return messages


def load_table(path: Path) -> tuple[list[dict], list[dict], int]:
    delimiter = sniff_delimiter(path)
    lines = path.read_text(errors="replace").splitlines()
    rows = [line.split(delimiter) for line in lines if line.strip()]
    if not rows:
        raise SystemExit(f"{path} is empty")
    columns = None
    joined_rows = 0
    if not is_number(rows[0][0]):
        columns = map_header(rows[0])
        if "opaque" not in columns or "stream" not in columns:
            raise SystemExit(
                f"{path.name} has no tcp.stream and couchbase.opaque columns. "
                "Export those fields from tshark, or pass the pcap."
            )
        rows = rows[1:]
    kind = "request"
    if columns and "magic" in columns:
        requests, responses = [], []
        # Split after expansion by magic on each source row.
        req_rows, res_rows = [], []
        for cells in rows:
            magic = cells[columns["magic"]] if columns["magic"] < len(cells) else ""
            try:
                value = int(magic, 16) if str(magic).lower().startswith("0x") else int(float(magic or "0"))
            except ValueError:
                value = 0
            if value in CLIENT_RES_MAGIC:
                res_rows.append(cells)
            else:
                req_rows.append(cells)
        requests = rows_to_messages(req_rows, columns, "request")
        responses = rows_to_messages(res_rows, columns, "response")
        return requests, responses, 0
    width = len(rows[0])
    if columns:
        kind = "response" if "status" in columns and "src" not in columns else "request"
    elif width >= 10:
        kind = "request"
    elif width >= 6:
        kind = "response"
    else:
        raise SystemExit(
            f"{path.name} has {width} columns. Expected 10 (requests) or 6 (responses), "
            "or a header row naming tcp.stream and couchbase.opaque."
        )
    for cells in rows:
        opaque_index = columns["opaque"] if columns and "opaque" in columns else (8 if kind == "request" else 4)
        if opaque_index < len(cells) and "," in cells[opaque_index]:
            joined_rows += 1
    messages = rows_to_messages(rows, columns, kind)
    if kind == "request":
        return messages, [], joined_rows
    return [], messages, joined_rows


def load_tsv_pair(reqs_path: Path, resps_path: Path | None) -> tuple[list[dict], list[dict], int]:
    reqs, resps, joined = load_table(reqs_path)
    reqs, resps = _keep_kv(reqs), _keep_kv(resps)
    if resps_path is not None:
        extra_reqs, extra_resps, extra_joined = load_table(resps_path)
        # A response file can be mislabeled; keep whichever side it actually holds.
        if extra_resps:
            resps.extend(extra_resps)
        elif extra_reqs and not reqs:
            reqs = extra_reqs
        elif extra_reqs:
            log(f"{resps_path.name} looked like requests; expected a response export")
        joined += extra_joined
    if not reqs:
        raise SystemExit(f"No requests in {reqs_path}")
    if not resps:
        raise SystemExit(
            f"No responses for {reqs_path.name}. Pass --resps, or put the pcap in the same folder."
        )
    return reqs, resps, joined


def _completed_response(group: list[dict]) -> dict:
    """The call finishes at the last packet. Body is the sum of every packet."""
    done = dict(group[-1])
    done["body"] = sum(int(msg.get("body") or 0) for msg in group)
    done["response_packets"] = len(group)
    return done


def _pair_one_to_one(reqs: list[dict], resps: list[dict]) -> tuple[list, list, list, int]:
    matched = []
    unanswered = []
    resp_only = []
    i = j = 0
    while i < len(reqs) and j < len(resps):
        if resps[j]["time"] < reqs[i]["time"]:
            resp_only.append(resps[j])
            j += 1
            continue
        matched.append((reqs[i], resps[j]))
        i += 1
        j += 1
    unanswered.extend(reqs[i:])
    resp_only.extend(resps[j:])
    return matched, unanswered, resp_only, 0


def _pair_multi_response(reqs: list[dict], resps: list[dict]) -> tuple[list, list, list, int]:
    """Attach every following response to the request, until the next request.

    Statistics reuses one opaque for the whole reply, and the client sends the
    same opaque again on the next poll. Packets before the next request belong
    to this call. A packet before the first request stays unmatched.
    """
    matched = []
    unanswered = []
    resp_only = []
    extra = 0
    j = 0
    for index, req in enumerate(reqs):
        next_time = reqs[index + 1]["time"] if index + 1 < len(reqs) else None
        while j < len(resps) and resps[j]["time"] < req["time"]:
            resp_only.append(resps[j])
            j += 1
        group = []
        while j < len(resps) and (next_time is None or resps[j]["time"] < next_time):
            group.append(resps[j])
            j += 1
        if group:
            matched.append((req, _completed_response(group)))
            extra += len(group) - 1
        else:
            unanswered.append(req)
    resp_only.extend(resps[j:])
    return matched, unanswered, resp_only, extra


def pair_messages(requests: list[dict], responses: list[dict]) -> dict:
    """Pair on (tcp.stream, opaque) in time order.

    A response timestamp earlier than the request is an in-flight response
    from before that request, not a match for it. Opaque is per connection,
    so the stream stays in the key. A Statistics request owns every response
    packet on that key until the next request: those packets are one call.
    """
    by_req: dict[tuple[str, str], list[dict]] = defaultdict(list)
    by_res: dict[tuple[str, str], list[dict]] = defaultdict(list)
    no_reply = []
    for msg in requests:
        if not expects_reply(msg.get("opcode") or "", msg.get("snapshot_ack")):
            no_reply.append(msg)
            continue
        by_req[(msg["stream"], msg["opaque"])].append(msg)
    for msg in responses:
        by_res[(msg["stream"], msg["opaque"])].append(msg)

    matched = []
    unanswered = []
    resp_only = []
    continuations = 0
    for key in set(by_req) | set(by_res):
        reqs = sorted(by_req.get(key, []), key=lambda msg: (msg["time"], msg["frame"]))
        resps = sorted(by_res.get(key, []), key=lambda msg: (msg["time"], msg["frame"]))
        if reqs and all(is_multi_response(msg.get("opcode") or "") for msg in reqs):
            part_matched, part_unanswered, part_only, extra = _pair_multi_response(reqs, resps)
        else:
            part_matched, part_unanswered, part_only, extra = _pair_one_to_one(reqs, resps)
        matched.extend(part_matched)
        unanswered.extend(part_unanswered)
        resp_only.extend(part_only)
        continuations += extra
    unanswered.sort(key=lambda msg: (msg["time"], msg["frame"]))
    resp_only.sort(key=lambda msg: (msg["time"], msg["frame"]))
    return {
        "matched": matched,
        "unanswered": unanswered,
        "resp_only": resp_only,
        "no_reply": no_reply,
        "multi_response_continuations": continuations,
    }


def bin_width(capture_end: float) -> int:
    if capture_end <= 180:
        return 10
    if capture_end <= 1800:
        return 60
    return 300


def build_facts(
    requests: list[dict],
    responses: list[dict],
    paired: dict,
    *,
    source_label: str,
    pcap_names: list[str],
    capture_end: float,
    packet_count: int | None,
    magics: Counter | None,
    joined_rows: int,
    opcode_names: dict[str, str],
    loss: dict | None,
) -> dict:
    matched = paired["matched"]
    unanswered = paired["unanswered"]
    resp_only = paired["resp_only"]
    no_reply = paired.get("no_reply") or []
    rtts = [resp["time"] - req["time"] for req, resp in matched if resp["time"] >= req["time"]]
    max_rtt = max(rtts) if rtts else None
    window = max_rtt if max_rtt is not None else 1.0
    window_source = "maximum matched round trip" if max_rtt is not None else "1 second fallback, no matched round trip"

    def enrich(msg: dict, left: float | None = None) -> dict:
        row = {
            "frame": msg["frame"],
            "time": msg["time"],
            "time_s": fmt_secs(msg["time"]),
            "seconds_left": None if left is None else round(left, 3),
            "stream": msg["stream"],
            "src": msg["src"],
            "sport": msg["sport"],
            "dst": msg["dst"],
            "dport": msg["dport"],
            "opcode": msg["opcode"],
            "opcode_name": opcode_name(msg["opcode"], opcode_names),
            "opaque": msg["opaque"],
            "key": msg["key"],
            "status": msg.get("status") or "",
            "status_name": status_name(msg.get("status") or ""),
        }
        return row

    unanswered_rows = [enrich(msg, capture_end - msg["time"]) for msg in unanswered]
    resp_only_rows = [enrich(msg, capture_end - msg["time"]) for msg in resp_only]
    start_rows = [row for row in resp_only_rows if row["time"] <= window]
    end_rows = [row for row in unanswered_rows if (row["seconds_left"] or 0) <= window]
    end_rows_1s = [row for row in unanswered_rows if (row["seconds_left"] or 0) <= 1.0]
    opening_rows = [
        row for row in unanswered_rows
        if row["time"] <= window and (row["seconds_left"] or 0) > window
    ]
    interior_unanswered = [
        row for row in unanswered_rows
        if row["time"] > window and (row["seconds_left"] or 0) > window
    ]
    interior_resp_only = [row for row in resp_only_rows if row["time"] > window]

    width = bin_width(capture_end)
    bins = int(capture_end // width) + 1 if capture_end > 0 else 1
    histogram = [
        {"start": i * width, "end": (i + 1) * width, "unanswered": 0, "resp_only": 0, "matched": 0}
        for i in range(bins)
    ]

    def bin_index(when: float) -> int:
        return min(bins - 1, max(0, int(when // width)))

    for row in unanswered_rows:
        histogram[bin_index(row["time"])]["unanswered"] += 1
    for row in resp_only_rows:
        histogram[bin_index(row["time"])]["resp_only"] += 1
    for req, _resp in matched:
        histogram[bin_index(req["time"])]["matched"] += 1

    frame_counts = Counter(msg["frame"] for msg in requests)
    multi_frames = sum(1 for count in frame_counts.values() if count > 1)
    extra_messages = sum(count - 1 for count in frame_counts.values() if count > 1)
    empty_keys = sum(1 for msg in requests if not msg.get("key"))

    families = Counter(key_family(row["key"]) for row in unanswered_rows)
    dominant = families.most_common(1)[0][0] if families else ""
    other_rows = [row for row in unanswered_rows if key_family(row["key"]) != dominant]
    dupes = [
        {"key": key, "count": count}
        for key, count in Counter(row["key"] for row in unanswered_rows if row["key"]).most_common()
        if count > 1
    ]

    stream_reqs = Counter(msg["stream"] for msg in requests)
    stream_un = Counter(row["stream"] for row in unanswered_rows)
    endpoints: dict[str, dict] = {}
    for msg in requests:
        endpoints.setdefault(
            msg["stream"],
            {"src": msg["src"], "sport": msg["sport"], "dst": msg["dst"], "dport": msg["dport"]},
        )
    streams = []
    for stream, req_count in stream_reqs.most_common():
        end = endpoints.get(stream, {})
        un = stream_un[stream]
        streams.append(
            {
                "stream": stream,
                "src": end.get("src", ""),
                "sport": end.get("sport", ""),
                "dst": end.get("dst", ""),
                "dport": end.get("dport", ""),
                "requests": req_count,
                "unanswered": un,
                "share": (un / req_count) if req_count else 0,
            }
        )

    resp_streams_by_opaque: dict[str, set[str]] = defaultdict(set)
    for msg in responses:
        resp_streams_by_opaque[msg["opaque"]].add(msg["stream"])
    cross = []
    for row in unanswered_rows:
        others = resp_streams_by_opaque.get(row["opaque"], set()) - {row["stream"]}
        if others:
            cross.append(
                {
                    "opaque": row["opaque"],
                    "request_stream": row["stream"],
                    "response_streams": sorted(others),
                    "key": row["key"],
                    "time_s": row["time_s"],
                    "opcode_name": row["opcode_name"],
                }
            )

    client = Counter((msg["src"], msg["sport"]) for msg in requests).most_common(1)
    ports = couchbase_ports(requests)

    tcp = None
    if loss and loss.get("available"):
        near = gap_counts(unanswered, loss)
        tcp = {
            "ports": loss["ports"],
            "lost_segments": loss["lost_segments"],
            "retransmissions": loss["retransmissions"],
            "ack_lost_segments": loss["ack_lost_segments"],
            "lost_by_stream": loss["lost_by_stream"],
            "client_to_server": loss["client_to_server"],
            "server_to_client": loss["server_to_client"],
            "unanswered_near_gap": near,
        }

    magic_rows = []
    if magics:
        for magic, count in magics.most_common():
            magic_rows.append(
                {
                    "magic": f"0x{magic:02x}",
                    "role": MAGIC_ROLE.get(magic, "other"),
                    "messages": count,
                }
            )

    return {
        "source": source_label,
        "pcap_files": pcap_names,
        "capture_seconds": capture_end,
        "packet_count": packet_count,
        "client": {"ip": client[0][0][0], "port": client[0][0][1]} if client else {},
        "server": couchbase_server(requests),
        "couchbase_ports": ports,
        "counts": {
            "request_messages": len(requests),
            "request_frames": len(frame_counts),
            "multi_message_frames": multi_frames,
            "extra_messages_in_those_frames": extra_messages,
            "joined_tsv_rows": joined_rows,
            "empty_keys": empty_keys,
            "response_messages": len(responses),
            "matched": len(matched),
            "unanswered_requests": len(unanswered_rows),
            "no_reply_messages": len(no_reply),
            "unique_unanswered_keys": len({row["key"] for row in unanswered_rows if row["key"]}),
            "responses_without_request": len(resp_only_rows),
            "multi_response_continuations": int(paired.get("multi_response_continuations") or 0),
        },
        "rtt_seconds": {
            "median": statistics.median(rtts) if rtts else None,
            "mean": statistics.mean(rtts) if rtts else None,
            "p90": percentile(rtts, 0.90),
            "p95": percentile(rtts, 0.95),
            "p99": percentile(rtts, 0.99),
            "max": max_rtt,
            "samples": len(rtts),
        },
        "edge": {
            "window_seconds": window,
            "window_source": window_source,
            "start_responses": len(start_rows),
            "end_requests": len(end_rows),
            "end_requests_within_1s": len(end_rows_1s),
            "opening_requests": len(opening_rows),
            "interior_unanswered": len(interior_unanswered),
            "interior_responses_without_request": len(interior_resp_only),
            "start_examples": start_rows[:8],
            "closing_examples": end_rows[:8],
            "end_examples": end_rows_1s[:8],
        },
        "bin_seconds": width,
        "bins": histogram,
        "magics": magic_rows,
        "opcodes_requests": _opcode_counter(requests, opcode_names),
        "opcodes_unanswered": _opcode_counter(unanswered, opcode_names),
        "opcodes_resp_only": _opcode_counter(resp_only, opcode_names),
        "status_responses": _status_counter(responses),
        "families": [{"family": name, "count": count} for name, count in families.most_common()],
        "dominant_family": dominant,
        "duplicate_keys": dupes,
        "streams": streams,
        "cross_stream_opaque": cross[:8],
        "cross_stream_opaque_count": len(cross),
        "other_keys": other_rows,
        "unanswered": unanswered_rows,
        "tcp": tcp,
    }


def _opcode_counter(messages: list[dict], learned: dict[str, str]) -> list[dict]:
    counts = Counter(msg["opcode"] for msg in messages)
    return [
        {"opcode": opcode, "name": opcode_name(opcode, learned), "count": count}
        for opcode, count in counts.most_common()
    ]


def _status_counter(messages: list[dict]) -> list[dict]:
    counts = Counter(msg.get("status") or "" for msg in messages)
    rows = []
    for status, count in counts.most_common():
        if not status:
            continue
        rows.append({"status": status, "name": status_name(status), "count": count})
    return rows


def _endpoint_phrase(facts: dict) -> str:
    client = facts.get("client") or {}
    server = facts.get("server") or {}
    if not client or not server:
        return "The client and server addresses were not both in the export."
    return (
        f"Couchbase is `{server_label(server)}` port `{server.get('port')}`. "
        f"Client requests are from `{client['ip']}`."
    )


def _stream_phrase(stream: dict) -> str:
    left = f"`{stream['src']}:{stream['sport']}`" if stream.get("src") else "an unknown client port"
    right = f"`{stream['dst']}:{stream['dport']}`" if stream.get("dst") else "the server"
    return f"{left} → {right}"


def unanswered_table(rows: list[dict]) -> str:
    table_rows = []
    for row in rows:
        table_rows.append(
            [
                row["time_s"],
                f"{row['seconds_left']:.3f}" if row["seconds_left"] is not None else "",
                row["frame"],
                row["stream"],
                row["opcode_name"],
                backtick(row["key"]) if row["key"] else "",
            ]
        )
    return md_table(
        ["Time (s)", "Left (s)", "Frame", "Stream", "Op", "Key"],
        table_rows,
    )


def render_summary(facts: dict) -> str:
    counts = facts["counts"]
    edge = facts["edge"]
    rtt = facts["rtt_seconds"]
    lines: list[str] = []
    lines.append("# Orphaned Couchbase requests")
    lines.append("")
    lines.append(f"Source: `{facts['source']}`")
    label = server_label(facts.get("server"))
    if label:
        lines.append("")
        lines.append(f"Couchbase: `{label}` port `{facts['server'].get('port')}`.")
    if facts.get("pcap_files"):
        shown = ", ".join(f"`{name}`" for name in facts["pcap_files"])
        lines.append("")
        lines.append(f"Capture file{'s' if len(facts['pcap_files']) > 1 else ''}: {shown}.")
    lines.append("")
    lines.append(
        f"**{counts['unanswered_requests']} client requests have no matching response** "
        f"({counts['unique_unanswered_keys']} document keys). "
        f"**{counts['responses_without_request']} responses have no matching request.**"
    )
    folded = counts.get("multi_response_continuations") or 0
    if folded:
        lines.append("")
        lines.append(
            f"A Statistics request is answered by many packets that repeat one opaque "
            f"(vbucket-seqno does this, one line per vBucket). "
            f"**{folded}** of those continuation packets belong to the request in front of them. "
            f"They are one call, finished at the last packet, not responses without a request."
        )
    lines.append("")
    lines.append(
        f"Matched calls return in {fmt_ms(rtt['median']) or 'an unknown time'}"
        + (f" (maximum {fmt_ms(rtt['max'])})" if rtt["max"] is not None else "")
        + f". The in-flight window is {fmt_ms(edge['window_seconds'])} ({edge['window_source']}). "
        f"Inside that window there "
        f"{'is' if edge['start_responses'] == 1 else 'are'} "
        f"**{edge['start_responses']}** response"
        f"{'' if edge['start_responses'] == 1 else 's'} whose request was sent before the recording started, and "
        f"**{edge['end_requests']}** request"
        f"{'' if edge['end_requests'] == 1 else 's'} whose response would have arrived after it stopped "
        f"(**{edge['end_requests_within_1s']}** if that end window is widened to 1 second). "
        + (
            f"**{edge.get('opening_requests', 0)}** requests in that opening window have no reply in the file. "
            if edge.get("opening_requests")
            else ""
        )
        + f"The other **{edge['interior_unanswered']}** unanswered requests and "
        f"**{edge['interior_responses_without_request']}** unmatched responses sit further inside the file."
    )
    traffic = facts.get("traffic") or {}
    cluster = traffic.get("cluster") or {}
    sdk = traffic.get("sdk") or {}
    if cluster.get("requests") or sdk.get("requests"):
        lines.append("")
        lines.append(
            f"Cluster (node-to-node, DCP, and replication meta): **{cluster.get('requests', 0)}** requests, "
            f"**{cluster.get('unanswered', 0)}** without a reply, median {fmt_ms((cluster.get('median_ms') or 0) / 1000) if cluster.get('median_ms') is not None else 'n/a'}, "
            f"**{cluster.get('retrans', 0)}** retransmissions. "
            f"**{cluster.get('no_reply', 0)}** of the cluster messages are DCP stream data and do not expect a reply, so they are not lost responses. "
            f"SDK (an application port to 11210): **{sdk.get('requests', 0)}** requests, "
            f"**{sdk.get('unanswered', 0)}** without a reply, median {fmt_ms((sdk.get('median_ms') or 0) / 1000) if sdk.get('median_ms') is not None else 'n/a'}, "
            f"**{sdk.get('retrans', 0)}** retransmissions."
        )
    lines.append("")
    lines.append("## What was captured")
    lines.append("")
    if facts.get("packet_count") or facts.get("capture_seconds"):
        bits = []
        if facts.get("packet_count"):
            bits.append(f"{facts['packet_count']:,} packets")
        if facts.get("capture_seconds"):
            bits.append(f"{facts['capture_seconds']:.3f} seconds")
        lines.append("The recording is " + " and ".join(bits) + ".")
        lines.append("")
    lines.append(_endpoint_phrase(facts))
    lines.append("")
    lines.append(
        f"Client requests: **{counts['request_messages']}** messages in "
        f"**{counts['request_frames']}** frames. "
        f"Client responses: **{counts['response_messages']}** messages. "
        f"Matched on `tcp.stream` + `couchbase.opaque`: **{counts['matched']}**."
    )
    if facts["magics"]:
        lines.append("")
        lines.append(
            md_table(
                ["Magic", "Role", "Messages"],
                [[row["magic"], row["role"], str(row["messages"])] for row in facts["magics"]],
            )
        )
        lines.append("")
        lines.append(
            "Server-initiated messages (magic `0x82` / `0x83`) are counted above and are not part of the client pairing."
        )
    lines.append("")
    lines.append("## How the requests and responses were matched")
    lines.append("")
    lines.append(
        "An operation is the pair `tcp.stream` and `couchbase.opaque`. "
        "The same opaque on two streams is two connections, each with its own counter. "
        "Messages on a pair are matched in time order. A response timestamp earlier than the request stays unmatched: "
        "it was already on the wire, and it is not the answer to the later request."
    )
    lines.append("")
    lines.append(
        "The same comparison in a spreadsheet is column K on the request sheet, `=C1&\"-\"&I1` "
        "(stream and opaque), column G on the response sheet, `=C1&\"-\"&E1`, and "
        "`=COUNTIF(Responses!G:G, K1)` on the request sheet. A count of 0 is an unanswered request."
    )
    lines.append("")
    lines.append(
        "Request columns are frame, time, tcp.stream, source, source port, destination, destination port, "
        "opcode, opaque, key. Response columns are frame, time, tcp.stream, opcode, opaque, status."
    )
    if counts["empty_keys"] == counts["request_messages"] and counts["request_messages"]:
        lines.append("")
        lines.append(
            "Every request key in this export is empty. With collections the document id is "
            "`couchbase.key.logical_key`, and `couchbase.key` itself is blank. "
            "Pass the pcap to fill the keys in."
        )
    elif counts["empty_keys"]:
        lines.append("")
        lines.append(
            f"{counts['empty_keys']} requests have no document key. "
            "Where a collection logical key was present, that value is the key used here."
        )
    if counts["multi_message_frames"]:
        lines.append("")
        lines.append(
            f"**{counts['multi_message_frames']}** frames contain more than one client request "
            f"({counts['extra_messages_in_those_frames']} extra messages). "
            "A field export joins those opcodes and opaques with commas in one cell. "
            "A single `COUNTIF` on the joined cell looks for one id that no response row equals. "
            "Each message is matched on its own opaque here."
        )
    if counts["joined_tsv_rows"]:
        lines.append("")
        lines.append(
            f"The request export had {counts['joined_tsv_rows']} rows with a comma-joined opaque. Those rows were split before the match."
        )
    lines.append("")
    lines.append("## Round trip and the edges of the file")
    lines.append("")
    if rtt["samples"]:
        lines.append(
            md_table(
                ["", "Round trip"],
                [
                    ["Median", fmt_ms(rtt["median"])],
                    ["Mean", fmt_ms(rtt["mean"])],
                    ["90th percentile", fmt_ms(rtt["p90"])],
                    ["95th percentile", fmt_ms(rtt["p95"])],
                    ["99th percentile", fmt_ms(rtt["p99"])],
                    ["Maximum", fmt_ms(rtt["max"])],
                    ["Matched samples", str(rtt["samples"])],
                ],
            )
        )
    else:
        lines.append("No request had a later response, so there is no round-trip sample. The edge window is 1 second.")
    lines.append("")
    lines.append(
        "A capture slices in-flight work at both ends. A response whose request was sent before the tap opened "
        "has no request in the file. A request whose answer would arrive after the tap closed has no response in the file. "
        f"The window used for that slice is {fmt_ms(edge['window_seconds'])}."
    )
    lines.append("")
    edge_rows = [
        [
            "Start",
            "Response whose request was sent before the capture opened",
            str(edge["start_responses"]),
        ],
        [
            "End",
            f"Request still in flight when the capture closed (within {fmt_ms(edge['window_seconds'])})",
            str(edge["end_requests"]),
        ],
        [
            "End, 1 second",
            "Same cutoff widened to 1 second",
            str(edge["end_requests_within_1s"]),
        ],
        [
            "Interior",
            "Unanswered requests with more than the in-flight window left in the file",
            str(edge["interior_unanswered"]),
        ],
        [
            "Interior",
            "Responses with no request after the opening window",
            str(edge["interior_responses_without_request"]),
        ],
    ]
    lines.append(md_table(["Edge", "What it is", "Count"], edge_rows))
    if edge["start_examples"]:
        lines.append("")
        lines.append("Responses in the opening window:")
        lines.append("")
        lines.append(
            md_table(
                ["Time (s)", "Frame", "Stream", "Op", "Opaque", "Status"],
                [
                    [
                        row["time_s"],
                        row["frame"],
                        row["stream"],
                        row["opcode_name"],
                        backtick(row["opaque"]),
                        row["status"] or "",
                    ]
                    for row in edge["start_examples"]
                ],
            )
        )
    if edge["end_examples"]:
        lines.append("")
        lines.append("Requests in the last second, including the closing window:")
        lines.append("")
        lines.append(
            md_table(
                ["Time (s)", "Left (s)", "Frame", "Stream", "Op", "Key"],
                [
                    [
                        row["time_s"],
                        f"{row['seconds_left']:.3f}",
                        row["frame"],
                        row["stream"],
                        row["opcode_name"],
                        backtick(row["key"]) if row["key"] else "",
                    ]
                    for row in edge["end_examples"]
                ],
            )
        )
    if facts["bins"]:
        lines.append("")
        lines.append(
            f"Counts by {facts['bin_seconds']}-second slice. The interior rows are spread through the recording, next to the matched traffic."
        )
        lines.append("")
        lines.append(
            md_table(
                ["Seconds", "Unanswered requests", "Responses with no request", "Matched requests"],
                [
                    [
                        f"{row['start']}–{row['end']}",
                        str(row["unanswered"]),
                        str(row["resp_only"]),
                        str(row["matched"]),
                    ]
                    for row in facts["bins"]
                    if row["unanswered"] or row["resp_only"] or row["matched"]
                ],
            )
        )
    resp_only_ops = facts["opcodes_resp_only"]
    if resp_only_ops:
        lines.append("")
        bits = ", ".join(f"{row['count']} {row['name']}" for row in resp_only_ops[:6])
        lines.append(f"Responses with no request, by opcode: {bits}.")

    tcp = facts.get("tcp")
    lines.append("")
    lines.append("## Packets missing from the recording")
    lines.append("")
    if not tcp:
        lines.append(
            "This run did not read a pcap, so TCP lost-segment markers were not counted. "
            "Pass the capture file to measure holes next to the unanswered requests."
        )
    elif tcp["lost_segments"] == 0:
        lines.append(
            f"tshark reported no lost-segment markers on port {', '.join(tcp['ports'])}. "
            f"Retransmissions: {tcp['retransmissions']}."
        )
    else:
        ports = ", ".join(tcp["ports"])
        lines.append(
            f"On port {ports} tshark reports **{tcp['lost_segments']:,}** lost-segment markers, "
            f"**{tcp['retransmissions']:,}** retransmissions, and "
            f"**{tcp['ack_lost_segments']:,}** packets acknowledging a segment the capture never saw."
        )
        lines.append("")
        lines.append(
            f"The holes run both ways: **{tcp['client_to_server']:,}** client → server and "
            f"**{tcp['server_to_client']:,}** server → client. "
            "A hole toward the server leaves a response with no request in the file. "
            "A hole toward the client leaves a request with no response."
        )
        top_stream = next(iter(tcp["lost_by_stream"]), None)
        if top_stream is not None:
            lines.append("")
            lines.append(
                f"Stream `{top_stream}` has {tcp['lost_by_stream'][top_stream]:,} of those lost-segment markers."
            )
        near = tcp["unanswered_near_gap"]
        lines.append("")
        lines.append("Unanswered requests with a lost-segment marker on the same stream after the request:")
        lines.append("")
        lines.append(
            md_table(
                ["Window after the request", "Unanswered requests with a gap"],
                [
                    ["50 ms", f"{near.get('0.05', 0)} of {counts['unanswered_requests']}"],
                    ["250 ms", f"{near.get('0.25', 0)} of {counts['unanswered_requests']}"],
                    ["1 s", f"{near.get('1.0', 0)} of {counts['unanswered_requests']}"],
                    ["2.5 s", f"{near.get('2.5', 0)} of {counts['unanswered_requests']}"],
                ],
            )
        )
        if tcp["lost_segments"] and tcp["retransmissions"] * 20 < tcp["lost_segments"]:
            lines.append("")
            lines.append(
                "Retransmissions are rare next to those holes, which fits packets the recorder did not see."
            )

    lines.append("")
    lines.append("## What the unanswered requests are")
    lines.append("")
    if facts["opcodes_unanswered"]:
        lines.append(
            md_table(
                ["Opcode", "Name", "Unanswered"],
                [
                    [backtick(row["opcode"]), row["name"], str(row["count"])]
                    for row in facts["opcodes_unanswered"]
                ],
            )
        )
    if facts["opcodes_requests"]:
        lines.append("")
        sent = ", ".join(f"{row['count']:,} {row['name']}" for row in facts["opcodes_requests"][:8])
        lines.append(f"The client sent {sent}.")
    if facts["status_responses"]:
        lines.append("")
        statuses = ", ".join(
            f"**{row['count']:,}** `{row['status']}` ({row['name']})" for row in facts["status_responses"][:6]
        )
        lines.append(f"Responses that are present: {statuses}.")
    if facts["families"]:
        lines.append("")
        lines.append(
            md_table(
                ["Key family", "Unanswered requests"],
                [[backtick(row["family"]), str(row["count"])] for row in facts["families"][:12]],
            )
        )
    if facts["duplicate_keys"]:
        lines.append("")
        lines.append("Document keys requested more than once with no response either time:")
        lines.append("")
        for row in facts["duplicate_keys"]:
            lines.append(f"- {backtick(row['key'])} ({row['count']} times)")
    if facts["streams"]:
        lines.append("")
        lines.append("Connections with at least one client request:")
        lines.append("")
        shown = [row for row in facts["streams"] if row["unanswered"]] or facts["streams"][:8]
        lines.append(
            md_table(
                ["Stream", "Path", "Requests", "Unanswered", "Share"],
                [
                    [
                        row["stream"],
                        _stream_phrase(row),
                        str(row["requests"]),
                        str(row["unanswered"]),
                        f"{row['share'] * 100:.1f}%",
                    ]
                    for row in shown
                ],
            )
        )
        quiet = [row["stream"] for row in facts["streams"] if not row["unanswered"]]
        if quiet:
            lines.append("")
            lines.append(
                "Streams with requests and no unanswered ones: "
                + ", ".join(f"`{stream}`" for stream in quiet)
                + "."
            )
    if facts["cross_stream_opaque_count"]:
        lines.append("")
        example = facts["cross_stream_opaque"][0]
        lines.append(
            f"{facts['cross_stream_opaque_count']} unanswered opaque value"
            f"{'' if facts['cross_stream_opaque_count'] == 1 else 's'} also appear on a response in another stream. "
            f"Example: opaque `{example['opaque']}` is an unanswered {example['opcode_name']} on stream "
            f"`{example['request_stream']}` at t={example['time_s']}"
            + (f" for {backtick(example['key'])}" if example["key"] else "")
            + f", and a different connection (stream {', '.join('`'+s+'`' for s in example['response_streams'])}) "
            "used the same opaque. The stream keeps them apart."
        )
    other = facts["other_keys"]
    dominant = facts["dominant_family"]
    if other and dominant and dominant != "(no key)":
        lines.append("")
        lines.append(
            f"## Keys outside `{dominant}`"
        )
        lines.append("")
        lines.append(
            f"The other {counts['unanswered_requests'] - len(other)} unanswered requests are `{dominant}`. These are the rest."
        )
        lines.append("")
        lines.append(
            md_table(
                ["Time (s)", "Left (s)", "Stream", "Op", "Key"],
                [
                    [
                        row["time_s"],
                        f"{row['seconds_left']:.3f}",
                        row["stream"],
                        row["opcode_name"],
                        backtick(row["key"]) if row["key"] else "",
                    ]
                    for row in other
                ],
            )
        )
    lines.append("")
    lines.append("## All unanswered requests")
    lines.append("")
    if facts["unanswered"]:
        lines.append("Sorted by time. Left is seconds of capture remaining after the request.")
        lines.append("")
        lines.append(unanswered_table(facts["unanswered"]))
    else:
        lines.append("Every client request had a later response on the same stream and opaque.")
    lines.extend(_next_section(facts))
    lines.append("")
    return "\n".join(lines)


def _body_peaks(charts: dict) -> tuple[int, int | None, int, int | None, int]:
    max_in = max_out = large = 0
    sec_in = sec_out = None
    for row in (charts.get("buckets") or {}).get("1") or []:
        large += int(row.get("body_large") or 0)
        if int(row.get("body_in_max") or 0) > max_in:
            max_in = int(row["body_in_max"])
            sec_in = row.get("t")
        if int(row.get("body_out_max") or 0) > max_out:
            max_out = int(row["body_out_max"])
            sec_out = row.get("t")
    return max_in, sec_in, max_out, sec_out, large


def next_questions(facts: dict, charts: dict | None = None) -> list[dict]:
    """Questions a support engineer can ask from counts already in hand."""
    steps: list[dict] = []
    traffic = (charts or {}).get("traffic") or {}
    cluster = traffic.get("cluster") or {}
    sdk = traffic.get("sdk") or {}
    if cluster.get("requests") and sdk.get("requests"):
        steps.append(
            {
                "title": "Separate cluster replication from application calls",
                "text": (
                    f"Cluster: {cluster['requests']} requests, {cluster['unanswered']} without a reply, "
                    f"median {cluster.get('median_ms')} ms, {cluster.get('retrans')} retransmissions. "
                    f"SDK: {sdk['requests']} requests, {sdk['unanswered']} without a reply, "
                    f"median {sdk.get('median_ms')} ms, {sdk.get('retrans')} retransmissions. "
                    "DCP and meta replication are cluster. An application port to 11210 is SDK. "
                    "Do not read the cluster missing-reply count as application timeouts."
                ),
            }
        )
    edge = facts["edge"]
    opening = edge.get("opening_requests") or 0
    if opening:
        steps.append(
            {
                "title": "The recording opened in the middle of live calls",
                "text": (
                    f"{opening} requests in the first {edge['window_seconds']:.3f}s have no reply, and "
                    f"{edge['start_responses']} replies in that window have no request. "
                    "On a replication connection the opaque counts upward. The missing reply and the extra reply "
                    "are neighbors that were already on the wire when the file started. "
                    "Read later matched calls on that stream before treating the command as failed."
                ),
            }
        )
    counts = facts["counts"]
    streams = facts.get("streams") or []
    client_ip = (facts.get("client") or {}).get("ip") or ""
    sources = {row.get("src") for row in streams if row.get("src")}
    if len(sources) == 1 and client_ip and len(streams) > 1:
        top = streams[0]
        steps.append(
            {
                "title": "One client, many connections",
                "text": (
                    f"All {counts['request_messages']} requests come from {client_ip}. "
                    f"The busiest connection is {client_ip}:{top.get('sport')} "
                    f"(stream {top.get('stream')}), with {top.get('requests')} requests and "
                    f"{top.get('unanswered')} unanswered. Ask what that connection does that the others do not."
                ),
            }
        )
    tcp = facts.get("tcp") or {}
    near = tcp.get("unanswered_near_gap") or {}
    if tcp and counts["unanswered_requests"]:
        near_250 = near.get("0.25")
        gap_clause = (
            f" {near_250} of {counts['unanswered_requests']} unanswered requests "
            "sit within 250 ms of a gap on the same stream."
            if near_250 is not None
            else ""
        )
        steps.append(
            {
                "title": "Ask whether the recorder dropped packets",
                "text": (
                    f"Port {', '.join(tcp.get('ports') or [])} shows {tcp.get('lost_segments')} lost-segment markers "
                    f"and {tcp.get('retransmissions')} retransmissions."
                    f"{gap_clause} "
                    "Ask about the span port, snap length, and whether the capture disk kept up. "
                    "Do not treat the whole unanswered set as Couchbase timeouts."
                ),
            }
        )
    if edge["interior_unanswered"] > edge["end_requests"] + edge["start_responses"]:
        steps.append(
            {
                "title": "The open and close of the file are not the missing calls",
                "text": (
                    f"{edge['start_responses']} "
                    f"{'response has' if edge['start_responses'] == 1 else 'responses have'} "
                    "no request at the start, and "
                    f"{edge['end_requests']} "
                    f"{'request is' if edge['end_requests'] == 1 else 'requests are'} "
                    "still in flight at the end. "
                    f"{edge['interior_unanswered']} unanswered requests sit further inside the file."
                ),
            }
        )
    families = facts.get("families") or []
    dominant = facts.get("dominant_family") or ""
    if dominant and families and counts["unanswered_requests"]:
        fam_count = families[0]["count"]
        if fam_count >= 5 and fam_count / counts["unanswered_requests"] >= 0.5:
            steps.append(
                {
                    "title": f"Most missing replies are {dominant}",
                    "text": (
                        f"{fam_count} of {counts['unanswered_requests']} unanswered requests are {dominant}. "
                        "Ask the application owner whether that read is large, retried, or sent to a replica."
                    ),
                }
            )
    if not charts:
        return steps[:6]
    slow = charts.get("slow_ms") or {}
    overall = charts.get("rtt_overall_ms") or {}
    if slow.get("over_100"):
        sdk_ms = sdk.get("median_ms")
        cluster_ms = cluster.get("median_ms")
        if sdk_ms is not None and cluster_ms is not None:
            pace = f"SDK median is {sdk_ms} ms. Cluster median is {cluster_ms} ms. "
        else:
            pace = f"The median matched call is {overall.get('rtt_median')} ms. "
        steps.append(
            {
                "title": "The slow calls are a short tail",
                "text": (
                    f"{pace}"
                    f"{slow.get('over_100')} calls took 100 ms or more"
                    f" and {slow.get('over_250')} took 250 ms or more. "
                    f"The slowest matched call is {overall.get('rtt_max')} ms. "
                    "Compare those seconds with the body-length chart before calling the server slow."
                ),
            }
        )
    max_in, sec_in, max_out, sec_out, large = _body_peaks(charts)
    if max_in or max_out:
        steps.append(
            {
                "title": "Check the large documents",
                "text": (
                    f"The largest request body is {max_in:,} bytes"
                    + (f" at {sec_in}s" if sec_in is not None else "")
                    + f". The largest reply is {max_out:,} bytes"
                    + (f" at {sec_out}s" if sec_out is not None else "")
                    + f". {large} messages are 1 MB (1,048,576 bytes) or larger. "
                    "Ask whether a value that size is expected on that key, and whether it lines up with a slow second."
                ),
            }
        )
    return steps[:6]


def _next_section(facts: dict) -> list[str]:
    steps = facts.get("next_steps")
    if steps is None:
        steps = next_questions(facts)
    lines = ["", "## Next questions and steps", ""]
    if not steps:
        lines.append("No further question stood out from these counts.")
        return lines
    for index, step in enumerate(steps, 1):
        lines.append(f"{index}. **{step['title']}.** {step['text']}")
        lines.append("")
    return lines


def chart_digest(charts: dict) -> list[str]:
    """Extra aggregates for the local model. Numbers only, already counted."""
    lines = ["Slow calls and body size:"]
    slow = charts.get("slow_ms") or {}
    overall = charts.get("rtt_overall_ms") or {}
    lines.append(
        "Matched calls: {matched}. At or over 50 ms: {over_50}. At or over 100 ms: {over_100}. "
        "At or over 250 ms: {over_250}.".format(
            matched=slow.get("matched"),
            over_50=slow.get("over_50"),
            over_100=slow.get("over_100"),
            over_250=slow.get("over_250"),
        )
    )
    lines.append(
        "Blended round trip ms median/p90/p95/p99/max (mixes SDK and cluster): "
        f"{overall.get('rtt_median')}, {overall.get('rtt_p90')}, {overall.get('rtt_p95')}, "
        f"{overall.get('rtt_p99')}, {overall.get('rtt_max')}"
    )
    traffic = charts.get("traffic") or {}
    if traffic:
        lines.append("Read SDK and cluster speeds separately. The blended median hides the slower side.")
        for role, row in traffic.items():
            lines.append(
                f"- {role}: requests {row.get('requests')} matched {row.get('matched')} "
                f"unanswered {row.get('unanswered')} no_reply {row.get('no_reply')} "
                f"median_ms {row.get('median_ms')} p99_ms {row.get('p99_ms')} "
                f"retrans {row.get('retrans')}"
            )
    bands = [row for row in charts.get("rtt_histogram") or [] if row.get("count")]
    if bands:
        lines.append(
            "Response-time bands (ms, count/sdk/cluster): "
            + ", ".join(
                f"{row['label']}={row['count']}/{row.get('sdk', 0)}/{row.get('cluster', 0)}"
                for row in bands
            )
        )
    max_in, sec_in, max_out, sec_out, large = _body_peaks(charts)
    lines.append(
        f"Largest request body: {max_in} bytes at {sec_in}s. "
        f"Largest reply body: {max_out} bytes at {sec_out}s. "
        f"Messages at or over 1 MB: {large}. "
        "Total body length is extras + key + value."
    )
    client_rows = charts.get("clients") or charts.get("by_requester_ip") or []
    lines.append(f"Clients: {len(client_rows)} addresses.")
    lines.append("Clients with the most unanswered requests:")
    worst_clients = sorted(
        client_rows,
        key=lambda row: (row.get("unanswered") or 0, row.get("requests") or 0),
        reverse=True,
    )[:8]
    for row in worst_clients:
        lines.append(
            f"- {row.get('ip')}: {row.get('requests')} requests, {row.get('unanswered')} unanswered"
            + (f", {row.get('unanswered_pct')}%" if row.get("unanswered_pct") is not None else "")
            + (f", median {row.get('median_ms')} ms" if row.get("median_ms") is not None else "")
        )
    lines.append("Busiest client connections:")
    for row in (charts.get("by_connection") or [])[:8]:
        lines.append(
            f"- {row['ip']}:{row['port']} stream {row['stream']}: "
            f"{row['requests']} requests, {row['unanswered']} unanswered"
        )
    lines.append(
        "Opcodes in this capture (opcode, name, side, expects a reply, requests, unanswered, median ms, p99 ms, what it does):"
    )
    for row in charts.get("by_opcode") or []:
        expects = "reply" if row.get("expects_reply") is not False else "no reply"
        lines.append(
            f"- {row.get('opcode')} {row.get('name')} side={row.get('role') or ''} {expects}: "
            f"requests={row.get('requests')} unanswered={row.get('unanswered')} "
            f"median_ms={row.get('median_ms')} p99_ms={row.get('p99_ms')} "
            f"{row.get('description') or ''}".rstrip()
        )
    lines.append("Ten slowest matched calls (ms, seconds from start, body bytes, key):")
    for row in charts.get("top_slowest") or []:
        lines.append(
            f"- {row.get('time_ms')} ms at {row.get('seconds')}s side={row.get('role') or ''} "
            f"body={row.get('body_bytes')} stream {row.get('stream')} opaque {row.get('opaque')} {row.get('key')}"
        )
    return lines


def facts_brief(facts: dict, charts: dict | None = None) -> str:
    """Counts only. The model writes the note from this, and does not get the finished prose."""
    counts = facts["counts"]
    edge = facts["edge"]
    rtt = facts["rtt_seconds"]
    lines = [
        "Write the capture note from these counts. Do not invent a number or a key.",
        "",
        "How to read the counts:",
        "- DCP is full duplex. Cluster is node-to-node KV, DCP opcodes 0x50-0x67, Get All VBucket Seqnos 0x48, a Statistics key that starts with vbucket-seqno, or replication meta 0xa0-0xa5 and 0xa8. SDK is an application port to 11210 for the other commands.",
        "- The opaque on a DCP stream request is copied onto every later command for that stream. A snapshot marker and a mutation often share one packet and that opaque. A later packet is the next change, not a retry. Do not call no_reply messages lost responses.",
        "- These producer messages do not expect a command reply: stream end 0x55, snapshot marker 0x56 unless snapshot-type flag 0x08 Ack is set, mutation 0x57, deletion 0x58, expiration 0x59, buffer acknowledgement 0x5d (its response is unused; opaque 0 means the whole connection), and 0x5f-0x67. Noop 0x5c does expect a reply: the producer disconnects if the consumer stays silent.",
        "- Statistics 0x10 with key vbucket-seqno, and Get All VBucket Seqnos 0x48, are how a DCP consumer learns the high sequence number before a stream request. Statistics is one request and many response packets on one opaque. Continuation packets folded into the request are one call.",
        "- Replies with no request in the opening window, and requests with no reply in that same window, are calls the capture cut through. Requests in the closing window were still in flight when recording stopped.",
        "- Quote the SDK median and the cluster median. The blended round-trip median mixes them and hides the slower side.",
        "- Capture duplicates are the same TCP segment seen twice within 1 ms. Do not call them retransmissions or DCP retries. A retransmission waited out a timeout.",
        "",
        f"Source: {facts['source']}",
        f"Capture files: {', '.join(facts.get('pcap_files') or []) or '(tsv export)'}",
        f"Packets: {facts.get('packet_count')}",
        f"Duration seconds: {facts.get('capture_seconds')}",
        f"Client: {facts.get('client')}",
        f"Server: {facts.get('server')}",
        f"Request messages: {counts['request_messages']} in {counts['request_frames']} frames",
        f"Multi-message request frames: {counts['multi_message_frames']} ({counts['extra_messages_in_those_frames']} extra messages)",
        f"Joined tsv rows that were split: {counts['joined_tsv_rows']}",
        f"Requests with an empty document key: {counts['empty_keys']}",
        f"Response messages: {counts['response_messages']}",
        f"Matched: {counts['matched']}",
    ]
    traffic = (charts or {}).get("traffic") or {}
    if traffic:
        lines.append(
            "Cluster vs SDK: "
            + ", ".join(
                f"{role} requests {row.get('requests')} unanswered {row.get('unanswered')} "
                f"no_reply {row.get('no_reply')} median_ms {row.get('median_ms')} "
                f"p99_ms {row.get('p99_ms')} retrans {row.get('retrans')}"
                for role, row in traffic.items()
            )
        )
    lines.extend([
        f"Unanswered requests: {counts['unanswered_requests']}",
        f"Unique unanswered keys: {counts['unique_unanswered_keys']}",
        f"Responses with no request: {counts['responses_without_request']}",
        f"Statistics continuation packets folded into their request: {counts.get('multi_response_continuations') or 0}",
        f"Round trip median/mean/p90/p95/p99/max seconds: "
        f"{rtt['median']}, {rtt['mean']}, {rtt['p90']}, {rtt['p95']}, {rtt['p99']}, {rtt['max']}",
        f"Edge window seconds: {edge['window_seconds']} ({edge['window_source']})",
        f"Start-window responses: {edge['start_responses']}",
        f"End-window requests: {edge['end_requests']}",
        f"Opening-window requests with no reply: {edge.get('opening_requests', 0)}",
        f"Requests in the last 1 second: {edge['end_requests_within_1s']}",
        f"Interior unanswered: {edge['interior_unanswered']}",
        f"Interior responses with no request: {edge['interior_responses_without_request']}",
        "",
        "Magic counts:",
    ])
    for row in facts["magics"]:
        lines.append(f"- {row['magic']} {row['role']}: {row['messages']}")
    lines.append("")
    lines.append("Opening-window responses:")
    for row in edge["start_examples"]:
        lines.append(
            f"- t={row['time_s']} frame {row['frame']} stream {row['stream']} {row['opcode_name']} opaque {row['opaque']} status {row['status']}"
        )
    lines.append("")
    window = edge["window_seconds"]
    lines.append(
        f"Requests inside the closing window (left <= {window:.6f}s). "
        f"Count is {edge['end_requests']}. These are the in-flight requests:"
    )
    closing = edge.get("closing_examples")
    if closing is None:
        closing = [row for row in edge["end_examples"] if (row["seconds_left"] or 0) <= window + 1e-9]
    wider = [row for row in edge["end_examples"] if (row["seconds_left"] or 0) > window + 1e-9]
    for row in closing:
        lines.append(
            f"- t={row['time_s']} left={row['seconds_left']} frame {row['frame']} stream {row['stream']} {row['opcode_name']} {row['key']}"
        )
    lines.append(
        f"Other requests in the last 1 second but outside that window. "
        f"The 1-second count is {edge['end_requests_within_1s']} and includes the closing-window rows above:"
    )
    for row in wider:
        lines.append(
            f"- t={row['time_s']} left={row['seconds_left']} frame {row['frame']} stream {row['stream']} {row['opcode_name']} {row['key']}"
        )
    lines.append("")
    lines.append(f"Bins of {facts['bin_seconds']} seconds (unanswered, response-only, matched):")
    for row in facts["bins"]:
        if row["unanswered"] or row["resp_only"] or row["matched"]:
            lines.append(
                f"- {row['start']}-{row['end']}: {row['unanswered']}, {row['resp_only']}, {row['matched']}"
            )
    tcp = facts.get("tcp")
    lines.append("")
    if not tcp:
        lines.append("TCP loss: not measured. Say the pcap is required for lost-segment counts.")
    else:
        lines.append(
            f"TCP ports {tcp['ports']}: lost_segments={tcp['lost_segments']} "
            f"retransmissions={tcp['retransmissions']} ack_lost={tcp['ack_lost_segments']} "
            f"client_to_server={tcp['client_to_server']} server_to_client={tcp['server_to_client']}"
        )
        lines.append(f"Lost by stream: {tcp['lost_by_stream']}")
        lines.append(f"Unanswered with a gap after the request: {tcp['unanswered_near_gap']}")
    if charts:
        packet_counts = {row.get("name"): row.get("count") or 0 for row in charts.get("packet_types") or []}
        lines.append(
            f"Capture duplicates: {packet_counts.get('Capture duplicate', 0)}. "
            "These are the same TCP segment recorded again within 1 ms. They are not retries and they are not DCP. "
            f"Retransmission packets that waited out a timeout: {packet_counts.get('Retransmission', 0)}."
        )
    lines.append("")
    lines.append("Request opcodes: " + ", ".join(f"{row['count']} {row['name']} ({row['opcode']})" for row in facts["opcodes_requests"]))
    lines.append("Unanswered opcodes: " + ", ".join(f"{row['count']} {row['name']} ({row['opcode']})" for row in facts["opcodes_unanswered"]))
    lines.append("Response-only opcodes: " + ", ".join(f"{row['count']} {row['name']}" for row in facts["opcodes_resp_only"]))
    lines.append("Response status: " + ", ".join(f"{row['count']} {row['status']} {row['name']}" for row in facts["status_responses"]))
    lines.append("Key families: " + ", ".join(f"{row['count']} {row['family']}" for row in facts["families"]))
    lines.append(f"Dominant family: {facts['dominant_family']}")
    if facts["duplicate_keys"]:
        lines.append("Duplicate unanswered keys:")
        for row in facts["duplicate_keys"]:
            lines.append(f"- {row['count']} {row['key']}")
    streams = facts["streams"]
    ranked_streams = sorted(
        streams,
        key=lambda row: (row.get("unanswered") or 0, row.get("requests") or 0),
        reverse=True,
    )
    shown_streams = ranked_streams[:12]
    lines.append(
        f"Streams: {len(streams)} total. "
        f"Showing {len(shown_streams)} with the most unanswered requests, then the busiest."
    )
    for row in shown_streams:
        lines.append(
            f"- stream {row['stream']} {row['src']}:{row['sport']} -> {row['dst']}:{row['dport']} "
            f"requests={row['requests']} unanswered={row['unanswered']}"
        )
    if facts["cross_stream_opaque_count"]:
        lines.append(f"Same opaque on another stream: {facts['cross_stream_opaque_count']}")
        for row in facts["cross_stream_opaque"][:3]:
            lines.append(
                f"- opaque {row['opaque']} unanswered on stream {row['request_stream']} ({row['opcode_name']} {row['key']}) "
                f"also on response streams {row['response_streams']}"
            )
    lines.append("")
    lines.append(f"Keys outside {facts['dominant_family']}:")
    for row in facts["other_keys"]:
        lines.append(
            f"- t={row['time_s']} left={row['seconds_left']} stream {row['stream']} {row['opcode_name']} {row['key']}"
        )
    lines.append("")
    lines.append(
        "How the match works: composite key is tcp.stream + '-' + couchbase.opaque. "
        "Spreadsheet equivalent: Requests K =C1&\"-\"&I1, Responses G =C1&\"-\"&E1, "
        "Requests L =COUNTIF(Responses!G:G, K1). Zero is unanswered. "
        "Collection document ids are couchbase.key.logical_key; couchbase.key is often empty. "
        "Comma-joined opaques in one tshark row are separate messages."
    )
    if charts:
        lines.append("")
        lines.extend(chart_digest(charts))
    lines.append("")
    lines.append(
        "End the note with a Next questions and steps section of 4 to 6 numbered items. "
        "Each item cites a count from this message. These are the next checks for a support engineer. "
        "Do not invent a root cause, a host, or a key."
    )
    lines.append("")
    lines.append("Put the full key table under All unanswered requests by leaving this token on its own line:")
    lines.append(TABLE_TOKEN)
    return "\n".join(lines)


SYSTEM_PROMPT = """You are a Couchbase support engineer writing a packet-capture note.

Use only the counts in the user message. If a figure is missing, leave it out. Do not invent keys, hosts, times, or causes.

Write GitHub-flavored markdown with these headings, in this order:
# Orphaned Couchbase requests
## What was captured
## How the requests and responses were matched
## Round trip and the edges of the file
## Packets missing from the recording
## What the unanswered requests are
## Keys outside the main family
## All unanswered requests
## Next questions and steps

The opening states the Couchbase host and IP, the unanswered-request count, the unique key count, and the responses that have no request.
Then state the round trip and the in-flight window. Separate three groups: responses already on the wire when the file opened, requests still on the wire when the file closed, and the interior rows that had more than that window of capture left.
When slow-call counts and body lengths are present, put them in the round-trip section. A short tail of calls over 100 ms, with a maximum well under a second, is not a server timeout.
When lost-segment markers are present in both directions and retransmissions are rare, say the missing packets fit a recorder that did not see them. Do not call the whole unanswered set Couchbase timeouts.
Name the stream and key family that hold most of the unanswered requests. Mention duplicate keys and any opaque that also appears on a different stream.
If every request shares one client IP, say so, and name the busiest source port.
Under All unanswered requests, leave the line {{UNANSWERED_TABLE}} exactly as written, on its own line. Do not invent the full key list.
The last section is 4 to 6 numbered questions or actions. Each one cites a count from the message.
No preamble. No chain of thought. No extra headings."""


def strip_think(text: str) -> str:
    return _THINK_RE.sub("", text or "").strip()


def clean_model_markdown(text: str) -> str:
    text = strip_think(text).strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:markdown|md)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    if not text.startswith("#"):
        index = text.find("\n#")
        if index != -1:
            text = text[index + 1 :]
    return text.strip() + "\n"


def trace_filters(charts: dict) -> str:
    """Filters a person can paste into Wireshark. Counted, so the model cannot drop them."""
    lines = [
        "## Wireshark filters",
        "",
        "Counted from this capture. Each line is a display filter.",
        "",
    ]
    for row in charts.get("top_slowest") or []:
        stream = row.get("stream") or ""
        opaque = row.get("opaque") or ""
        if not stream or not opaque:
            continue
        call = f"tcp.stream == {stream} && couchbase.opaque == {opaque}"
        lines.append(f"- Slow call, {row.get('time_ms')} ms, `{row.get('key') or ''}`: `{call}`")
    groups = (
        ("SDK request missing a response", "missing_response_sdk"),
        ("Cluster request missing a response", "missing_response_cluster"),
        ("SDK response missing a request", "missing_request_sdk"),
        ("Cluster response missing a request", "missing_request_cluster"),
    )
    for label, key in groups:
        for row in charts.get(key) or []:
            filt = row.get("error_filter") or ""
            if not filt and row.get("stream") and row.get("opaque"):
                filt = f"tcp.stream == {row['stream']} && couchbase.opaque == {row['opaque']}"
            if not filt:
                continue
            lines.append(f"- {label}, {row.get('seconds')} s, `{row.get('key') or row.get('opaque') or ''}`: `{filt}`")
    if len(lines) == 4:
        return ""
    return "\n".join(lines) + "\n"


def append_trace_filters(text: str, charts: dict) -> str:
    block = trace_filters(charts)
    if not block or "## Wireshark filters" in text:
        return text
    return text.rstrip() + "\n\n" + block


def splice_table(text: str, table: str) -> str:
    block = "Sorted by time. Left is seconds of capture remaining after the request.\n\n" + table
    if TABLE_TOKEN in text:
        return text.replace(TABLE_TOKEN, block)
    return text.rstrip() + "\n\n## All unanswered requests\n\n" + block + "\n"


INTEREST_SYSTEM = """You mark points of interest on a Couchbase capture chart.

Return only a JSON array. No markdown. Each object has "seconds", "title", and "why".
"seconds" must be one of the candidate seconds in the user message. Do not invent a time.
Pick 4 to 6 moments that are worth a vertical line: where slowness, a large body, and TCP loss line up, plus a moment that is only a loss spike or only a large body when those are different seconds.
"title" is at most 6 words. "why" is one sentence and cites a number from that candidate.
"""


def interest_candidates(charts: dict) -> list[dict]:
    """Counted seconds the model is allowed to stake. Nearby seconds collapse to one."""
    found: list[dict] = []

    def add(seconds: float | int | None, title: str, why: str) -> None:
        if seconds is None:
            return
        try:
            seconds = round(float(seconds), 3)
        except (TypeError, ValueError):
            return
        for item in found:
            if abs(item["seconds"] - seconds) < 0.5:
                return
        found.append({"seconds": seconds, "title": title, "why": why})

    for row in (charts.get("top_slowest") or [])[:4]:
        add(
            row.get("seconds"),
            "Slow call",
            f"{row.get('time_ms')} ms, body {row.get('body_bytes')} bytes",
        )
    rows = ((charts.get("buckets") or {}).get("1") or [])
    if rows:
        peak_p99 = max(rows, key=lambda row: row.get("rtt_p99") or 0)
        if peak_p99.get("rtt_p99"):
            add(
                peak_p99.get("t"),
                "Highest p99",
                f"p99 {peak_p99.get('rtt_p99')} ms, median {peak_p99.get('rtt_median')} ms",
            )
        peak_loss = max(rows, key=lambda row: row.get("lost") or 0)
        if peak_loss.get("lost"):
            add(
                peak_loss.get("t"),
                "Most TCP loss",
                f"{peak_loss.get('lost')} lost segments, {peak_loss.get('unanswered')} lost responses",
            )
        peak_out = max(rows, key=lambda row: row.get("body_out_max") or 0)
        if peak_out.get("body_out_max"):
            add(
                peak_out.get("t"),
                "Largest reply",
                f"{peak_out.get('body_out_max')} bytes out of Couchbase",
            )
        peak_in = max(rows, key=lambda row: row.get("body_in_max") or 0)
        if peak_in.get("body_in_max"):
            add(
                peak_in.get("t"),
                "Largest request",
                f"{peak_in.get('body_in_max')} bytes into Couchbase",
            )
        peak_miss = max(rows, key=lambda row: row.get("unanswered") or 0)
        if peak_miss.get("unanswered"):
            add(
                peak_miss.get("t"),
                "Most lost responses",
                f"{peak_miss.get('unanswered')} requests with no reply",
            )
    return found[:8]


def _fallback_interest(candidates: list[dict]) -> list[dict]:
    return [
        {"seconds": item["seconds"], "title": item["title"], "why": item["why"]}
        for item in candidates[:6]
    ]


def parse_interest_stakes(text: str, candidates: list[dict]) -> list[dict]:
    """Keep model rows whose second is one of the counted candidates."""
    cleaned = strip_think(text or "").strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    start = cleaned.find("[")
    end = cleaned.rfind("]")
    if start == -1 or end <= start:
        raise ValueError("model stake reply had no JSON array")
    payload = json.loads(cleaned[start : end + 1])
    if not isinstance(payload, list):
        raise ValueError("model stake reply was not a list")
    chosen: list[dict] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        try:
            seconds = float(item.get("seconds"))
        except (TypeError, ValueError):
            continue
        match = None
        for candidate in candidates:
            gap = abs(candidate["seconds"] - seconds)
            if gap <= 0.75 and (match is None or gap < abs(match["seconds"] - seconds)):
                match = candidate
        if match is None:
            continue
        if any(abs(row["seconds"] - match["seconds"]) < 0.5 for row in chosen):
            continue
        title = str(item.get("title") or match["title"]).strip()[:80] or match["title"]
        why = str(item.get("why") or match["why"]).strip()[:280] or match["why"]
        chosen.append({"seconds": match["seconds"], "title": title, "why": why})
        if len(chosen) >= 6:
            break
    if not chosen:
        raise ValueError("model stake reply matched no candidate second")
    return chosen


def choose_interest_stakes(
    charts: dict,
    *,
    base_url: str,
    model: str,
    timeout: int,
    use_model: bool,
    provider: str = "ollama",
    api_key: str = "",
) -> list[dict]:
    candidates = interest_candidates(charts)
    if not candidates or not use_model:
        return _fallback_interest(candidates)
    lines = ["Candidate seconds. Use only these seconds.", ""]
    for item in candidates:
        lines.append(f"- {item['seconds']}s {item['title']}: {item['why']}")
    try:
        raw = call_model(
            "\n".join(lines),
            provider=provider,
            base_url=base_url,
            model=model,
            timeout=min(int(timeout), 180),
            system=INTEREST_SYSTEM,
            api_key=api_key,
        )
        picked = parse_interest_stakes(raw, candidates)
        log(f"model marked {len(picked)} points of interest")
        return picked
    except (SystemExit, ValueError, json.JSONDecodeError, KeyError, TypeError) as exc:
        log(f"Interest stakes fell back to the counted seconds: {exc}")
        return _fallback_interest(candidates)


def chat_completions_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def api_host_is_local(base_url: str) -> bool:
    host = (urllib.parse.urlparse(base_url).hostname or "").lower()
    return host in _LOCAL_API_HOSTS


def message_text(body: dict, provider: str) -> str:
    if provider == "openai":
        choices = body.get("choices") or []
        if not choices or not isinstance(choices[0], dict):
            return ""
        content = (choices[0].get("message") or {}).get("content") or ""
        if isinstance(content, list):
            parts = []
            for part in content:
                if isinstance(part, str):
                    parts.append(part)
                elif isinstance(part, dict):
                    parts.append(str(part.get("text") or ""))
            return "".join(parts)
        return str(content)
    message = body.get("message") or {}
    return str(message.get("content") or body.get("response") or "")


def model_request(
    note: str,
    *,
    provider: str,
    base_url: str,
    model: str,
    system: str | None,
    api_key: str,
) -> tuple[str, dict, dict]:
    messages = [
        {"role": "system", "content": system or SYSTEM_PROMPT},
        {"role": "user", "content": note},
    ]
    headers = {"Content-Type": "application/json"}
    if provider == "openai":
        payload = {"model": model, "temperature": 0.2, "max_tokens": 8192, "messages": messages}
        if api_key:
            headers["Authorization"] = "Bearer " + api_key
        return chat_completions_url(base_url), payload, headers
    payload = {
        "model": model,
        "think": False,
        "stream": False,
        "messages": messages,
        "options": {"temperature": 0.2, "num_predict": 3072},
    }
    return base_url.rstrip("/") + "/api/chat", payload, headers


def call_model(
    note: str,
    *,
    provider: str,
    base_url: str,
    model: str,
    timeout: int,
    system: str | None = None,
    api_key: str = "",
) -> str:
    if provider == "openai":
        if not base_url or not model:
            raise SystemExit(
                "An OpenAI-compatible note needs ai.base_url and ai.model, "
                "or --api-base and --model. The API key stays in AI_API_KEY or OPENAI_API_KEY."
            )
        if not api_key and not api_host_is_local(base_url):
            raise SystemExit(
                "Set AI_API_KEY or OPENAI_API_KEY for that API. Do not put the key in config.json."
            )
    elif not base_url or not model:
        raise SystemExit("The Ollama note needs a base URL and a model.")
    url, payload, headers = model_request(
        note,
        provider=provider,
        base_url=base_url,
        model=model,
        system=system,
        api_key=api_key,
    )
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    log(f"asking {model} at {base_url} ({provider}), note {len(note)} characters")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:1500]
        raise SystemExit(f"The model API returned {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not reach the model API at {base_url}: {exc.reason}") from exc
    content = message_text(body, provider)
    if not content.strip():
        raise SystemExit(
            "The model returned an empty note. If it spent the reply on hidden thinking, "
            "confirm the model accepts think:false, or raise --timeout."
        )
    return content


def call_ollama(
    note: str,
    *,
    base_url: str,
    model: str,
    timeout: int,
    system: str | None = None,
) -> str:
    return call_model(
        note,
        provider="ollama",
        base_url=base_url,
        model=model,
        timeout=timeout,
        system=system,
    )


def write_tsv(path: Path, requests: list[dict], responses: list[dict], unanswered: list[dict]) -> None:
    def req_line(msg: dict) -> str:
        return "\t".join(
            [
                msg["frame"],
                f"{msg['time']:.9f}",
                msg["stream"],
                msg["src"],
                msg["sport"],
                msg["dst"],
                msg["dport"],
                msg["opcode"],
                msg["opaque"],
                msg["key"],
            ]
        )

    def resp_line(msg: dict) -> str:
        return "\t".join(
            [
                msg["frame"],
                f"{msg['time']:.9f}",
                msg["stream"],
                msg["opcode"],
                msg["opaque"],
                msg.get("status") or "",
            ]
        )

    (path / "reqs.pdus.tsv").write_text("\n".join(req_line(msg) for msg in requests) + "\n")
    (path / "resps.tsv").write_text("\n".join(resp_line(msg) for msg in responses) + "\n")
    header = "\t".join(
        [
            "frame",
            "time_s",
            "seconds_before_capture_end",
            "tcp.stream",
            "src",
            "src_port",
            "dst",
            "dst_port",
            "opcode",
            "opcode_name",
            "opaque",
            "couchbase.key",
            "response_count",
        ]
    )
    body = []
    for row in unanswered:
        left = "" if row["seconds_left"] is None else f"{row['seconds_left']:.3f}"
        body.append(
            "\t".join(
                [
                    row["frame"],
                    row["time_s"],
                    left,
                    row["stream"],
                    row["src"],
                    row["sport"],
                    row["dst"],
                    row["dport"],
                    row["opcode"],
                    row["opcode_name"],
                    row["opaque"],
                    row["key"],
                    "0",
                ]
            )
        )
    (path / "orphans.tsv").write_text(header + "\n" + "\n".join(body) + ("\n" if body else ""))


def sibling_resps(reqs_path: Path) -> Path | None:
    folder = reqs_path.parent
    for name in ("resps.tsv", "responses.tsv", "resp.tsv"):
        candidate = folder / name
        if candidate.exists() and candidate != reqs_path:
            return candidate
    return None


def sibling_pcaps(folder: Path) -> list[Path]:
    found = [path for path in folder.iterdir() if path.is_file() and is_pcap(path)]
    return sorted(found, key=lambda path: path.name)


def resolve_job(args: argparse.Namespace) -> dict:
    if args.pcap:
        return {"mode": "pcap", "pcap": Path(args.pcap).expanduser().resolve(), "also": []}
    if args.reqs:
        reqs = Path(args.reqs).expanduser().resolve()
        resps = Path(args.resps).expanduser().resolve() if args.resps else sibling_resps(reqs)
        return {"mode": "tsv", "reqs": reqs, "resps": resps}

    raw = Path(args.path).expanduser().resolve() if args.path else None
    if raw is None:
        raise SystemExit("Pass a pcap, a tsv export, or a directory.")
    if not raw.exists():
        raise SystemExit(f"No such path: {raw}")

    if raw.is_dir():
        pcaps = unique_pcaps(sibling_pcaps(raw))
        if pcaps and not args.from_tsv:
            if len(pcaps) > 1:
                names = "\n".join(str(rep) for rep, _members in pcaps)
                raise SystemExit(f"More than one distinct capture in {raw}:\n{names}\nPass one file.")
            rep, members = pcaps[0]
            return {"mode": "pcap", "pcap": rep, "also": members}
        reqs = next((raw / name for name in ("reqs.tsv", "requests.tsv") if (raw / name).exists()), None)
        if reqs is None:
            tables = [path for path in raw.iterdir() if path.is_file() and is_table(path)]
            if len(tables) == 1:
                reqs = tables[0]
            else:
                raise SystemExit(f"No pcap or reqs.tsv in {raw}")
        return {"mode": "tsv", "reqs": reqs, "resps": sibling_resps(reqs)}

    if is_pcap(raw):
        return {"mode": "pcap", "pcap": raw, "also": [raw]}
    if is_table(raw):
        if not args.from_tsv:
            pcaps = unique_pcaps(sibling_pcaps(raw.parent))
            if len(pcaps) == 1:
                rep, members = pcaps[0]
                log(
                    f"{raw.name} is a field export. Using {rep.name} so responses, "
                    "collection keys, and TCP gaps come from the capture."
                )
                return {"mode": "pcap", "pcap": rep, "also": members}
            if len(pcaps) > 1:
                names = ", ".join(rep.name for rep, _ in pcaps)
                raise SystemExit(f"Several different pcaps next to {raw.name}: {names}. Pass one with --pcap.")
        return {"mode": "tsv", "reqs": raw, "resps": Path(args.resps).resolve() if args.resps else sibling_resps(raw)}
    raise SystemExit(f"Do not know how to read {raw}")


def default_out(job: dict, args: argparse.Namespace) -> Path:
    if args.out:
        return Path(args.out).expanduser().resolve()
    source = job["pcap"] if job["mode"] == "pcap" else job["reqs"]
    # One folder per capture so filename_1 does not overwrite filename_0.
    return source.parent / f"{source.stem}-report"


def load_config(path: Path | None = None) -> dict:
    if path is None:
        path = ROOT / "config.json"
    else:
        path = path.expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must be a JSON object")
    return data


def apply_config(args: argparse.Namespace) -> argparse.Namespace:
    """CLI flags win, then environment, then config.json, then built-in defaults."""
    cfg = load_config(Path(args.config) if args.config else None)
    ollama = cfg.get("ollama") or {}
    if not isinstance(ollama, dict):
        ollama = {}
    ai = cfg.get("ai") or {}
    if not isinstance(ai, dict):
        ai = {}
    if args.ollama is None:
        args.ollama = os.environ.get("OLLAMA_BASE_URL") or ollama.get("base_url") or DEFAULT_OLLAMA
    if args.provider is None:
        args.provider = (os.environ.get("AI_PROVIDER") or str(ai.get("provider") or "ollama")).strip().lower()
    if args.provider in {"openai", "openai-compatible", "chat"}:
        args.provider = "openai"
    else:
        args.provider = "ollama"
    if args.provider == "openai":
        if args.model is None:
            args.model = (os.environ.get("AI_MODEL") or str(ai.get("model") or "")).strip()
        if args.api_base is None:
            args.api_base = (os.environ.get("AI_BASE_URL") or str(ai.get("base_url") or "")).strip()
        args.api_key = (os.environ.get("AI_API_KEY") or os.environ.get("OPENAI_API_KEY") or "").strip()
        if args.timeout is None:
            args.timeout = int(ai.get("timeout_seconds") or ollama.get("timeout_seconds") or DEFAULT_TIMEOUT)
    else:
        if args.model is None:
            args.model = ollama.get("model") or DEFAULT_MODEL
        if args.api_base:
            args.ollama = args.api_base
        args.api_base = args.ollama
        args.api_key = ""
        if args.timeout is None:
            args.timeout = int(ollama.get("timeout_seconds") or DEFAULT_TIMEOUT)
    if not args.tshark:
        from_env = (os.environ.get("TSHARK") or "").strip()
        from_file = str(cfg.get("tshark") or "").strip()
        args.tshark = from_env or from_file or None
    if not args.out:
        configured_out = str(cfg.get("output_dir") or "").strip()
        if configured_out:
            args.out = configured_out
    return args


def project_version() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    match = re.search(r'(?m)^version = "([^"]+)"', text)
    if not match:
        raise SystemExit("pyproject.toml has no version")
    return match.group(1)


def stamp_version(page: str, label: str) -> str:
    stamped, count = re.subn(
        r'(<span class="version" id="app-version">)[^<]*(</span>)',
        rf"\1v{project_version()}\2",
        page,
        count=1,
    )
    if count != 1:
        raise SystemExit(f"{label} is missing the version slot")
    return stamped


def chart_page() -> str:
    template = ROOT / "web" / "index.html"
    if not template.is_file():
        raise SystemExit(f"Chart page is missing: {template}")
    return stamp_version(template.read_text(), "chart page")


def report_page() -> str:
    template = ROOT / "web" / "summary.html"
    if not template.is_file():
        raise SystemExit(f"Report page is missing: {template}")
    return stamp_version(template.read_text(), "report page")


def write_charts(out: Path, charts: dict) -> None:
    (out / "charts.json").write_text(json.dumps(charts, separators=(",", ":")))
    (out / "index.html").write_text(chart_page())
    (out / "summary.html").write_text(report_page())
    original = ROOT / "web" / "index.original.html"
    if not original.is_file():
        raise SystemExit(f"Previous chart page is missing: {original}")
    shutil.copyfile(original, out / "index.original.html")
    vendor_src = ROOT / "web" / "vendor"
    library = vendor_src / "echarts.min.js"
    if not library.is_file():
        raise SystemExit(f"Chart library is missing: {library}")
    vendor_out = out / "vendor"
    vendor_out.mkdir(exist_ok=True)
    for path in vendor_src.iterdir():
        if path.is_file():
            shutil.copyfile(path, vendor_out / path.name)
    log(f"wrote {out / 'index.html'}")


def print_dry_run(out: Path, args: argparse.Namespace, facts: dict) -> None:
    counts = facts["counts"]
    files = ["facts.json", "charts.json", "index.html", "summary.html", "index.original.html", "vendor/echarts.min.js", "orphans.tsv", "reqs.pdus.tsv", "resps.tsv", "summary.md"]
    if not args.no_ai:
        files.append("summary.computed.md")
    print("dry-run")
    print(f"source: {facts['source']}")
    print(f"output directory (not created): {out}")
    print("files that would be written:")
    for name in files:
        print(f"  {name}")
    if args.no_ai:
        print("model: skipped (--no-ai)")
    else:
        print(f"model: would call {args.model} at {args.api_base}")
        if args.provider == "openai":
            print("model api: OpenAI chat completions")
    print(
        f"unanswered {counts['unanswered_requests']}, "
        f"responses without a request {counts['responses_without_request']}, "
        f"matched {counts['matched']}"
    )


def run_job(args: argparse.Namespace) -> tuple[Path, bool]:
    job = resolve_job(args)
    out = default_out(job, args)
    tshark = find_tshark(args.tshark)
    opcode_names: dict[str, str] = {}
    magics: Counter | None = None
    packet_count = None
    capture_end = 0.0
    joined_rows = 0
    pcap_names: list[str] = []
    loss = None
    loss_events: list[dict] = []
    packet_types: Counter | None = None

    if job["mode"] == "pcap":
        if not tshark:
            raise SystemExit("tshark is not on PATH and not in /Applications/Wireshark.app.")
        pcap = job["pcap"]
        pcap_names = [path.name for path in job.get("also") or [pcap]]
        requests, responses, magics, loss_events, packet_types = load_pcap(pcap, tshark)
        capinfos = find_capinfos(tshark)
        duration = None
        if capinfos:
            duration, packet_count = read_capinfos(capinfos, pcap)
        times = [msg["time"] for msg in requests + responses]
        capture_end = max([t for t in [duration, max(times) if times else 0] if t is not None])
        loss = summarize_loss(loss_events, couchbase_ports(requests))
        source = str(pcap)
    else:
        requests, responses, joined_rows = load_tsv_pair(job["reqs"], job.get("resps"))
        times = [msg["time"] for msg in requests + responses]
        capture_end = max(times) if times else 0.0
        source = str(job["reqs"])
        if job.get("resps"):
            source += f" + {job['resps'].name}"

    paired = pair_messages(requests, responses)
    facts = build_facts(
        requests,
        responses,
        paired,
        source_label=source,
        pcap_names=pcap_names,
        capture_end=capture_end,
        packet_count=packet_count,
        magics=magics,
        joined_rows=joined_rows,
        opcode_names=opcode_names,
        loss=loss,
    )
    if args.dry_run:
        print_dry_run(out, args, facts)
        return out, True

    charts = build_charts(
        requests,
        paired,
        loss_events,
        couchbase_ports(requests),
        capture_end,
        packet_types,
    )
    facts["traffic"] = charts.get("traffic") or {}
    facts["next_steps"] = next_questions(facts, charts)
    charts["next_steps"] = facts["next_steps"]
    computed = render_summary(facts)
    out.mkdir(parents=True, exist_ok=True)
    (out / "facts.json").write_text(json.dumps(facts, indent=2) + "\n")
    write_tsv(out, requests, responses, facts["unanswered"])

    def finish_charts(use_model: bool) -> None:
        charts["interest_stakes"] = choose_interest_stakes(
            charts,
            base_url=args.api_base,
            model=args.model,
            timeout=args.timeout,
            use_model=use_model,
            provider=args.provider,
            api_key=args.api_key,
        )
        write_charts(out, charts)

    if args.no_ai:
        finish_charts(False)
        (out / "summary.md").write_text(append_trace_filters(computed, charts))
        log(f"wrote {out / 'summary.md'}")
        return out, True

    try:
        raw = call_model(
            facts_brief(facts, charts),
            provider=args.provider,
            base_url=args.api_base,
            model=args.model,
            timeout=args.timeout,
            api_key=args.api_key,
        )
    except SystemExit as exc:
        finish_charts(True)
        (out / "summary.md").write_text(append_trace_filters(computed, charts))
        log(str(exc))
        log(f"The model did not write the note. The counted report is {out / 'summary.md'}")
        return out, False
    finish_charts(True)
    cleaned = append_trace_filters(
        splice_table(clean_model_markdown(raw), unanswered_table(facts["unanswered"])),
        charts,
    )
    (out / "summary.computed.md").write_text(append_trace_filters(computed, charts))
    (out / "summary.md").write_text(cleaned)
    missing = [
        row["key"]
        for row in facts["unanswered"]
        if row["key"] and row["key"] not in cleaned
    ]
    headline = str(facts["counts"]["unanswered_requests"])
    if headline not in cleaned or (facts["unanswered"] and len(missing) > max(3, len(facts["unanswered"]) // 5)):
        log(
            "The model note dropped counted keys or the unanswered total. "
            "summary.md is the model text; summary.computed.md is the counted note."
        )
    else:
        log("model note kept the counted keys")
    log(f"wrote {out / 'summary.md'}")
    return out, True


def self_test() -> int:
    try:
        import pytest
    except ImportError as exc:
        raise SystemExit(
            "pytest is not installed. From the project root: python3 -m venv .venv && "
            "source .venv/bin/activate && pip install -r requirements.txt"
        ) from exc
    return int(pytest.main(["-q", str(ROOT / "tests")]))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Count unanswered Couchbase ops in a Wireshark dump and write a note with a local or remote model."
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="pcap/pcapng, a .tsv/.csv field export, or a directory of those files",
    )
    parser.add_argument("--pcap", help="capture file to read with tshark")
    parser.add_argument("--reqs", help="request field export (10 columns, or a header row)")
    parser.add_argument("--resps", help="response field export (6 columns, or a header row)")
    parser.add_argument(
        "--from-tsv",
        action="store_true",
        help="read the tsv even when a pcap is in the same folder",
    )
    parser.add_argument("-o", "--out", help="output directory (default: <capture name>-report next to the input)")
    parser.add_argument("--model", default=None, help=f"Model name (default from config.json, else {DEFAULT_MODEL} for Ollama)")
    parser.add_argument("--ollama", default=None, help=f"Ollama base URL (default from config.json, else {DEFAULT_OLLAMA})")
    parser.add_argument(
        "--provider",
        default=None,
        choices=["ollama", "openai"],
        help="ollama talks to a local Ollama server. openai posts to an OpenAI-compatible /chat/completions API",
    )
    parser.add_argument(
        "--api-base",
        default=None,
        help="Base URL for --provider openai, before /chat/completions. Also overrides the Ollama URL when --provider ollama",
    )
    parser.add_argument("--timeout", type=int, default=None, help="seconds to wait for the model (default from config.json)")
    parser.add_argument("--no-ai", action="store_true", help="write the counted note and skip the model")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="count and print the plan; do not write files or call Ollama",
    )
    parser.add_argument("--config", help="path to config.json (default: config.json next to this script)")
    parser.add_argument("--tshark", help="path to tshark")
    parser.add_argument("--self-test", action="store_true", help="run pytest on tests/ and exit")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        return self_test()
    if not args.path and not args.pcap and not args.reqs:
        parse_args(["-h"])
    args = apply_config(args)
    out, ai_ok = run_job(args)
    if args.dry_run:
        return 0
    counts_path = out / "facts.json"
    counts = json.loads(counts_path.read_text())["counts"]
    log(
        f"unanswered {counts['unanswered_requests']}, "
        f"responses without a request {counts['responses_without_request']}, "
        f"matched {counts['matched']}"
    )
    print(out / "summary.md")
    return 0 if ai_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
