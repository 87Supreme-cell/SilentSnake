# Capture events: `silentsnake.capture/1`

Output of `silentsnake-capture` (stage A). One JSON object per line on stdout; nothing is written to disk. The engine is a producer for the encrypted log store and the local API, and this schema is their input contract.

**Versioning.** Fields may be *added* within `/1`. Renaming, removing or changing the meaning of a field bumps the schema to `/2`. Consumers must ignore unknown fields and unknown `type` values.

## Envelope (every event)

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `silentsnake.capture/1` |
| `seq` | integer | 1, 2, 3, … per engine run, gap-free. A gap means events were lost |
| `ts` | string | RFC 3339 UTC, microseconds (`2026-11-25T17:35:00.030000Z`). Packet time for packet events, wall-clock time for engine events |
| `type` | string | One of the types below |
| `summary` | string | Plain-English description for people. **Not for parsing**: the structured fields are authoritative |

All names taken from traffic (DNS names, TLS SNI) are sanitized: bytes outside `[A-Za-z0-9-_*.]` appear as `\xNN`, and a `.` inside a DNS label appears as `\x2e`.

## Shared objects

- **Endpoint:** `{"ip": "93.184.216.34", "port": 443}`. `port` is 0 for protocols without ports (ICMP).
- **Flow fields** (in `flow_start` and `flow_end`):

| Field | Type | Meaning |
|---|---|---|
| `flow_id` | integer | Unique within the run |
| `proto` | string | `tcp`, `udp`, `icmp`, `icmpv6`, `igmp`, `gre`, `esp`, `sctp`, or `ip-proto-N` |
| `direction` | string | `outbound` (this machine started it), `inbound`, `local` (both ends here), `transit` (neither end here), `unknown` (own addresses not known, e.g. `--read` without `--local-addr`) |
| `initiator`, `responder` | Endpoint | Who started the flow and who answered |
| `initiator_inferred` | bool | The flow was already running when capture started; initiator guessed from ports |
| `service` | string? | Port-based hint for the responder port (`https`, `dns`, `ssh`, `quic`, …). A hint, not an identification |
| `server_name` | string? | Best known name for the responder |
| `server_name_source` | string? | `sni` (TLS ClientHello) or `dns` (earlier DNS answer for that address) |

## Event types

### `engine_start`
`version` (string) and `source`: `kind` (`live` or `file`), `name` (interface or file path), `link_type`, `filter` (optional BPF expression), `euid`, `cap_net_raw` (bool).

### `flow_start`
Flow fields. Emitted on the first packet of a new flow.

### `flow_end`
Flow fields, plus:

| Field | Meaning |
|---|---|
| `reason` | `closed` (FIN both ways), `reset` (RST), `idle` (TCP 300 s, UDP 60 s, other 30 s), `evicted` (flow table full), `capture_end` (file ended), `capture_stopped` (live capture stopped) |
| `duration_ms` | First to last packet |
| `initiator_packets`, `initiator_bytes`, `responder_packets`, `responder_bytes` | Per-direction counts; bytes are on-the-wire lengths |

### `dns`
UDP DNS, mDNS (5353) or LLMNR (5355). `flow_id`, `protocol` (`dns`/`mdns`/`llmnr`), `client`, `server` (Endpoints), `id`, `is_response`, `opcode`, `rcode` (`NOERROR`, `NXDOMAIN`, …), `truncated_by_server` (TC flag), `questions` (`[{name, qtype}]`), `answers` (`[{name, rtype, ttl, data?}]`, where `data` is decoded for A, AAAA, CNAME, PTR and NS), `partially_decoded` (counts exceeded the parser's limits of 16 questions / 64 answers).

### `tls_client_hello`
`flow_id`, `client`, `server`, `server_name` (SNI or `null`), `ech` (Encrypted Client Hello present: `server_name` is then only the outer, public name), `anomalies` (any of `legacy_tls_version`, `no_extensions`, `trailing_bytes`, `duplicate_extension`, `sni_empty`, `sni_too_long`, `sni_unusual_characters`).

### `stats` (live capture, every `--stats` seconds) and `engine_stop`
Counters: `packets_seen`, `bytes_seen`, `packets_non_ip`, `packets_fragmented`, `packets_undecoded`, `packets_unsupported_link`, `packets_after_close`, `flows_started`, `flows_ended`, `flows_evicted`, `dns_messages`, `dns_parse_errors`, `tls_client_hellos`, `tls_unparsed`; `flows_active`; and for live capture, the libpcap kernel counters `kernel_received`, `kernel_dropped`, `interface_dropped`. **Any non-zero `kernel_dropped` or `interface_dropped` means the record is incomplete**, and the summary says so.

`engine_stop` adds `reason`: `duration`, `packet_count`, `end_of_file` or `output_closed`.

## Example

```json
{"schema":"silentsnake.capture/1","seq":5,"ts":"2026-11-25T17:35:00.030000Z","type":"flow_start","flow_id":2,"proto":"tcp","direction":"outbound","initiator":{"ip":"192.168.1.10","port":51000},"responder":{"ip":"93.184.216.34","port":443},"initiator_inferred":false,"service":"https","server_name":"example.com","server_name_source":"dns","summary":"New outbound TCP connection from this machine (192.168.1.10:51000) to 93.184.216.34:443 (HTTPS, example.com via DNS)."}
```

## Exit codes

`0` success · `1` capture or output error · `2` usage error · `3` refused for privilege reasons (running as root, or holding capabilities beyond `CAP_NET_RAW`).
