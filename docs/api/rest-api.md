# Local REST API: `silentsnake.api/1`

`silentsnake-api` (Go, standard library only) runs the capture engine as a child process, aggregates its [capture events](capture-events.md), and serves them to the dashboard. The dashboard is its only intended client.

## Security model
- **Listens on `127.0.0.1:8765` only.** `--listen` accepts no other host. Each request is also checked: the peer must be IPv4 loopback, and `Host` must be `127.0.0.1:8765` or `localhost:8765`, which defends against DNS rebinding.
- **Bearer token.** `Authorization: Bearer <token>`, compared in constant time. On first run the token is created as 32 random bytes in hex at `$XDG_DATA_HOME/silentsnake/config/api-token` (default `~/.local/share/...`), mode 0600, in 0700 directories. The API refuses to start if any of these is looser, is a symlink, or isn't owned by the user.
- **Read-only.** Only `GET` is accepted, and nothing in the API changes capture, permissions or config.
- **Strict input.** Only documented query parameters are accepted, each once. `limit` is an integer from 1 to 500. Anything else is `400` with a JSON error.
- **Rate limit.** 20 requests/s per process, burst 40 (`429` + `Retry-After`). At most 4 concurrent streams.
- **No privileges.** The API refuses root and holds no capabilities. Only the capture binary has `CAP_NET_RAW`.

## Running
```sh
silentsnake-api [--capture-bin ~/.local/bin/silentsnake-capture] [--interface any] [--listen 127.0.0.1:8765]
```
If the engine exits, the API restarts it with backoff (1 s, doubling, max 60 s). The failure is visible in `/v1/overview` (`engine.running: false`, `engine.last_error`, plus a risk reason).

## Endpoints

| Endpoint | Returns |
|---|---|
| `GET /v1/health` | `{"status":"ok","api":"silentsnake.api/1"}` |
| `GET /v1/overview` | `risk` {`score` 0–100, `level`, `color`, `reasons[]`}, `engine` {`running`, `interface`, `version`, `started_at`, `packets_seen`, `bytes_seen`, `flows_active`, `kernel_dropped`, `incomplete`, `last_error`, `events_rejected`}, `active_flows`, `flagged_flows`, `traffic_per_minute` [{`minute`, `bytes`, `flows`}] (last 60), `top_destinations` [{`name`, `bytes`, `flows`}] (top 10), `generated_at` |
| `GET /v1/connections?state=active\|recent\|all&limit=N` | `connections`: active flows newest first, then recently ended ones (last 500). Each has the flow fields from the capture schema plus `started`, `last_seen`, `ended`, `end_reason`, `initiator_bytes`, `responder_bytes`, `tls_anomalies`, `risk`, `risk_reasons`, `status` (`allowed` or `flagged`; stage A observes and never blocks), `summary` |
| `GET /v1/events?limit=N` | `events`: the last N capture events {`seq`, `ts`, `type`, `summary`, `flow_id`} for the live log |
| `GET /v1/stream` | Server-Sent Events: `event: log` (one per capture event) and `event: overview` (every second, plus `stream_dropped`: events this slow client missed) |

## Risk score v0

The score is a transparent heuristic over what stage A can see. It is a prompt to look, **not a verdict**. Every point comes with a reason in plain English. Per flow:

| Rule | Points |
|---|---|
| Inbound connection (another machine opened it) | +25 |
| Transit traffic (neither end is this machine) | +10 |
| Unencrypted TCP service to a non-local peer: FTP 21, Telnet 23, HTTP 80, POP3 110, IMAP 143, LDAP 389 | +20 |
| Outbound TCP to a port ≥ 1024 with no known service | +10 |
| Each TLS ClientHello anomaly reported by the engine | +30 |

A flow scoring 50 or more is `flagged`. The overall score is the riskiest flow seen in the last 5 minutes. On top of that, two engine signals from the last 10 minutes add points: UDP trailing-byte evasion (+40) and capture drops making the record incomplete (+15). The total is capped at 100. Levels: 0–24 `low` (green), 25–49 `guarded` (yellow), 50–74 `elevated` (orange), 75–100 `high` (red). A colour always travels with its label and number.

Process and systemd-unit attribution (stage C) will add per-process rules. The rule table is Ronin's to change.

## Versioning
Fields may be added within `/1`. Renaming or removing a field, or changing its meaning, bumps the version to `/2`. Clients must ignore unknown fields.
