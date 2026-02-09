# Client Code Structure (Desired)

This document describes the target structure for the `slt-client` crate as the
client implementation is completed (see `client-tasks-do-not-commit.md` for the
feature checklist).

Goals:
- Keep responsibilities obvious and local (each file has one reason to change).
- Make the client runtime read like a state machine: `tcp -> auth -> (optional) quic_discovery -> (optional) register -> run`.
- Centralize cross-cutting glue (TLS CA loading, message I/O, timeouts) so it is not duplicated across modules.
- Keep protocol definitions and crypto primitives in `slt-core`; keep I/O and orchestration in `slt-client`.

Non-goals:
- No behavior changes implied by this structure. It is a map for refactors and new code.
- No attempt to hide all `tokio`/I/O details behind heavy abstractions.

## Proposed module tree

Target `slt-client/src/` layout:

```text
slt-client/src/
  main.rs                 CLI bootstrap: parse args, init tracing, load config
  app.rs                  `run(config, cancel)` orchestration wrapper

  runtime/
    mod.rs                 high-level runtime entry + shared structs
    session.rs             steady-state session loop (ping/idle, DATA pump)
    register.rs            REGISTER_CID + UDP-QSP verification + transport switch

  transport/
    mod.rs                 transport types and traits (minimal)
    tcp.rs                 TCP+TLS connect/handshake and framed message I/O
    udp_qsp.rs             UDP-QSP framed message I/O (protect/open + datagrams)
    quic_discovery.rs      real QUIC handshake to nginx to discover DCIDs
    tls.rs                 CA loading helpers for boring/quiche

  auth.rs                  AUTH phase (TLS exporter + signature + AUTH_OK/FALSE)
  tun.rs                   TUN read/write tasks + channel plumbing (anti-spoof)
  wire.rs                  small message helpers (buffer management, encode/write)
```

Notes:
- `wire.rs` is deliberately tiny and boring: it exists to remove repeated decode loops and "split_off/replace" patterns.
- The `transport/` module is not an attempt to generalize everything; it just prevents `runtime` from owning per-transport details.

## Layering and ownership rules

To avoid the "functionality spread without thought" feeling, enforce these boundaries:

1. `main.rs` owns process concerns only.
   - CLI args and tracing init live here.
   - It should not know about protocol messages or socket details.

2. `app.rs` owns top-level orchestration and logging of major milestones.
   - `app::run(config, cancel)` is the entrypoint called by `main`.
   - It calls into `runtime` and handles high-level error reporting.

3. `runtime/` owns state transitions and steady-state behavior.
   - `runtime::run_client(...)` sequences phases and constructs the session loop.
   - `runtime::session` does the long-running select loop.
   - `runtime::register` does the upgrade path: register, verify, switch, fallback policy.

4. `transport/` owns the mechanics of each channel.
   - `transport::tcp` owns TCP connect + TLS handshake and provides framed read/write helpers.
   - `transport::udp_qsp` owns UDP-QSP packetization and provides framed read/write helpers.
   - `transport::quic_discovery` owns QUIC handshake-to-nginx used only to obtain DCIDs.
   - `transport::tls` owns CA-loading so TCP+QUIC do not reimplement it.

5. `auth.rs` owns only the AUTH state machine.
   - It should operate on a "framed TCP transport" interface, not raw buffers if possible.
   - It returns an outcome with "leftover bytes" or relies on the shared read buffer model below.

6. `tun.rs` owns only the TUN tasks and channel backpressure policy.
   - It should not parse protocol frames.
   - It enforces anti-spoof (src_ip must equal `assigned_ipv4`) before forwarding.

## Shared data model (types to converge on)

The runtime becomes easier to read if it passes around a small set of explicit structs:

- `TcpTransport` (in `transport/tcp.rs`)
  - Owns `SslStream<TcpStream>` plus a read buffer.
  - Exposes `read_next_message()` and `write_message(message)` helpers.

- `UdpQspTransport` (in `transport/udp_qsp.rs`)
  - Owns `QuicQspSession<...>` plus peer/socket.
  - Exposes the same `read_next_message()` and `write_message(message)` helpers.

- `ClientSession` (in `runtime/session.rs`)
  - Owns:
    - TUN channels (to/from session)
    - TCP transport (always present while connected)
    - optional UDP-QSP transport (after registration)
    - active transport state, timers, and limits
  - Implements the session loop for:
    - TCP `DATA` <-> TUN `packet`
    - ping/pong
    - idle timeout
    - close/shutdown

- `UpgradeContext` (in `runtime/register.rs`)
  - Owns the QUIC ids and any policy for retries/backoff/verification.

This mirrors the server shape in `slt-server/src/sessions/mod.rs` while keeping client-specific behavior local.

## Read buffer and message I/O conventions

The current code uses a "shared read buffer" pattern on TCP (AUTH and REGISTER preserve leftovers).
Keep that pattern, but make it consistent:

- There is exactly one TCP read buffer owned by `TcpTransport`.
- Any phase (auth/register/session) that needs to read from TCP uses the same buffer.
- Decoding follows a standard loop:
  1. If a full message exists in `read_buf`, consume it and handle it.
  2. Otherwise read more bytes into `read_buf` (with deadline/cancel handling).

This removes ad-hoc "decode twice" and repeated `split_off/replace` boilerplate.

`wire.rs` should provide utilities like:
- `try_decode_one(read_buf, limits) -> Result<Option<MessageAndConsumed>, io::Error>`
- `consume_prefix(read_buf, consumed) -> Vec<u8>` (or equivalent) to keep the "leftover" operation uniform.

## Transport switch and fallback (Task 8+)

Desired behavior for Task 8-10 should live in `runtime/register.rs` and `runtime/session.rs`:

- Registration is a distinct sub-state:
  - TCP remains active for control while awaiting REGISTER_*.
  - During registration, `DATA` frames received on TCP are still allowed and forwarded to TUN.

- Verification is explicit:
  - After `REGISTER_OK`, client expects UDP-QSP `PING` from the server.
  - Client replies `PONG` over UDP-QSP and marks UDP verified.
  - Only after verification does `active_transport` switch to UDP-QSP for `DATA` and keepalives.

- Fallback policy is centralized:
  - If UDP verify times out, stay on TCP.
  - If UDP becomes idle/unhealthy, fall back to TCP if still connected.
  - If TCP is lost, tear down UDP-QSP and reconnect from scratch with backoff.

The important structural point: the transport switch policy is not spread across `quic.rs`, `runtime.rs`, and `tcp.rs`.

## Logging and error conventions

- `main.rs` and `app.rs` should log "big steps" (startup, auth ok/fail, upgrade ok/fail, shutdown).
- `runtime/session.rs` should log per-session lifecycle and liveness events at `info` or `debug`.
- `transport/*` should avoid `info` logs; use `debug/trace` for mechanics.
- Avoid generic `io::Error::other(format!("{err:?}"))` at call sites when a typed error exists.
  - If we keep using `io::Error` for plumbing, concentrate mapping helpers in `wire.rs` or the specific transport module.

## Incremental refactor plan (no behavior change)

Current file mapping into the target tree:
- `slt-client/src/main.rs` stays `main.rs` (but shrinks as `app.rs` grows).
- `slt-client/src/runtime.rs` splits into `runtime/mod.rs`, `runtime/session.rs`, and `runtime/register.rs`.
- `slt-client/src/tcp.rs` moves to `transport/tcp.rs`.
- `slt-client/src/quic.rs` moves to `transport/quic_discovery.rs`.
- `slt-client/src/auth.rs` stays `auth.rs` (updated to use `wire.rs` + `TcpTransport`).
- `slt-client/src/tun.rs` stays `tun.rs` (unchanged responsibilities).

1. Introduce `transport/tls.rs` and move CA-loading logic out of `tcp.rs` and `quic.rs`.
2. Introduce `wire.rs` with the shared "decode-consume" helper used by AUTH, REGISTER, and session.
3. Split the current `runtime.rs` into `runtime/mod.rs`, `runtime/session.rs`, and `runtime/register.rs`.
4. Move QUIC discovery code into `transport/quic_discovery.rs` (keeping the current API shape).

After these steps, implementing Task 8-10 becomes additive work rather than fighting file boundaries.
