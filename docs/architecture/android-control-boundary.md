# Android / Rust Control Boundary

The Android VPN client is two cooperating halves with a deliberate ownership
split. Rust owns the VPN session — protocol state, connection/reconnect policy,
transport selection, terminal-error classification, and the typed event stream.
Android owns the platform — the `VpnService` lifecycle, native-runtime
supervision, the TUN file descriptor, socket protection/binding, DNS through the
active underlying network, foreground-service lifecycle, network observation,
and UI state rendering. The two halves talk through a small UniFFI surface that
carries control and state, never packet data.

This document describes that boundary so future changes keep it clean.

## Ownership split

| Responsibility                                                                         | Owner                                      |
|----------------------------------------------------------------------------------------|--------------------------------------------|
| Connection, auth, in-runtime reconnect/backoff, UDP-QSP upgrade, transport selection   | Rust runtime (`slt-client`)                |
| Session lifecycle event stream (`ClientEvent`)                                         | Rust runtime                               |
| Path recovery on network change (UDP refresh / re-register / TCP fallback / reconnect) | Rust runtime                               |
| Native-runtime restart after terminal events and TUN retention                         | Android (`NativeSessionSupervisor`)        |
| VPN permission flow, `VpnService` foreground lifecycle, notification                   | Android (`SltVpnService`)                  |
| TUN fd establishment and ownership                                                     | Android                                    |
| `VpnService.protect(fd)` + bind to the active `Network`                                | Android (`PlatformServices.protectSocket`) |
| DNS resolution through the active underlying `Network`                                 | Android (`PlatformServices.resolveHost`)   |
| Underlying-network observation + handoff reporting                                     | Android (`NetworkChangeWatcher`)           |
| UI state model and rendering                                                           | Android (`VpnUiState`, `StatusLine`)       |

Rust never touches `VpnService`, Android sockets, or the Android `Network`
directly; it requests those platform operations through callbacks. Rust decides
recovery while its runtime is active and reports whether a terminal error is
retryable. Android does not parse protocol state; it combines that classification
with its fail-closed lifecycle policy when supervising an exited native runtime.

## UniFFI surface

Declared with proc macros next to the Rust implementation
(`slt-client/src/android/uniffi_api.rs`); Kotlin bindings are generated, not
hand-maintained.

- `validate_client_config(config_toml) -> ClientConfigSummary` — pre-flight
  validation used by the profile editor and at tunnel start.
- `start_session(config_toml, tun_fd, mtu, platform_services, callback)
  -> NativeSession` — create a native session over an Android-owned TUN fd.
- `NativeSession.handle()` — the session's globally unique identity.
- `NativeSession.stop()` — request shutdown (joins the worker).
- `NativeSession.network_changed()` — report an underlying-network handoff.
- `PlatformServices.protect_socket(fd, kind) -> SocketProtectionResult` — protect
  and bind a socket while preserving protect rejection, temporary network
  absence, bind failure, and unexpected platform failure as distinct outcomes.
- `PlatformServices.resolve_host(hostname) -> List<String>` — DNS on the active
  network.
- `NativeSessionCallback.on_event(event)` — typed lifecycle callback.

`PlatformServices` and `NativeSessionCallback` are `with_foreign` traits: Rust
holds them as `Arc<dyn …>` and Kotlin supplies the implementations. These are the
only `dyn` dispatch points, and they sit in the platform glue — the runtime core
is monomorphized over concrete `ClientRuntimeServices` (a trait with associated
types, so socket protector / host resolver / observer are all statically
dispatched).

## Session start contract

`start_session` validates everything it can **synchronously, before spawning the
worker thread**: config parse, TUN-mtu consistency, and tokio-runtime creation.
Any failure is returned as a typed `SltInteropError` (no session is created), so
Android surfaces it directly rather than through an event. The worker thread is
left with only TUN-spawn and `run_client`; consequently the only worker-emitted
pre-`run_client` `Error` is a TUN-spawn failure (plus a panic, caught and
reported). `run_client` owns its own terminal `Starting…Stopped`/`Error` stream.

This keeps the worker from racing Android's session-handle assignment and lets
the event identity below be the sole source of truth.

## Typed events and identity

Rust emits typed `ClientEvent { handle, seq, transport, kind }` envelopes through
an `ObserverSink` (`slt-client/src/runtime/observer.rs`). `kind` is a
`ClientEventKind` enum spanning session lifecycle, TCP/auth, the reconnect loop,
UDP registration/upgrade, transport switches, and network-handoff refresh.
Events are non-secret: never keys, tokens, connection IDs, or payloads.

- `handle` — the owning `NativeSession`'s globally unique handle (monotonic
  counter). This is the **sole identity source** Android uses to reject stale
  callbacks from a previous session.
- `seq` — a monotonic per-session sequence number available for ordering.
- `transport` — the active *data-path* transport at event time (stays `Tcp`
  through the upgrade handshake, flips to `UdpQsp` on the switch commit).

Android reduces each event to a richer `VpnUiState` (status, fine-grained phase,
typed transport, reconnect attempt/delay, last error) in `SltVpnStatusBus.applyEvent`
and renders it. `applyEvent` returns a `NativeTerminal` (none / stopped / errored)
so `NativeSessionSupervisor` can restart the native runtime or request platform
teardown; the store owns UI state, and `SltVpnService` owns the VPN/TUN lifecycle.
Because the handle is globally unique and
`nativeHandle` is assigned on the main thread before any `mainHandler.post`
callback can run, a handle mismatch is sufficient to reject stale events — no
separate generation counter is needed.

Extension contract: a new `ClientEventKind` variant requires a new arm in
`applyEvent` (the `when` is exhaustive, so the build fails otherwise) and, if the
variant is terminal, a `NativeTerminal` mapping.

## Terminal supervision and fail-closed policy

The Rust runtime's `retryable` terminal-error field classifies whether restarting
the native runtime is expected to recover without external intervention. Android
also tracks whether an `Authenticated` event has armed fail-closed behavior for
the current Start request. Once armed, Android retains the TUN and periodically
restarts the native runtime after every terminal error. Packets routed into the
VPN remain blocked during restart backoff instead of falling through to the
underlying network.

| Fail-closed armed | Rust `retryable` | Android action                       |
|-------------------|------------------|--------------------------------------|
| No                | `true`           | Restart native, retain TUN           |
| No                | `false`          | Report fatal error and tear down TUN |
| Yes               | Either           | Restart native, retain TUN           |

An explicit Stop or a new Start request clears the fail-closed state. A terminal
error before authentication tears down only when Rust classifies it as
non-retryable, avoiding an indefinite blackhole for a Start request that has
never authenticated successfully.

## Network handoff

Android observes connectivity changes (`NetworkChangeWatcher`), updates the
active underlying `Network` used for socket binding and DNS, and notifies Rust via
`NativeSession.network_changed()`. Rust decides the recovery: refresh the UDP-QSP
path on the current socket, replace the UDP IO backend (preserving crypto state),
fall back to TCP and rediscover/re-register UDP, or reconnect TCP. Android only
maintains platform state and renders the result.

## What stays out of the FFI

Packet bytes never cross the language boundary. Android hands Rust an owned TUN
file descriptor; after startup, all packet I/O stays inside the Rust runtime. If
a future feature needs genuinely high-frequency cross-language calls, add a
focused JNI path for that measured hot path rather than generalizing the UniFFI
surface.
