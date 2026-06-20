# CLAUDE.md

## Architecture Overview

SLT is a VPN implementation that multiplexes VPN traffic with standard web traffic on ports 80/443. It consists of 5 crates:

- **slt-core**: Protocol definitions, crypto primitives, configuration types, packet parsing
- **slt-server**: VPN server with TCP/UDP front doors, client authentication, session management, TUN integration
- **slt-client**: VPN client with connection establishment, authentication, transport switching (TCP ↔ UDP-QSP)
- **slt-cli**: WireGuard-style management CLI (`slt` binary) for project init, key/cert generation, client management, and config validation
- **slt-tools**: CLI utilities for generating TLS/QUIC ClientHello packets

The Android client skeleton lives in `android/` as a standalone Kotlin/Compose Gradle project. It owns Android platform integration such as `VpnService`, VPN permission flow, foreground service lifecycle, and TUN fd creation.

### Key Protocol Concepts

**Traffic Classification**: The server inspects TLS ClientHello `legacy_session_id` for a 32-byte HMAC token to identify VPN clients. Unknown traffic is forwarded to nginx.

**UDP-QSP**: QUIC-shaped packet protection for VPN data. Uses QUIC short headers with AES-128-GCM AEAD. No actual QUIC handshake - just the wire format.

**Frame Format**: All VPN messages use `TYPE(1) + LEN(4) + PAYLOAD` framing. See `docs/protocol/wire-format.md` for message types and `docs/protocol/messages.md` for payload schemas.

**Connection Flow**:
```
TCP connect -> TLS handshake -> AUTH/AUTH_OK -> (optional QUIC discovery) -> REGISTER_CID/REGISTER_OK -> UDP-QSP active
```

## Project Structure & Module Organization
- Workspace root (`Cargo.toml`) defines five crates: `slt-core`, `slt-client`, `slt-server`, `slt-cli`, and `slt-tools`.
- `slt-core/src/` contains shared protocol and crypto primitives.
    - `crypto/` includes TLS/ClientHello helpers plus UDP-QSP packet/session crypto.
    - `config/` defines `ClientConfig` and `ServerConfig` with parsing/validation.
    - `proto/`, `types/`, and `transport/` hold wire formats, domain types, and shared transport helpers.
    - `classifier.rs` implements TCP ClientHello classification.
- `slt-client/src/` is the `client` binary (runtime loop, auth flow, transport switching, TUN I/O, metrics).
- `slt-server/src/` provides the `server` binary plus server library modules (`auth`, `sessions`, `quic`, `tcp`, `tun`, `registry`, `router`, `udp_qsp`, `metrics`).
- `slt-cli/src/` is the `slt` management binary (project init, key/cert generation, client add/remove/list/show, config validation).
- `slt-tools/src/bin/` contains helper CLIs (`tcp_client_hello`, `quic_client_hello`).
- `android/` contains the Android VPN client skeleton:
    - `android/app/src/main/java/dev/slt/android/` holds the Kotlin/Compose UI and `VpnService`.
    - `android/app/src/main/AndroidManifest.xml` declares VPN and foreground-service integration.
    - `android/*.gradle.kts` and `android/gradle.properties` configure the standalone Android Gradle build.
- `vendor/` includes patched dependencies (`boring`, `boring-sys`, `quiche`).
- `scripts/` holds local capture helpers (e.g., `scripts/chrome-*.sh`).
- `local/` is an ignored scratch directory for temporary files and temporary docs.
- Project status: early-stage development. Prefer clear, correct changes over compatibility preservation; breaking changes are acceptable unless a task explicitly requires compatibility.


## Coding Standards

- Rust 2024 edition
- Format Rust with `cargo fmt --all -- --config imports_granularity=Module,group_imports=StdExternalCrate`
- Android code is Kotlin + Jetpack Compose; keep Kotlin/XML formatted with Android Studio defaults until a checked-in formatter is added.
- All `pub` items must have doc comments
- Descriptive names (e.g., `configure_client_chrome_ssl`, `quic_client_chrome_config`)
- Tests colocated with code using `#[cfg(test)]`
- Favor real protocol artifacts in tests over mock data
- **anyhow usage** (for application code like `slt-cli`):
  - Use `.context()` and `.with_context()` to add error context
  - Use `bail!` for early returns with an error
  - Avoid `map_err(|e| anyhow!(...))` - prefer `with_context`

## Commit Guidelines

- Use Conventional Commit messages: `<type>(<scope>): <subject>` (e.g., `feat(slt-core): add udp-qsp key phase tracking`).
- Common types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`.
- Always run `cargo fmt --all -- --config imports_granularity=Module,group_imports=StdExternalCrate` before committing (pre-commit hook also runs fmt --check/clippy/test).
- Run `cargo build`, `cargo test`, and `cargo clippy` before finalizing
- For Android changes, run `gradle assembleDebug` and `gradle testDebugUnitTest lintDebug` from `android/`.
- For Rust Android smoke checks, run `cargo ndk -t x86_64-linux-android build -p slt-client --lib`.
- Changes under `vendor/` must be in a separate commit

## Vendor Update Workflow

- `vendor-versions.toml` is the source of truth for vendored crate versions and patch file paths.
- `scripts/update-vendor.sh sync` recreates `vendor/` from crates.io and reapplies `vendor-patches/*.patch`.
- Refresh `vendor-patches/<crate>.patch` every time `vendor/<crate>/` changes, not just before version upgrades.
- If you edit `vendor/boring-sys/patches/*.patch`, run `scripts/update-vendor.sh capture-patches` so `vendor-patches/boring-sys.patch` stays in sync.
- Version bump flow: update `vendor-versions.toml` -> run `scripts/update-vendor.sh sync` -> resolve/verify vendor changes -> run `scripts/update-vendor.sh capture-patches`.
- Keep vendor-related files (`vendor/`, `vendor-patches/`, `vendor-versions.toml`, and vendoring pin updates) in dedicated commits separate from regular project changes.

## Configuration

- `ClientConfig`/`ServerConfig` use serde with `humantime-serde` for durations
- Fixed-size keys/IDs are hex-encoded strings in TOML config files

## Reference Documentation

Documentation is in `docs/`:

- `docs/README.md`: Documentation index
- `docs/user-guide/`: Installation, quick-start, configuration
- `docs/architecture/`: System design, traffic classification, transport security
- `docs/protocol/`: Wire format, messages, UDP-QSP, connection flow, key update
- `docs/deployment/`: Server/client setup, nginx integration
- `docs/reference/`: Config schema, message types quick reference
