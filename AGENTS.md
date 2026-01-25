# Repository Guidelines

## Project Structure & Module Organization
- `src/` contains the Rust library and helpers.
  - `src/crypto/` holds TLS/QUIC helpers (ClientHello tooling, Chrome-like config).
  - `src/classifier.rs` implements the TCP ClientHello classifier.
  - `src/config/` defines `ClientConfig` and `ServerConfig` plus serde helpers.
  - `src/bin/` contains small CLI tools for emitting TLS/QUIC ClientHello packets.
- `vendor/` includes patched dependencies (`boring`, `boring-sys`, `quiche`).
- `scripts/` holds local capture helpers (e.g., `scripts/chrome-*.sh`).
- `spec.txt` is the protocol/design reference.

## Coding Style & Naming Conventions
- Rust 2024 edition, formatted with `cargo fmt`.
- Prefer small, focused helpers in `src/crypto/` and `src/config/`.
- Use descriptive names (`configure_client_chrome_ssl`, `quic_client_chrome_config`).
- Public items (`pub`) must include doc comments.

## Testing Guidelines
- Tests live alongside code using `#[cfg(test)]`.
- Run `cargo test` locally; no additional test harness required.
- Favor real protocol artifacts (e.g., Boring-generated ClientHello) for tests.

## Commit & Pull Request Guidelines
- Use short, imperative commit messages (e.g., “add config module”).
- Always run `cargo fmt` before committing.
- Run `cargo build`, `cargo test`, and `cargo clippy` and fix errors before the final response.
- Changes under `vendor/` must be in a separate commit.
- Separate vendor updates from project changes when possible.
- PRs should describe behavior changes, include relevant commands run, and link any issues.

## Security & Configuration Notes
- `ClientConfig`/`ServerConfig` use serde; durations parse with `humantime-serde`.
- Fixed-size keys/IDs are hex-encoded strings in config files.
