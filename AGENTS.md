# Repository Guidelines

## Project Structure & Module Organization
- Workspace root (`Cargo.toml`) defines four crates: `slt-core`, `slt-client`, `slt-server`, and `slt-tools`.
- `slt-core/src/` contains shared protocol and crypto primitives.
  - `crypto/` includes TLS/ClientHello helpers plus UDP-QSP packet/session crypto.
  - `config/` defines `ClientConfig` and `ServerConfig` with parsing/validation.
  - `proto/`, `types/`, and `transport/` hold wire formats, domain types, and shared transport helpers.
  - `classifier.rs` implements TCP ClientHello classification.
- `slt-client/src/` is the `client` binary (runtime loop, auth flow, transport switching, TUN I/O, metrics).
- `slt-server/src/` provides the `server` binary plus server library modules (`auth`, `sessions`, `quic`, `tcp`, `tun`, `registry`, `router`, `udp_qsp`, `metrics`).
- `slt-tools/src/bin/` contains helper CLIs (`tcp_client_hello`, `quic_client_hello`).
- `vendor/` includes patched dependencies (`boring`, `boring-sys`, `quiche`).
- `scripts/` holds local capture helpers (e.g., `scripts/chrome-*.sh`).
- `local/` is an ignored scratch directory for temporary files and temporary docs.
- Protocol/design references live in `spec.txt` and `protocol.md`; crate-specific architecture notes are in `client-structure.md` and `server-structure.md`.
- Project status: early-stage development. Prefer clear, correct changes over compatibility preservation; breaking changes are acceptable unless a task explicitly requires compatibility.

## Coding Style & Naming Conventions
- Rust 2024 workspace; format with `cargo fmt --all -- --config imports_granularity=Module,group_imports=StdExternalCrate`.
- Workspace lints are strict: rustc warnings are denied, clippy `all` is denied, and `pedantic`/`nursery` run at warn level.
- Keep shared protocol/config/crypto logic in `slt-core`; keep runtime/orchestration logic in `slt-client` and `slt-server`.
- Prefer small, focused modules and descriptive names (`configure_client_chrome_ssl`, `message_limits_from_mtu`).
- Public library APIs (`pub`) should include doc comments and clear error behavior.

## Testing Guidelines
- Tests live alongside code using `#[cfg(test)]`.
- Run checks from workspace root:
  - `cargo build --workspace`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets`
- For focused changes, run targeted crate checks first (for example `cargo test -p slt-core`) before workspace-wide checks.
- Favor real protocol artifacts (e.g., Boring/quiche-generated handshakes and frames) for tests.

## Commit & Pull Request Guidelines
- Use Conventional Commit messages: `<type>(<scope>): <subject>` (e.g., `feat(slt-core): add udp-qsp key phase tracking`).
- Common types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`.
- Always run `cargo fmt --all -- --config imports_granularity=Module,group_imports=StdExternalCrate` before committing (pre-commit hook also runs fmt --check/clippy/test).
- Commit hooks run tests and may need capabilities unavailable in the sandbox (for example local socket binds). Agents should perform `git commit` outside the sandbox so hooks can run successfully.
- Do not bypass hooks with `--no-verify` unless explicitly requested by the user.
- Run `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets` and fix errors before the final response.
- Changes under `vendor/` must be in a separate commit.
- Separate vendor updates from project changes when possible.
- PRs should describe behavior changes, include relevant commands run, and link any issues.

## Security & Configuration Notes
- `ClientConfig`/`ServerConfig` live in `slt-core::config` and use serde; durations parse with `humantime-serde`.
- Fixed-size keys/IDs are hex-encoded strings in config files via `slt-core/src/types/serde/` helpers.
- Keep `tun_mtu` within `slt_core::config::MAX_TUN_MTU` so UDP-QSP framing fits the Ethernet MTU budget.
- Avoid logging raw secrets or key material; follow the existing “secrets redacted” logging pattern.
