# Vendored Crates

The workspace patches these crates from local paths:
- `vendor/boring`
- `vendor/boring-sys`
- `vendor/quiche`

Versions and patch paths are defined in `vendor-versions.toml`.

## Update Workflow

1. Edit versions in `vendor-versions.toml`.
2. Run `scripts/update-vendor.sh sync`.
3. If local crate edits are needed, apply them in `vendor/`, then run:
   `scripts/update-vendor.sh capture-patches`
4. Validate:
   - `cargo build --workspace`
   - `cargo test --workspace`
   - `cargo clippy --workspace`
5. Commit vendor changes in a dedicated commit.

## Why this exists

Keeping local crate deltas as patch files makes future version bumps mechanical:
replace sources, reapply patches, and resolve only real upstream conflicts.
