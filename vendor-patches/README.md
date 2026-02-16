# Vendor Patch Queue

This directory stores local diffs for vendored crates in `vendor/`.

Patch files are generated and re-applied by `scripts/update-vendor.sh`:

1. `scripts/update-vendor.sh capture-patches`
2. `scripts/update-vendor.sh sync`

Patch destinations are configured in `vendor-versions.toml` under `[patches]`.

Notes:
- Missing or empty patch files are treated as "no local patch".
- Keep patches focused and remove them when upstream releases include the change.
- Commit `vendor/` refreshes separately from non-vendor edits.
