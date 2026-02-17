#!/usr/bin/env bash

set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly VERSIONS_FILE="${VERSIONS_FILE:-${ROOT_DIR}/vendor-versions.toml}"
readonly CRATES=("boring" "boring-sys" "quiche")

usage() {
    cat <<'EOF'
Usage:
  scripts/update-vendor.sh sync
  scripts/update-vendor.sh capture-patches

Commands:
  sync             Refresh vendor crates from versions in vendor-versions.toml,
                   re-apply local patch files, and update Cargo.toml pins.
  capture-patches  Compare current vendor crates against crate sources from
                   vendor-versions.toml and write patch files under vendor-patches/.
EOF
}

log() {
    printf '%s\n' "$*"
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

manifest_get() {
    local section="$1"
    local key="$2"

    awk -v section="$section" -v key="$key" '
        function trim(s) {
            sub(/^[[:space:]]+/, "", s);
            sub(/[[:space:]]+$/, "", s);
            return s;
        }

        BEGIN {
            in_section = 0;
        }

        {
            line = $0;
            sub(/[[:space:]]*#.*/, "", line);

            if (line ~ /^[[:space:]]*\[/) {
                in_section = (trim(line) == "[" section "]");
                next;
            }

            if (!in_section) {
                next;
            }

            split(line, parts, "=");
            if (length(parts) < 2) {
                next;
            }

            lhs = trim(parts[1]);
            if (lhs != key) {
                next;
            }

            rhs = substr(line, index(line, "=") + 1);
            rhs = trim(rhs);

            if (rhs ~ /^".*"$/) {
                sub(/^"/, "", rhs);
                sub(/"$/, "", rhs);
                print rhs;
                exit;
            }
        }
    ' "$VERSIONS_FILE"
}

manifest_get_required() {
    local section="$1"
    local key="$2"
    local value

    value="$(manifest_get "$section" "$key")"
    [[ -n "$value" ]] || die "missing ${key} in [${section}] of ${VERSIONS_FILE}"
    printf '%s\n' "$value"
}

manifest_get_optional() {
    local section="$1"
    local key="$2"

    manifest_get "$section" "$key" || true
}

download_and_extract_crate() {
    local crate="$1"
    local version="$2"
    local destination="$3"
    local tmpdir archive url extracted

    tmpdir="$(mktemp -d)"
    archive="${tmpdir}/${crate}-${version}.crate"
    url="https://static.crates.io/crates/${crate}/${crate}-${version}.crate"

    log "Downloading ${crate}@${version}"
    curl -fsSL "$url" -o "$archive"

    tar -xzf "$archive" -C "$tmpdir"
    extracted="${tmpdir}/${crate}-${version}"
    if [[ ! -d "$extracted" ]]; then
        extracted="$(find "$tmpdir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
    fi
    [[ -d "$extracted" ]] || die "failed to extract ${crate}@${version}"

    rm -rf "$destination"
    mkdir -p "$destination"
    cp -a "${extracted}/." "$destination/"

    rm -rf "$tmpdir"
}

apply_crate_patch() {
    local crate="$1"
    local patch_rel="$2"
    local patch_abs="${ROOT_DIR}/${patch_rel}"

    if [[ ! -f "$patch_abs" ]]; then
        log "Patch file not found for ${crate}, skipping: ${patch_rel}"
        return
    fi

    if [[ ! -s "$patch_abs" ]]; then
        log "Patch file is empty for ${crate}, skipping: ${patch_rel}"
        return
    fi

    log "Applying ${patch_rel} to vendor/${crate}"
    (
        cd "${ROOT_DIR}"
        git apply --whitespace=nowarn --directory="vendor/${crate}" "$patch_abs"
    )
}

update_workspace_dep_version() {
    local dep_key="$1"
    local dep_version="$2"
    local file="${ROOT_DIR}/Cargo.toml"
    local tmp_file="${file}.tmp"

    awk -v dep_key="$dep_key" -v dep_version="$dep_version" '
        function trim(s) {
            sub(/^[[:space:]]+/, "", s);
            sub(/[[:space:]]+$/, "", s);
            return s;
        }

        BEGIN {
            in_workspace_deps = 0;
            updated = 0;
        }

        /^\[workspace\.dependencies\]/ {
            in_workspace_deps = 1;
            print;
            next;
        }

        /^\[/ && $0 !~ /^\[workspace\.dependencies\]/ {
            in_workspace_deps = 0;
        }

        {
            if (in_workspace_deps) {
                line = $0;
                sub(/[[:space:]]*#.*/, "", line);
                split(line, parts, "=");
                lhs = trim(parts[1]);

                if (lhs == dep_key) {
                    print dep_key " = \"" dep_version "\"";
                    updated = 1;
                    next;
                }
            }

            print;
        }

        END {
            if (!updated) {
                exit 2;
            }
        }
    ' "$file" > "$tmp_file" || die "failed to update ${dep_key} in ${file}"

    mv "$tmp_file" "$file"
}

update_workspace_dep_inline_table_version() {
    local dep_key="$1"
    local dep_version="$2"
    local file="${ROOT_DIR}/Cargo.toml"
    local tmp_file="${file}.tmp"

    awk -v dep_key="$dep_key" -v dep_version="$dep_version" '
        function trim(s) {
            sub(/^[[:space:]]+/, "", s);
            sub(/[[:space:]]+$/, "", s);
            return s;
        }

        BEGIN {
            in_workspace_deps = 0;
            updated = 0;
        }

        /^\[workspace\.dependencies\]/ {
            in_workspace_deps = 1;
            print;
            next;
        }

        /^\[/ && $0 !~ /^\[workspace\.dependencies\]/ {
            in_workspace_deps = 0;
        }

        {
            if (in_workspace_deps) {
                line = $0;
                stripped = line;
                sub(/[[:space:]]*#.*/, "", stripped);
                split(stripped, parts, "=");
                lhs = trim(parts[1]);

                if (lhs == dep_key) {
                    updated_line = line;
                    if (updated_line ~ /version[[:space:]]*=/) {
                        gsub(/version[[:space:]]*=[[:space:]]*"[^"]*"/, "version = \"" dep_version "\"", updated_line);
                        print updated_line;
                        updated = 1;
                        next;
                    }
                }
            }

            print;
        }

        END {
            if (!updated) {
                exit 2;
            }
        }
    ' "$file" > "$tmp_file" || die "failed to update inline table version for ${dep_key} in ${file}"

    mv "$tmp_file" "$file"
}

update_quiche_boring_dep_version() {
    local dep_version="$1"
    local file="${ROOT_DIR}/vendor/quiche/Cargo.toml"
    local tmp_file="${file}.tmp"

    awk -v dep_version="$dep_version" '
        BEGIN {
            in_boring_section = 0;
            updated = 0;
        }

        /^\[dependencies\.boring\]/ {
            in_boring_section = 1;
            print;
            next;
        }

        /^\[/ && $0 !~ /^\[dependencies\.boring\]/ {
            in_boring_section = 0;
        }

        {
            if (in_boring_section && $0 ~ /^[[:space:]]*version[[:space:]]*=/) {
                print "version = \"" dep_version "\"";
                updated = 1;
                in_boring_section = 0;
                next;
            }

            print;
        }

        END {
            if (!updated) {
                exit 2;
            }
        }
    ' "$file" > "$tmp_file" || die "failed to update quiche boring dep version in ${file}"

    mv "$tmp_file" "$file"
}

sync_crate() {
    local crate="$1"
    local version patch_rel

    version="$(manifest_get_required "versions" "$crate")"
    patch_rel="$(manifest_get_optional "patches" "$crate")"

    download_and_extract_crate "$crate" "$version" "${ROOT_DIR}/vendor/${crate}"

    if [[ -n "$patch_rel" ]]; then
        apply_crate_patch "$crate" "$patch_rel"
    fi
}

capture_patch_for_crate() {
    local crate="$1"
    local version patch_rel patch_abs
    local temp_dir baseline_dir compare_dir patch_temp

    version="$(manifest_get_required "versions" "$crate")"
    patch_rel="$(manifest_get_optional "patches" "$crate")"

    if [[ -z "$patch_rel" ]]; then
        log "No patch path configured for ${crate}; skipping patch capture"
        return
    fi

    patch_abs="${ROOT_DIR}/${patch_rel}"
    temp_dir="$(mktemp -d)"
    baseline_dir="${temp_dir}/baseline"
    compare_dir="${temp_dir}/compare"
    patch_temp="${temp_dir}/patch.diff"

    download_and_extract_crate "$crate" "$version" "$baseline_dir"

    cp -a "${baseline_dir}/." "$compare_dir/"
    (
        cd "$compare_dir"
        git init -q
        git add -A
        git -c user.name="vendor-bot" \
            -c user.email="vendor-bot@example.invalid" \
            commit -q -m "baseline"
    )

    rsync -a --delete --exclude=".git/" "${ROOT_DIR}/vendor/${crate}/" "${compare_dir}/"

    if (
        cd "$compare_dir"
        git add -A
        git diff --cached --quiet --exit-code
    ); then
        rm -f "$patch_abs"
        log "No local changes for ${crate}; removed ${patch_rel}"
    else
        local diff_status=$?
        if [[ "$diff_status" -ne 1 ]]; then
            die "failed to diff ${crate} while capturing patches"
        fi
        (
            cd "$compare_dir"
            git diff --cached --binary > "$patch_temp"
        )
        mkdir -p "$(dirname "$patch_abs")"
        mv "$patch_temp" "$patch_abs"
        log "Wrote ${patch_rel}"
    fi

    rm -rf "$temp_dir"
}

run_sync() {
    local boring_version boring_sys_version tokio_boring_version quiche_version

    boring_version="$(manifest_get_required "versions" "boring")"
    boring_sys_version="$(manifest_get_required "versions" "boring-sys")"
    tokio_boring_version="$(manifest_get_required "versions" "tokio-boring")"
    quiche_version="$(manifest_get_required "versions" "quiche")"

    for crate in "${CRATES[@]}"; do
        sync_crate "$crate"
    done

    update_workspace_dep_version "boring" "$boring_version"
    update_workspace_dep_version "boring-sys" "$boring_sys_version"
    update_workspace_dep_version "tokio-boring" "$tokio_boring_version"
    update_workspace_dep_inline_table_version "quiche" "$quiche_version"
    update_quiche_boring_dep_version "$boring_version"

    log "Vendor sync complete."
}

run_capture_patches() {
    for crate in "${CRATES[@]}"; do
        capture_patch_for_crate "$crate"
    done

    log "Patch capture complete."
}

main() {
    local command="${1:-sync}"

    [[ -f "$VERSIONS_FILE" ]] || die "versions file not found: ${VERSIONS_FILE}"

    need_cmd awk
    need_cmd cp
    need_cmd curl
    need_cmd find
    need_cmd git
    need_cmd mktemp
    need_cmd rsync
    need_cmd tar

    case "$command" in
        sync)
            run_sync
            ;;
        capture-patches)
            run_capture_patches
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            usage
            die "unknown command: ${command}"
            ;;
    esac
}

main "$@"
