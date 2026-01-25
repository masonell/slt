#!/usr/bin/env bash

set -e
TMP_DIR=/tmp/chrome

mkdir -p "$TMP_DIR"
rm -rf "$TMP_DIR"/*

google-chrome-stable \
    --no-first-run \
    --no-default-browser-check \
    --user-data-dir="$TMP_DIR/chrome-profile" \
    --host-resolver-rules="MAP dns.google.com 8.8.8.8" \
    https://dns.google.com
