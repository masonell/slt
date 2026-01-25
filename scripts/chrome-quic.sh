#!/usr/bin/env bash

set -e
TMP_DIR=/tmp/chrome

mkdir -p "$TMP_DIR"
rm -rf "$TMP_DIR"/*

google-chrome-stable \
    --no-first-run \
    --no-default-browser-check \
    --enable-quic \
    --user-data-dir="$TMP_DIR/chrome-profile" \
    https://cloudflare-quic.com/
