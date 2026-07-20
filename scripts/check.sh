#!/usr/bin/env bash
set -euo pipefail

echo "--- cargo fmt ---"
cargo fmt --all -- --check

echo "--- cargo check ---"
cargo check --all-targets --all-features

echo "--- cargo clippy ---"
cargo clippy --all-targets --all-features -- --deny warnings

echo "--- cargo build ---"
cargo build --release

echo "--- cargo test ---"
cargo test --all-targets --all-features

echo "All checks passed."
