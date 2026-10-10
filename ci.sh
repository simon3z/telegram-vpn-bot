#!/usr/bin/env bash
# CI quality gate for telegram-vpn-bot.
# Usage: ./ci.sh
set -euo pipefail
cd "$(dirname "$0")"

cargo fmt --check
cargo clippy --release --all-targets -- -D warnings
cargo test --release --all-targets

echo "✓ All checks passed."
