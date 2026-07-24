#!/usr/bin/env bash
set -euo pipefail

export LLVM_PROFDATA="$(which llvm-profdata)"
export LLVM_COV="$(which llvm-cov)"

cargo llvm-cov --all-targets --all-features --html

echo "--- Summary ---"
cargo llvm-cov report | grep '^TOTAL'
