#!/bin/bash

set -ex

source "${CARGO_HOME:-$HOME/.cargo}/env"

export RUSTFLAGS="-D warnings"

TARGET="x86_64-unknown-none.json"

# Install cargo components
time rustup component add clippy
time rustup component add rustfmt
time rustup component add rust-src

# Run cargo builds and checks
time cargo build --target "$TARGET" -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem
time cargo build --release --target "$TARGET" -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem
time cargo build --target "$TARGET" --features "coreboot" -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem
time cargo build --release --target "$TARGET" --features "coreboot" -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem
time cargo clippy --target "$TARGET" -Zbuild-std=core,alloc
time cargo clippy --target "$TARGET" -Zbuild-std=core,alloc --features "coreboot"
time cargo clippy --all-targets --all-features
time cargo fmt --all -- --check
