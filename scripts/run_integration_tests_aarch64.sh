#!/bin/bash
set -x

source "${CARGO_HOME:-$HOME/.cargo}/env"
source $(dirname "$0")/fetch_disk_images.sh

TARGET="aarch64-unknown-none.json"

WORKLOADS_DIR="$HOME/workloads"
mkdir -p "$WORKLOADS_DIR"

CH_VERSION="v27.0"
CH_URL="https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$CH_VERSION/cloud-hypervisor-static-aarch64"
CH_PATH="$WORKLOADS_DIR/cloud-hypervisor"
if [ ! -f "$CH_PATH" ]; then
    wget --quiet $CH_URL -O $CH_PATH
    chmod +x $CH_PATH
    sudo setcap cap_net_admin+ep $CH_PATH
fi

BIONIC_OS_IMAGE_DOWNLOAD_NAME="bionic-server-cloudimg-arm64.img"
BIONIC_OS_IMAGE_DOWNLOAD_URL="https://cloud-hypervisor.azureedge.net/$BIONIC_OS_IMAGE_DOWNLOAD_NAME"
BIONIC_OS_DOWNLOAD_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_IMAGE_DOWNLOAD_NAME"
if [ ! -f "$BIONIC_OS_DOWNLOAD_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time wget --quiet $BIONIC_OS_IMAGE_DOWNLOAD_URL || exit 1
    popd
fi

BIONIC_OS_RAW_IMAGE_NAME="bionic-server-cloudimg-arm64.raw"
BIONIC_OS_RAW_IMAGE="$WORKLOADS_DIR/$BIONIC_OS_RAW_IMAGE_NAME"
if [ ! -f "$BIONIC_OS_RAW_IMAGE" ]; then
    pushd $WORKLOADS_DIR
    time qemu-img convert -p -f qcow2 -O raw $BIONIC_OS_IMAGE_DOWNLOAD_NAME $BIONIC_OS_RAW_IMAGE_NAME || exit 1
    popd
fi

rustup component add rust-src
cargo build --release --target "$TARGET" -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem

export RUST_BACKTRACE=1
time cargo test --features "integration_tests" "integration::tests::linux"
