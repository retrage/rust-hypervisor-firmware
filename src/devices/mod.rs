// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

pub mod block;
#[cfg(target_arch = "aarch64")]
pub mod mmio;
pub mod pci;
#[cfg(target_arch = "aarch64")]
pub mod pl011;
#[cfg(target_arch = "aarch64")]
pub mod pl031;
#[cfg(target_arch = "x86_64")]
pub mod rtc;
pub mod virtio;
