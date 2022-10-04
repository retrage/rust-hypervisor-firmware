// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

#[cfg(target_arch = "x86_64")]
pub mod cmos;
#[cfg(target_arch = "aarch64")]
pub mod pl011;
#[cfg(target_arch = "aarch64")]
pub mod pl031;
