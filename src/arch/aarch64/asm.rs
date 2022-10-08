// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

use core::arch::global_asm;

#[cfg(target_arch = "aarch64")]
global_asm!(include_str!("ram64.s"));
