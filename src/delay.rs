// SPDX-License-Identifier: BSD-3-Clause
// Copyright (C) 2020 Akira Moroo
// Copyright (C) 2018 Google LLC

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_rdtsc;

const NSECS_PER_SEC: u64 = 1000000000;
const CPU_KHZ_DEFAULT: u64 = 200;
const PAUSE_THRESHOLD_TICKS: u64 = 150;

#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
pub unsafe fn ndelay(ns: u64) {
    let delta = ns * CPU_KHZ_DEFAULT / NSECS_PER_SEC;
    let mut pause_delta = 0;
    let start = _rdtsc();
    if delta > PAUSE_THRESHOLD_TICKS {
        pause_delta = delta - PAUSE_THRESHOLD_TICKS;
    }
    while _rdtsc() - start < pause_delta {
        asm!("pause");
    }
    while _rdtsc() - start < delta {}
}

#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
pub unsafe fn udelay(us: u64) {
    for _i in 0..us as usize {
        ndelay(1000)
    }
}

#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
pub unsafe fn mdelay(ms: u64) {
    for _i in 0..ms as usize {
        udelay(1000)
    }
}

#[allow(dead_code)]
pub fn wait_while<F>(ms: u64, cond: F) -> bool
where
    F: Fn() -> bool,
{
    let mut us = ms * 1000;
    while cond() && us > 0 {
        unsafe {
            udelay(1);
        }
        us -= 1;
    }
    cond()
}

#[allow(dead_code)]
pub fn wait_until<F>(ms: u64, cond: F) -> bool
where
    F: Fn() -> bool
{
    let mut us = ms * 1000;
    while !cond() && us > 0 {
        unsafe {
            udelay(1);
        }
        us -= 1;
    }
    cond()
}
