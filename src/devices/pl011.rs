// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

use core::fmt;

pub struct Pl011SerialPort;

impl Pl011SerialPort {
    pub const fn new() -> Self {
        Self {}
    }

    pub fn init(&mut self) {
        // Do nothing
    }

    pub fn send(&mut self, data: u8) {
        // TODO: Configure base address from FDT
        const BASE_ADDR: *mut u8 = 0x0900_0000 as *mut u8;
        unsafe {
            core::ptr::write_volatile(BASE_ADDR, data);
        }
    }
}

impl fmt::Write for Pl011SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.send(byte);
        }
        Ok(())
    }
}
