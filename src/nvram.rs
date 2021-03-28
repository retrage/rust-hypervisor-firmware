// SPDX-License-Identifier: BSD-3-Clause
// Copyright (C) 2021 Akira Moroo

use atomic_refcell::AtomicRefCell;
use x86_64::instructions::port::{Port, PortWriteOnly};

static NVRAM: AtomicRefCell<NvRam> = AtomicRefCell::new(NvRam::new());

struct NvRam {
    address_port: PortWriteOnly<u8>,
    data_port: Port<u8>,
}

impl NvRam {
    const fn new() -> Self {
        Self {
            address_port: PortWriteOnly::new(0x70),
            data_port: Port::new(0x71),
        }
    }

    fn read(&mut self, addr: u8) -> u8 {
        assert!(addr < 128);
        unsafe {
            self.address_port.write(addr);
            self.data_port.read()
        }
    }

    #[allow(dead_code)]
    fn write(&mut self, addr: u8, val: u8) {
        assert!(addr < 128);
        unsafe {
            self.address_port.write(addr);
            self.data_port.write(val);
        }
    }
}

fn is_updating() -> bool {
    (NVRAM.borrow_mut().read(10) & 0x80) != 0
}

fn bcd2dec(b: u8) -> u8 {
    ((b >> 4) & 0x0f) * 10 + (b & 0x0f)
}

fn read_rtc(addr: u8) -> u8 {
    bcd2dec(NVRAM.borrow_mut().read(addr))
}

fn wait_update() -> bool {
    let mut timeout = 10000;
    while is_updating() && timeout > 0 {
        timeout -= 1;
    }
    if timeout <= 0 {
        return false;
    }
    true
}

pub fn read_date() -> Result<(u8, u8, u8), ()> {
    if !wait_update() {
        return Err(());
    }
    Ok((read_rtc(9), read_rtc(8), read_rtc(7)))
}

pub fn read_time() -> Result<(u8, u8, u8), ()> {
    if !wait_update() {
        return Err(());
    }
    Ok((read_rtc(4), read_rtc(2), read_rtc(0)))
}
