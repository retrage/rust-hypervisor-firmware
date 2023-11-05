// SPDX-License-Identifier: Apache-2.0
// Copyright © 2019 Intel Corporation

// Inspired by https://github.com/phil-opp/blog_os/blob/post-03/src/vga_buffer.rs
// from Philipp Oppermann

use core::fmt;

use atomic_refcell::AtomicRefCell;

#[cfg(target_arch = "aarch64")]
use crate::{arch::aarch64::layout::map, uart_pl011::Pl011 as UartPl011};

#[cfg(target_arch = "x86_64")]
use uart_16550::SerialPort as Uart16550;

#[cfg(target_arch = "riscv64")]
use crate::uart_mmio::UartMmio;

// We use COM1 as it is the standard first serial port.
#[cfg(target_arch = "x86_64")]
pub static PORT: AtomicRefCell<Uart16550> = AtomicRefCell::new(unsafe { Uart16550::new(0x3f8) });

#[cfg(target_arch = "aarch64")]
pub static PORT: AtomicRefCell<UartPl011> =
    AtomicRefCell::new(UartPl011::new(map::mmio::PL011_START));

// TODO: Fill from FDT?
#[cfg(target_arch = "riscv64")]
const SERIAL_PORT_ADDRESS: u64 = 0x1000_0000;
#[cfg(target_arch = "riscv64")]
pub static PORT: AtomicRefCell<UartMmio> = AtomicRefCell::new(UartMmio::new(SERIAL_PORT_ADDRESS));

pub struct Serial;
impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        PORT.borrow_mut().write_str(s)
    }
}

pub struct Logger;

impl Logger {
    pub fn init() {
        log::set_logger(&LOGGER)
            .map(|()| log::set_max_level(log::LevelFilter::Info))
            .unwrap();
    }
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        if cfg!(not(feature = "log-serial")) {
            return false;
        }
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record) {
        use core::fmt::Write;
        if self.enabled(record.metadata()) {
            writeln!(
                Serial,
                "[{}] {} - {}",
                record.level(),
                record.target(),
                record.args()
            )
            .unwrap();
        }
    }

    fn flush(&self) {}
}

pub static LOGGER: Logger = Logger;
