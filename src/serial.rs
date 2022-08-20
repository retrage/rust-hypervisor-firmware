// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Inspired by https://github.com/phil-opp/blog_os/blob/post-03/src/vga_buffer.rs
// from Philipp Oppermann

use core::fmt;

use atomic_refcell::AtomicRefCell;
#[cfg(target_arch = "x86_64")]
use uart_16550::SerialPort;

// We use COM1 as it is the standard first serial port.
#[cfg(target_arch = "x86_64")]
pub static PORT: AtomicRefCell<SerialPort> = AtomicRefCell::new(unsafe { SerialPort::new(0x3f8) });

#[cfg(target_arch = "aarch64")]
pub struct Pl011SerialPort;

#[cfg(target_arch = "aarch64")]
impl Pl011SerialPort {
    pub const fn new() -> Self {
        Self {}
    }

    pub fn init(&mut self) {
        // Do nothing
    }

    pub fn send(&mut self, data: u8) {
        const BASE_ADDR: *mut u8 = 0x0900_0000 as *mut u8;
        unsafe {
            core::ptr::write_volatile(BASE_ADDR, data);
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl fmt::Write for Pl011SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.send(byte);
        }
        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
pub static PORT: AtomicRefCell<Pl011SerialPort> = AtomicRefCell::new(Pl011SerialPort::new());

pub struct Serial;
impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        PORT.borrow_mut().write_str(s)
    }
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        #[cfg(all(feature = "log-serial", not(test)))]
        writeln!($crate::serial::Serial, $($arg)*).unwrap();
        #[cfg(all(feature = "log-serial", test))]
        println!($($arg)*);
    }};
}

#[macro_export]
macro_rules! dbg {
    // NOTE: We cannot use `concat!` to make a static string as a format argument
    // of `eprintln!` because `file!` could contain a `{` or
    // `$val` expression could be a block (`{ .. }`), in which case the `eprintln!`
    // will be malformed.
    () => {
        $crate::log!("[{}:{}]", core::file!(), core::line!())
    };
    ($val:expr $(,)?) => {
        // Use of `match` here is intentional because it affects the lifetimes
        // of temporaries - https://stackoverflow.com/a/48732525/1063961
        match $val {
            tmp => {
                $crate::log!("[{}:{}] {} = {:#?}",
                    core::file!(), core::line!(), core::stringify!($val), &tmp);
                tmp
            }
        }
    };
    ($($val:expr),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
}
