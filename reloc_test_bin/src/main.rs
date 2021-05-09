#![no_std]
#![no_main]

use core::panic::PanicInfo;

use x86_64::instructions::hlt;

#[macro_use]
mod serial;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log!("PANIC: {}", info);
    loop {
        hlt()
    }
}

#[no_mangle]
fn main() {
    serial::PORT.borrow_mut().init();

    log!("Hello, world!");
}
