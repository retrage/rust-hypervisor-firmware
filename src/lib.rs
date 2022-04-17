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

#![feature(alloc_error_handler)]
#![feature(stmt_expr_attributes)]
#![cfg_attr(not(test), no_std)]
// #![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(unused_imports, dead_code))]
#![cfg_attr(not(feature = "log-serial"), allow(unused_variables, unused_imports))]

use core::ffi::c_void;
use cty::*;
use cstr_core::CStr;
use uuid::Uuid;

use core::panic::PanicInfo;

#[macro_use]
mod serial;

#[macro_use]
mod common;

// #[cfg(not(test))]
// mod asm;
mod block;
mod boot;
mod bzimage;
// mod coreboot;
mod delay;
mod efi;
mod fat;
// mod gdt;
// #[cfg(all(test, feature = "integration_tests"))]
// mod integration;
mod loader;
mod mem;
// mod paging;
mod part;
// mod pci;
mod pe;
// mod pvh;
// mod rtc;
// mod virtio;

#[cfg(all(not(test), feature = "log-panic", target_arch = "x86_64"))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log!("PANIC: {}", info);
    loop {
        hlt()
    }
}

extern "C" {
    fn flush_and_reboot();
}

#[cfg(all(not(test), feature = "log-panic", target_arch = "aarch64"))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log!("PANIC: {}", info);
    unsafe { flush_and_reboot() };
    loop {}
}

#[cfg(all(not(test), not(feature = "log-panic")))]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

// Enable SSE2 for XMM registers (needed for EFI calling)
#[cfg(target_arch = "x86_64")]
fn enable_sse() {
    let mut cr0 = Cr0::read();
    cr0.remove(Cr0Flags::EMULATE_COPROCESSOR);
    cr0.insert(Cr0Flags::MONITOR_COPROCESSOR);
    unsafe { Cr0::write(cr0) };
    let mut cr4 = Cr4::read();
    cr4.insert(Cr4Flags::OSFXSR);
    cr4.insert(Cr4Flags::OSXMMEXCPT_ENABLE);
    unsafe { Cr4::write(cr4) };
}

const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_PCI_BLOCK_DEVICE_ID: u16 = 0x1042;

#[cfg(target_arch = "x86_64")]
fn boot_from_device(device: &mut block::VirtioBlockDevice, info: &dyn boot::Info) -> bool {
    if let Err(err) = device.init() {
        log!("Error configuring block device: {:?}", err);
        return false;
    }
    log!(
        "Virtio block device configured. Capacity: {} sectors",
        device.get_capacity()
    );

    let (start, end) = match part::find_efi_partition(device) {
        Ok(p) => p,
        Err(err) => {
            log!("Failed to find EFI partition: {:?}", err);
            return false;
        }
    };
    log!("Found EFI partition");

    let mut f = fat::Filesystem::new(device, start, end);
    if let Err(err) = f.init() {
        log!("Failed to create filesystem: {:?}", err);
        return false;
    }
    log!("Filesystem ready");

    match loader::load_default_entry(&f, info) {
        Ok(mut kernel) => {
            log!("Jumping to kernel");
            kernel.boot();
            return true;
        }
        Err(err) => log!("Error loading default entry: {:?}", err),
    }

    log!("Using EFI boot.");
    let mut file = match f.open("/EFI/BOOT/BOOTX64 EFI") {
        Ok(file) => file,
        Err(err) => {
            log!("Failed to load default EFI binary: {:?}", err);
            return false;
        }
    };
    log!("Found bootloader (BOOTX64.EFI)");

    let mut l = pe::Loader::new(&mut file);
    let load_addr = 0x20_0000;
    let (entry_addr, load_addr, size) = match l.load(load_addr) {
        Ok(load_info) => load_info,
        Err(err) => {
            log!("Error loading executable: {:?}", err);
            return false;
        }
    };

    log!("Executable loaded");
    efi::efi_exec(entry_addr, load_addr, size, info, &f, device);
    true
}

#[no_mangle]
#[cfg(all(not(feature = "coreboot"), target_arch = "x86_64"))]
pub extern "C" fn rust64_start(rdi: &pvh::StartInfo) -> ! {
    serial::PORT.borrow_mut().init();

    enable_sse();
    paging::setup();

    main(rdi)
}

#[no_mangle]
#[cfg(all(feature = "coreboot", target_arch = "x86_64"))]
pub extern "C" fn rust64_start() -> ! {
    serial::PORT.borrow_mut().init();

    enable_sse();
    paging::setup();

    let info = coreboot::StartInfo::default();

    main(&info)
}

#[cfg(target_arch = "x86_64")]
fn main(info: &dyn boot::Info) -> ! {
    log!("\nBooting with {}", info.name());

    pci::print_bus();

    pci::with_devices(
        VIRTIO_PCI_VENDOR_ID,
        VIRTIO_PCI_BLOCK_DEVICE_ID,
        |pci_device| {
            let mut pci_transport = pci::VirtioPciTransport::new(pci_device);
            let mut device = block::VirtioBlockDevice::new(&mut pci_transport);
            boot_from_device(&mut device, info)
        },
    );

    panic!("Unable to boot from any virtio-blk device")
}

#[derive(Debug)]
pub enum Error {
    BadArgs,
}

fn load_image(spec: &str) -> Result<(), Error> {
    log!("Chainloading {}", spec);

    let mut args = spec.split(';');

    let uuid = Uuid::parse_str(args.next().ok_or(Error::BadArgs)?).or(Err(Error::BadArgs))?;
    let path = args.next().ok_or(Error::BadArgs)?;

    Ok(())
}

#[no_mangle]
#[cfg(target_arch = "aarch64")]
pub unsafe extern "C" fn rust_load_image(
    raw_spec: *const c_char,
    image: *mut *mut c_void,
    size: *mut size_t,
) -> c_int {
    let spec = unsafe { CStr::from_ptr(raw_spec).to_str().unwrap() };

    match load_image(spec) {
        Ok(()) => {
            log!("Chainload succeeded");
        },
        Err(err) => {
            log!("Chainload failed: {:?}", err);
        }
    }

    -1
}
