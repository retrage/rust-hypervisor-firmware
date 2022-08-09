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
#![feature(slice_take)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(unused_imports, dead_code))]
#![cfg_attr(not(feature = "log-serial"), allow(unused_variables, unused_imports))]

use core::{panic::PanicInfo, ptr};

#[cfg(target_arch = "x86_64")]
use x86_64::{
    instructions::hlt,
    registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
};

#[macro_use]
mod serial;

#[macro_use]
mod common;

#[cfg(not(test))]
mod asm;
#[cfg(target_arch = "x86_64")]
mod block;
#[cfg(target_arch = "x86_64")]
mod boot;
#[cfg(target_arch = "x86_64")]
mod bzimage;
#[cfg(target_arch = "x86_64")]
mod coreboot;
#[cfg(target_arch = "x86_64")]
mod delay;
#[cfg(target_arch = "x86_64")]
mod efi;
#[cfg(target_arch = "x86_64")]
mod fat;
#[cfg(target_arch = "x86_64")]
mod gdt;
#[cfg(all(test, feature = "integration_tests"))]
mod integration;
#[cfg(target_arch = "x86_64")]
mod loader;
mod mem;
#[cfg(target_arch = "x86_64")]
mod paging;
#[cfg(target_arch = "x86_64")]
mod part;
#[cfg(target_arch = "x86_64")]
mod pci;
#[cfg(target_arch = "x86_64")]
mod pe;
#[cfg(target_arch = "x86_64")]
mod pvh;
#[cfg(target_arch = "x86_64")]
mod rtc;
#[cfg(target_arch = "x86_64")]
mod virtio;

#[cfg(all(not(test), feature = "log-panic"))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log!("PANIC: {}", info);
    loop {
        #[cfg(target_arch = "x86_64")]
        hlt()
    }
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
#[cfg(not(feature = "coreboot"))]
pub extern "C" fn rust64_start() -> ! {
    // serial::PORT.borrow_mut().init();

    #[cfg(target_arch = "x86_64")]
    enable_sse();
    #[cfg(target_arch = "x86_64")]
    paging::setup();

    // #[cfg(target_arch = "x86_64")]
    main()
}

#[no_mangle]
#[cfg(feature = "coreboot")]
pub extern "C" fn rust64_start() -> ! {
    // serial::PORT.borrow_mut().init();

    #[cfg(target_arch = "x86_64")]
    enable_sse();
    #[cfg(target_arch = "x86_64")]
    paging::setup();

    #[cfg(target_arch = "x86_64")]
    let info = coreboot::StartInfo::default();

    // #[cfg(target_arch = "x86_64")]
    main()
}

fn main() -> ! {
    log!("\nBooting...");

    /*
    #[cfg(target_arch = "x86_64")]
    pci::print_bus();

    #[cfg(target_arch = "x86_64")]
    pci::with_devices(
        VIRTIO_PCI_VENDOR_ID,
        VIRTIO_PCI_BLOCK_DEVICE_ID,
        |pci_device| {
            let mut pci_transport = pci::VirtioPciTransport::new(pci_device);
            let mut device = block::VirtioBlockDevice::new(&mut pci_transport);
            boot_from_device(&mut device, info)
        },
    );
    */

    panic!("Unable to boot from any virtio-blk device")
}
