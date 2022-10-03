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

#![feature(core_intrinsics)]
#![feature(alloc_error_handler)]
#![feature(stmt_expr_attributes)]
#![feature(slice_take)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(unused_imports, dead_code))]
#![cfg_attr(not(feature = "log-serial"), allow(unused_variables, unused_imports))]

use core::panic::PanicInfo;

#[cfg(target_arch = "x86_64")]
use x86_64::instructions::hlt;

#[macro_use]
mod serial;

#[macro_use]
mod common;

mod arch;
mod boot;
#[cfg(target_arch = "x86_64")]
mod bzimage;
#[cfg(target_arch = "x86_64")]
mod coreboot;
mod delay;
mod devices;
mod efi;
mod fat;
#[cfg(target_arch = "aarch64")]
mod fdt;
#[cfg(all(test, feature = "integration_tests"))]
mod integration;
#[cfg(target_arch = "x86_64")]
mod loader;
mod mem;
mod part;
mod pe;
#[cfg(target_arch = "x86_64")]
mod pvh;

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

const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_PCI_BLOCK_DEVICE_ID: u16 = 0x1042;

fn boot_from_device(device: &mut devices::block::VirtioBlockDevice, info: &dyn boot::Info) -> bool {
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

    #[cfg(target_arch = "x86_64")]
    match loader::load_default_entry(&f, info) {
        Ok(mut kernel) => {
            log!("Jumping to kernel");
            kernel.boot();
            return true;
        }
        Err(err) => log!("Error loading default entry: {:?}", err),
    }

    log!("Using EFI boot.");
    #[cfg(target_arch = "x86_64")]
    let efi_boot_path = "/EFI/BOOT/BOOTX64.EFI";
    #[cfg(target_arch = "aarch64")]
    let efi_boot_path = "/EFI/BOOT/BOOTAA64.EFI";
    let mut file = match f.open(efi_boot_path) {
        Ok(file) => file,
        Err(err) => {
            log!("Failed to load default EFI binary: {:?}", err);
            return false;
        }
    };
    log!("Found bootloader: {}", efi_boot_path);

    let mut l = pe::Loader::new(&mut file);
    #[cfg(target_arch = "x86_64")]
    let load_addr = 0x20_0000;
    #[cfg(target_arch = "aarch64")]
    let load_addr = 0x4040_0000;
    let (entry_addr, load_addr, size) = match l.load(load_addr) {
        Ok(load_info) => load_info,
        Err(err) => {
            log!("Error loading executable: {:?}", err);
            return false;
        }
    };
    log!("entry_addr: {:#x}", entry_addr);
    log!("load_addr: {:#x}", load_addr);
    log!("size: {:#x}", size);

    log!("Executable loaded");
    efi::efi_exec(entry_addr, load_addr, size, info, &f, device);
    true
}

#[no_mangle]
#[cfg(target_arch = "x86_64")]
pub extern "C" fn rust64_start(#[cfg(not(feature = "coreboot"))] rdi: &pvh::StartInfo) -> ! {
    serial::PORT.borrow_mut().init();

    arch::x86_64::sse::enable_sse();
    arch::x86_64::paging::setup();

    #[cfg(not(feature = "coreboot"))]
    let info = *rdi;

    #[cfg(feature = "coreboot")]
    let info = coreboot::StartInfo::default();

    main(&info)
}

#[no_mangle]
#[cfg(target_arch = "aarch64")]
pub extern "C" fn rust64_start(x0: *const u8) -> ! {
    serial::PORT.borrow_mut().init();

    use crate::arch::aarch64::paging::interface::MMU;

    unsafe {
        if let Err(e) = arch::aarch64::paging::mmu().enable_mmu_and_caching() {
            panic!("MMU: {:?}", e);
        }
    }

    let info = fdt::StartInfo::new(x0);

    if let Some(region) = info.pci_cfg_region() {
        devices::pci::init(region);
    }

    main(&info)
}

fn main(
    #[cfg(target_arch = "x86_64")] info: &dyn boot::Info,
    #[cfg(target_arch = "aarch64")] info: &fdt::StartInfo,
) -> ! {
    log!("\nBooting...");

    #[cfg(target_arch = "aarch64")]
    {
        const VIRTIO_MMIO_VENDOR_ID: u32 = 0x554d4551;
        const VIRTIO_MMIO_BLOCK_DEVICE_ID: u32 = 0x2;
        devices::mmio::with_devices(
            info,
            VIRTIO_MMIO_VENDOR_ID,
            VIRTIO_MMIO_BLOCK_DEVICE_ID,
            |mmio_device| {
                let mut mmio_transport = devices::mmio::VirtioMmioTransport::new(mmio_device);
                let mut device = devices::block::VirtioBlockDevice::new(&mut mmio_transport);
                boot_from_device(&mut device, info)
            },
        );
    }

    devices::pci::print_bus();

    devices::pci::with_devices(
        VIRTIO_PCI_VENDOR_ID,
        VIRTIO_PCI_BLOCK_DEVICE_ID,
        |pci_device| {
            let mut pci_transport = devices::pci::VirtioPciTransport::new(pci_device);
            let mut device = devices::block::VirtioBlockDevice::new(&mut pci_transport);
            boot_from_device(&mut device, info)
        },
    );

    panic!("Unable to boot from any virtio-blk device")
}
