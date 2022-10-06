// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

use fdt::Fdt;

use crate::{
    boot::{E820Entry, Info},
    mem::MemoryRegion,
};

#[cfg(target_arch = "aarch64")]
use crate::mmio::MmioDevice;

pub struct StartInfo<'a> {
    fdt_addr: u64,
    fdt: Fdt<'a>,
}

impl StartInfo<'_> {
    pub fn new(ptr: *const u8) -> Self {
        let fdt = unsafe {
            match Fdt::from_ptr(ptr) {
                Ok(fdt) => fdt,
                Err(e) => panic!("Failed to create device tree object: {:?}", e),
            }
        };

        Self {
            fdt_addr: ptr as u64,
            fdt,
        }
    }

    pub fn pci_cfg_region(&self) -> Option<MemoryRegion> {
        let node = self.fdt.find_compatible(&["pci-host-ecam-generic"])?;
        let reg = node.property("reg")?;
        let (base, length) = Self::as_u64_pair(reg.value)?;
        Some(MemoryRegion::new(base, length))
    }

    #[cfg(target_arch = "aarch64")]
    pub fn with_virtio_mmio_devices<F>(&self, vendor_id: u32, device_id: u32, per_device: F)
    where
        F: Fn(MmioDevice) -> bool,
    {
        for node in self.fdt.find_all_nodes("/virtio_mmio") {
            let reg = node.property("reg").unwrap();
            let (base, size) = Self::as_u64_pair(reg.value).unwrap();
            let mut device = MmioDevice::new(base, size);
            device.init();
            if device.vendor_id == vendor_id && device.device_id == device_id && per_device(device)
            {
                break;
            }
        }
    }

    fn as_u64_pair(value: &[u8]) -> Option<(u64, u64)> {
        assert!(value.len() == 16);
        let lhs = u64::from_be_bytes(value.get(..8)?.try_into().unwrap());
        let rhs = u64::from_be_bytes(value.get(8..16)?.try_into().unwrap());
        Some((lhs, rhs))
    }
}

impl Info for StartInfo<'_> {
    fn name(&self) -> &str {
        "FDT"
    }

    fn rsdp_addr(&self) -> u64 {
        self.fdt_addr
    }

    fn cmdline(&self) -> &[u8] {
        match self.fdt.chosen().bootargs() {
            Some(s) => s.as_bytes(),
            None => b"",
        }
    }

    fn num_entries(&self) -> u8 {
        self.fdt.memory().regions().count() as u8
    }

    fn entry(&self, idx: u8) -> E820Entry {
        for (i, region) in self.fdt.memory().regions().enumerate() {
            if i == idx as usize {
                return E820Entry {
                    addr: region.starting_address as u64,
                    size: region.size.expect("memory size is required") as u64,
                    entry_type: E820Entry::RAM_TYPE,
                };
            }
        }
        panic!("No valid e820 entry found");
    }
}
