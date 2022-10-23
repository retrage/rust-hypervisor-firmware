// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

use fdt::Fdt;

use crate::boot::{E820Entry, Info};

pub struct StartInfo<'a> {
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

        Self { fdt }
    }

    pub fn find_compatible_region(&self, with: &[&str]) -> Option<(*const u8, usize)> {
        let node = self.fdt.find_compatible(with)?;
        if let Some(region) = node.reg()?.next() {
            return Some((region.starting_address, region.size?));
        }
        None
    }
}

impl Info for StartInfo<'_> {
    fn name(&self) -> &str {
        "FDT"
    }

    fn rsdp_addr(&self) -> u64 {
        // TODO: Remove reference to a platform specific value.
        crate::arch::aarch64::layout::map::dram::ACPI_START as u64
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
