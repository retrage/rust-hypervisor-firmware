// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

use fdt::{node::FdtNode, Fdt};

use crate::bootinfo::{EntryType, Info, MemoryEntry};

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

    pub fn with_nodes<F>(&self, path: &str, per_node: F)
    where
        F: Fn(&FdtNode),
    {
        for node in self.fdt.find_all_nodes(path) {
            per_node(&node);
        }
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

    fn num_entries(&self) -> usize {
        // TODO: Report the number of memory entries using LAYOUT info
        1
    }

    fn entry(&self, idx: usize) -> MemoryEntry {
        if idx == 0 {
            use crate::arch::aarch64::layout::map::dram;

            return MemoryEntry {
                addr: dram::START as u64,
                size: (dram::END - dram::START) as u64,
                entry_type: EntryType::Ram,
            };
        }
        panic!("No valid memory entry found");
    }
}
