// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 Akira Moroo

//! Universal Payload

use fdt::{node::NodeProperty, Fdt};

use crate::{
    bootinfo::{EntryType, Info, MemoryEntry},
    layout::MemoryDescriptor,
};

// From Option<Fdt::NodeProperty> to EntryType
impl From<Option<NodeProperty<'_>>> for EntryType {
    fn from(property: Option<NodeProperty>) -> Self {
        if let Some(property) = property {
            let s = property
                .as_str()
                .expect("Failed to convert property to string");
            match s {
                "acpireclaim" => EntryType::AcpiReclaimable,
                "acpinvs" => EntryType::AcpiNvs,
                "bootcode" => EntryType::BootCode,
                "bootdata" => EntryType::BootData,
                "runtimecode" => EntryType::RuntimeCode,
                "runtimedata" => EntryType::RuntimeData,
                _ => panic!("Unknown memory type {:?}", s),
            }
        } else {
            EntryType::Ram
        }
    }
}

pub struct StartInfo<'a> {
    acpi_rsdp_addr: Option<u64>,
    fdt_entry: MemoryEntry,
    fdt: Fdt<'a>,
    kernel_load_addr: u64,
    memory_layout: &'static [MemoryDescriptor],
    pci_bar_memory: Option<MemoryEntry>,
}

impl StartInfo<'_> {
    pub fn new(ptr: *const u8, memory_layout: &'static [MemoryDescriptor]) -> Self {
        let fdt = unsafe {
            match Fdt::from_ptr(ptr) {
                Ok(fdt) => fdt,
                Err(e) => panic!("Failed to create device tree object: {:?}", e),
            }
        };

        let fdt_entry = MemoryEntry {
            addr: ptr as u64,
            size: fdt.total_size() as u64,
            entry_type: EntryType::Reserved,
        };

        Self {
            acpi_rsdp_addr: Self::find_acpi_rsdp_addr(&fdt),
            fdt_entry,
            fdt,
            kernel_load_addr: Self::find_fit_addr(&fdt).unwrap_or(0), // TODO: How to specify default kernel load address?s
            memory_layout,
            pci_bar_memory: None, // TODO: Find PCI BAR memory
        }
    }

    fn find_acpi_rsdp_addr(fdt: &Fdt<'_>) -> Option<u64> {
        fdt.find_node("/chosen/upl-params")
            .and_then(|node| node.property("acpi"))
            .and_then(|property| property.as_usize())
            .map(|addr| addr as u64)
    }

    fn find_fit_addr(fdt: &Fdt<'_>) -> Option<u64> {
        fdt.find_node("/chosen/upl-image")
            .and_then(|node| node.property("fit"))
            .and_then(|property| property.as_usize())
            .map(|addr| addr as u64)
    }
}

impl Info for StartInfo<'_> {
    fn name(&self) -> &str {
        "Universal Payload"
    }

    fn rsdp_addr(&self) -> Option<u64> {
        self.acpi_rsdp_addr
    }

    fn fdt_reservation(&self) -> Option<MemoryEntry> {
        Some(self.fdt_entry)
    }

    fn cmdline(&self) -> &[u8] {
        b""
    }

    fn num_entries(&self) -> usize {
        self.fdt.find_all_nodes("/memory").count()
    }

    fn entry(&self, idx: usize) -> MemoryEntry {
        for (i, memory) in self.fdt.find_all_nodes("/memory").enumerate() {
            if i == idx {
                if let Some(region) = memory.reg().unwrap().next() {
                    return MemoryEntry {
                        addr: region.starting_address as u64,
                        size: region.size.expect("memory size is required") as u64,
                        entry_type: memory.property("usage").into(),
                    };
                }
            }
        }
        panic!("No valid memory entry found");
    }

    fn kernel_load_addr(&self) -> u64 {
        self.kernel_load_addr
    }

    fn memory_layout(&self) -> &'static [MemoryDescriptor] {
        self.memory_layout
    }

    fn pci_bar_memory(&self) -> Option<MemoryEntry> {
        self.pci_bar_memory
    }
}
