// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

use fdt_rs::{
    base::{DevTree, DevTreeNode, DevTreeProp},
    prelude::PropReader,
};

use crate::boot::{E820Entry, Info};

#[derive(Debug)]
#[repr(C)]
pub struct StartInfo<'a> {
    fdt_addr: u64,
    fdt: DevTree<'a>,
}

impl StartInfo<'_> {
    pub fn new(fdt_addr: *const u8) -> Self {
        let fdt = match unsafe { DevTree::from_raw_pointer(fdt_addr) } {
            Ok(fdt) => fdt,
            Err(e) => panic!("Failed to create device tree object: {:?}", e),
        };

        Self {
            fdt_addr: fdt_addr as u64,
            fdt,
        }
    }

    fn get_raw_prop_with<'a, N, P>(
        &'a self,
        node_predicate: N,
        prop_predicate: P,
    ) -> Option<&'a [u8]>
    where
        N: Fn(&DevTreeNode) -> bool,
        P: Fn(&DevTreeProp) -> bool,
    {
        let mut items = self.fdt.items();
        while let Ok(Some(node)) = items.next_node() {
            if node_predicate(&node) {
                let mut props = node.props();
                while let Ok(Some(prop)) = props.0.next_prop() {
                    if prop_predicate(&prop) {
                        return Some(prop.raw());
                    }
                }
            }
        }
        None
    }

    fn get_memory_reg_raw_prop<'a>(&'a self) -> Option<&'a [u8]> {
        self.get_raw_prop_with(
            |node| match node.name() {
                Ok(name) => name.starts_with("memory@"),
                Err(_) => false,
            },
            |prop| match prop.name() {
                Ok(name) => name == "reg",
                Err(_) => false,
            },
        )
    }
}

impl Info for StartInfo<'_> {
    fn name(&self) -> &str {
        "FDT"
    }

    fn rsdp_addr(&self) -> u64 {
        // TODO: How to handle platforms without ACPI?
        self.fdt_addr
    }

    fn cmdline(&self) -> &[u8] {
        match self.get_raw_prop_with(
            |node| match node.name() {
                Ok(name) => name == "chosen",
                Err(_) => false,
            },
            |prop| match prop.name() {
                Ok(name) => name == "bootargs",
                Err(_) => false,
            },
        ) {
            Some(prop) => prop,
            None => b"",
        }
    }

    fn num_entries(&self) -> u8 {
        match self.get_memory_reg_raw_prop() {
            Some(prop) => (prop.len() / (core::mem::size_of::<u64>() * 2)) as u8,
            None => 0,
        }
    }

    fn entry(&self, idx: u8) -> E820Entry {
        assert!(idx < self.num_entries());
        match self.get_memory_reg_raw_prop() {
            Some(prop) => {
                let mut buf = [0_u8; 8];
                buf.clone_from_slice(&prop[(idx as usize * 16)..(idx as usize * 16 + 8)]);
                let addr = u64::from_be_bytes(buf);
                buf.clone_from_slice(&prop[(idx as usize * 16 + 8)..(idx as usize * 16 + 16)]);
                let size = u64::from_be_bytes(buf);
                E820Entry {
                    addr,
                    size,
                    entry_type: E820Entry::RAM_TYPE,
                }
            }
            None => panic!("No valid e820 entry found"),
        }
    }
}
