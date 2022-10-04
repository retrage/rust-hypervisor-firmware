// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

use fdt_rs::{
    base::{DevTree, DevTreeNode, DevTreeProp},
    prelude::PropReader,
};

use crate::{
    boot::{E820Entry, Info},
    mem::MemoryRegion,
};

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

    fn get_raw_prop_with<N, P>(&'_ self, node_predicate: N, prop_predicate: P) -> Option<&[u8]>
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

    fn get_memory_reg_raw_prop(&'_ self) -> Option<&[u8]> {
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

    #[allow(dead_code)]
    pub fn get_num_nodes_with<N>(&self, node_predicate: N) -> usize
    where
        N: Fn(&DevTreeNode) -> bool,
    {
        let mut num = 0;
        let mut items = self.fdt.items();
        while let Ok(Some(node)) = items.next_node() {
            if node_predicate(&node) {
                num += 1;
            }
        }
        num
    }

    pub fn get_node_with<N>(&'_ self, idx: usize, node_predicate: N) -> Option<DevTreeNode>
    where
        N: Fn(&DevTreeNode) -> bool,
    {
        let mut count = idx;
        let mut items = self.fdt.items();
        while let Ok(Some(node)) = items.next_node() {
            if node_predicate(&node) {
                if count == 0 {
                    return Some(node);
                }
                count -= 1;
            }
        }
        None
    }

    fn get_prop<'a>(node: &'a DevTreeNode, prop_name: &'a str) -> Option<DevTreeProp<'a, 'a>> {
        let mut props = node.props();
        while let Ok(Some(prop)) = props.0.next_prop() {
            if let Ok(name) = prop.name() {
                if name == prop_name {
                    return Some(prop);
                }
            }
        }
        None
    }

    fn get_u64_pair(node: &DevTreeNode, prop_name: &str) -> Option<(u64, u64)> {
        type Uint = u64;
        if let Some(prop) = Self::get_prop(node, prop_name) {
            const BUF_LEN: usize = core::mem::size_of::<Uint>();
            let raw = prop.raw();
            let mut buf = [0_u8; BUF_LEN];
            buf.clone_from_slice(&raw[0..BUF_LEN]);
            let base = Uint::from_be_bytes(buf);
            buf.clone_from_slice(&raw[BUF_LEN..(BUF_LEN + BUF_LEN)]);
            let size = Uint::from_be_bytes(buf);
            return Some((base, size));
        }
        None
    }

    pub fn pci_cfg_region(&self) -> Option<MemoryRegion> {
        let node = self.get_node_with(0, |node| {
            // TODO: Fix to check "compatible" property
            if let Ok(name) = node.name() {
                return name.starts_with("pci@");
            }
            false
        })?;
        let (base, length) = Self::get_u64_pair(&node, "reg")?;
        Some(MemoryRegion::new(base, length))
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
