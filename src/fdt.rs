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

    pub fn get_node_with<'a, N>(&'a self, idx: usize, node_predicate: N) -> Option<DevTreeNode>
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

    fn get_u32(node: &DevTreeNode, prop_name: &str) -> Option<u32> {
        if let Some(prop) = Self::get_prop(node, prop_name) {
            const BUF_LEN: usize = core::mem::size_of::<u32>();
            let raw = prop.raw();
            let mut buf = [0_u8; BUF_LEN];
            buf.clone_from_slice(&raw[0..BUF_LEN]);
            let val = u32::from_be_bytes(buf);
            return Some(val);
        }
        None
    }

    fn get_u32_pair(node: &DevTreeNode, prop_name: &str) -> Option<(u32, u32)> {
        type Uint = u32;
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

    fn get_cells(node: &DevTreeNode, prop_name: &str, cells: &mut [u32]) {
        if let Some(prop) = Self::get_prop(node, prop_name) {
            const BUF_LEN: usize = core::mem::size_of::<u32>();
            let raw = prop.raw();
            dbg!(raw.len());
            for (idx, cell) in cells.iter_mut().enumerate() {
                let mut buf = [0_u8; BUF_LEN];
                buf.clone_from_slice(&raw[(BUF_LEN * idx)..(BUF_LEN * idx + BUF_LEN)]);
                *cell = u32::from_be_bytes(buf);
            }
        }
    }

    fn parse_pcie_child_bus_addr(addr: &[u32]) {
        if addr.len() != 3 {
            return;
        }
        let hi = addr[0];
        let mid = addr[1];
        let low = addr[2];

        const RELOCATABLE: u32 = 1 << 31;
        const PREFETCHABLE: u32 = 1 << 30;
        const ALIASED: u32 = 1 << 29;

        const SPACE_CODE_MASK: u32 = 0b11 << 24;
        const BUS_MASK: u32 = 0b11111111 << 16;
        const DEV_MASK: u32 = 0b11111 << 11;
        const FUNC_MASK: u32 = 0b111 << 8;
        const REG_MASK: u32 = 0b11111111 << 0;

        if hi & RELOCATABLE != 0 {
            log!("relocatable");
        }
        if hi & PREFETCHABLE != 0 {
            log!("prefetchable");
        }
        if hi & ALIASED != 0 {
            log!("aliased");
        }

        let space_code = (hi & SPACE_CODE_MASK) >> 24;
        let bus = (hi & BUS_MASK) >> 16;
        let dev = (hi & DEV_MASK) >> 11;
        let func = (hi & FUNC_MASK) >> 8;
        let reg = (hi & REG_MASK) >> 0;

        dbg!(space_code);
        dbg!(bus);
        dbg!(dev);
        dbg!(func);
        dbg!(reg);

        let address = (mid as u64) << 32 | (low as u64);
        dbg!(address);
    }

    pub fn dump_pcie_node(&self) {
        let node = self
            .get_node_with(0, |node| {
                if let Ok(name) = node.name() {
                    return name.starts_with("pcie@");
                }
                false
            })
            .unwrap();

        let (reg_base, reg_size) = Self::get_u64_pair(&node, "reg").unwrap();
        let (bus_min, bus_max) = Self::get_u32_pair(&node, "bus-range").unwrap();
        let address_cells = Self::get_u32(&node, "#address-cells").unwrap() as usize;
        let size_cells = Self::get_u32(&node, "#size-cells").unwrap() as usize;
        dbg!(reg_base, reg_size);
        dbg!(bus_min, bus_max);
        dbg!(address_cells);
        dbg!(size_cells);

        let range_cells = address_cells + 2 + size_cells;
        let mut ranges = [0_u32; 3 * (3 + 2 + 2)];
        Self::get_cells(&node, "ranges", &mut ranges);
        for idx in (0..ranges.len()).step_by(range_cells) {
            let child_bus_addr = &ranges[idx..(idx + address_cells)];
            let parent_bus_addr = &ranges[(idx + address_cells)..(idx + address_cells + 2)];
            let length = &ranges[(idx + address_cells + 2)..(idx + address_cells + 2 + size_cells)];

            dbg!();
            Self::parse_pcie_child_bus_addr(child_bus_addr);
            let parent_bus_addr = (parent_bus_addr[0] as u64) << 32 | (parent_bus_addr[1] as u64);
            let length = (length[0] as u64) << 32 | (length[1] as u64);

            // dbg!(child_bus_addr);
            dbg!(parent_bus_addr);
            dbg!(length);
        }
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
