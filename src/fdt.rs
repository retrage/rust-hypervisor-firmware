use fdt_rs::{base::DevTree, prelude::PropReader};

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

    fn find_prop_with<'a>(&'a self, target_node: &str, target_prop: &str) -> Option<&'a [u8]> {
        let mut items = self.fdt.items();
        while let Ok(Some(node)) = items.next_node() {
            if let Ok(node_name) = node.name() {
                if node_name == target_node {
                    let mut props = node.props();
                    while let Ok(Some(prop)) = props.0.next_prop() {
                        if let Ok(prop_name) = prop.name() {
                            if prop_name == target_prop {
                                return Some(prop.raw());
                            }
                        }
                    }
                }
            }
        }
        None
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
        match self.find_prop_with("chosen", "bootargs") {
            Some(prop) => prop,
            None => b"",
        }
    }

    fn num_entries(&self) -> u8 {
        todo!()
    }

    fn entry(&self, idx: u8) -> E820Entry {
        todo!()
    }
}
