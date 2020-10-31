
use core::mem::size_of;

use crate::{
    boot::{E820Entry, Info},
};

const TAG_FORWARD: u32 = 0x11;
const TAG_MEMORY: u32 = 0x01;

#[repr(C)]
#[derive(Debug)]
struct Header {
    signature: [u8; 4],
    header_bytes: u32,
    header_checksum: u32,
    table_bytes: u32,
    table_checksum: u32,
    table_entries: u32,
}

impl Header {
    pub fn has_signature(&self) -> bool {
        self.signature == [0x4c, 0x42, 0x49, 0x4f]
    }
}

#[repr(C)]
#[derive(Debug)]
struct Record {
    tag: u32,
    size: u32,
}

#[repr(C)]
#[derive(Debug)]
struct Forward  {
    tag: u32,
    size: u32,
    forward: u64,
}

#[repr(C)]
#[derive(Debug)]
struct MemMapEntry {
    addr: CBUInt64,
    size: CBUInt64,
    entry_type: u32,
}

#[repr(C)]
#[derive(Debug)]
struct CBUInt64 {
    lo: u32,
    hi: u32,
}

impl CBUInt64 {
    pub fn to_u64(&self) -> u64 {
        ((self.hi as u64) << 32) | self.lo as u64
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct StartInfo {
    rsdp_addr: u64,
    memmap_addr: u64,
    memmap_entries: u32,
}

impl StartInfo {
    pub fn new() -> Self {
        Self {
            rsdp_addr: 0,
            memmap_addr: 0,
            memmap_entries: 0,
        }
    }
    pub fn set_rsdp(&mut self) {
        let rsdp_addr = self.find_rsdp(0xe0000, 0x20000).unwrap_or(0);
        self.rsdp_addr = rsdp_addr;
    }
    fn find_header(&self, start: u64, len: usize) -> Result<&Header, ()> {
        for addr in (start..(start + len as u64)).step_by(16) {
            let header = unsafe { &*(addr as *const Header) };
            if header.has_signature() {
                return Ok(header);
            }
        }
        Err(())
    }
    fn parse_memmap(&mut self, record: &Record) {
        if record.tag != TAG_MEMORY {
            return;
        }
        let n_entries = record.size as usize / size_of::<MemMapEntry>();
        let rec_size = size_of::<Record>() as isize;
        let rec_ptr = (record as *const Record) as *const u8;
        let mem_ptr = unsafe { rec_ptr.offset(rec_size) as *const MemMapEntry };
        self.memmap_entries = n_entries as u32;
        self.memmap_addr = mem_ptr as u64;
    }
    fn find_rsdp(&self, start: u64, len: usize) -> Option<u64> {
        const RSDP_SIGNATURE: u64 = 0x2052_5450_2044_5352;
        for addr in (start..(start + len as u64)).step_by(16) {
            let val = unsafe { *(addr as *const u64) };
            if val == RSDP_SIGNATURE {
                return Some(addr);
            }
        }
        None
    }
}

impl Info for StartInfo {
    fn name(&self) -> &str {
        "coreboot"
    }
    fn rsdp_addr(&self) -> u64 {
        log!("rsdp_addr");
        self.rsdp_addr
    }
    fn cmdline(&self) -> &[u8] {
        log!("cmdline");
        b""
    }
    fn num_entries(&self) -> u8 {
        log!("num_entries: {}", self.memmap_entries);
        if self.memmap_addr == 0 {
            return 0;
        }
        self.memmap_entries as u8
    }
    fn entry(&self, idx: u8) -> E820Entry {
        log!("entry: {}", idx);
        assert!(idx < self.num_entries());
        let ptr = self.memmap_addr as *const MemMapEntry;
        let entry = unsafe { &*ptr.offset(idx as isize) };
        E820Entry {
            addr: entry.addr.to_u64(),
            size: entry.size.to_u64(),
            entry_type: entry.entry_type,
        }
    }
    fn parse(&mut self, start: u64, len: usize) -> Result<(), ()> {
        let header = self.find_header(start, len)?;
        let ptr = unsafe { (header as *const Header).offset(1) };
        let mut offset = 0;
        for _ in 0..header.table_entries {
            let rec_ptr = unsafe { (ptr as *const u8).offset(offset as isize) };
            let record = unsafe { &(*(rec_ptr as *const Record)) };
            match record.tag {
                TAG_FORWARD => {
                    let forward = unsafe { &*(rec_ptr as *const Forward) };
                    return self.parse(forward.forward, len);
                },
                TAG_MEMORY => {
                    self.parse_memmap(record);
                },
                _ => {},
            }
            offset += record.size;
        }
        Ok(())
    }
}
