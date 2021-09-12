
use core::mem::size_of;

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,

    /*
     * These fields are only valid for ACPI Version 2.0 and greater
     */
    length: u32,
    xsdt_address: u64,
    ext_checksum: u8,
    reserved: [u8; 3],
}

pub type Signature = [u8; 4];

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Sdt {
    signature: Signature,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

impl Sdt {
    pub fn data_address(&self) -> usize {
        self as *const _ as usize + size_of::<Self>()
    }

    pub fn data_len(&self) -> usize {
        let total_size = self.length as usize;
        let header_size = size_of::<Self>();
        if total_size >= header_size {
            total_size - header_size
        } else {
            0
        }
    }

    pub fn match_signature(&self, signature: &Signature) -> bool {
        self.signature == *signature
    }
}

pub struct Xsdt(&'static Sdt);

pub struct XsdtIter {
    sdt: &'static Sdt,
    i: usize,
}

impl Iterator for XsdtIter {
    type Item = usize;
    fn next(&mut self) -> Option<Self::Item> {
        if self.i < self.sdt.data_len() / size_of::<u64>() {
            let item = unsafe { *(self.sdt.data_address() as *const u64).add(self.i) };
            self.i += 1;
            Some(item as usize)
        } else {
            None
        }
    }
}
pub struct Rsdt(&'static Sdt);

pub struct RsdtIter {
    sdt: &'static Sdt,
    i: usize,
}

impl Iterator for RsdtIter {
    type Item = usize;
    fn next(&mut self) -> Option<Self::Item> {
        let _ = self.sdt.data_len();
        if self.i < self.sdt.data_len() / size_of::<u32>() {
            let item = unsafe { *(self.sdt.data_address() as *const u32).add(self.i) };
            self.i += 1;
            Some(item as usize)
        } else {
            None
        }
    }
}

pub fn find_from_rsdp(rsdp_addr: usize, signature: &Signature) -> Option<usize> {
    let rsdp = unsafe { &*(rsdp_addr as *const Rsdp) };
    if rsdp.revision > 0 {
        let sdt = unsafe { &*(rsdp.xsdt_address as *const Sdt) };
        let xsdt = Xsdt(sdt);
        assert!(xsdt.0.match_signature(&b"XSDT"));

        let xsdt_iter = XsdtIter { sdt: xsdt.0, i: 0 };

        for sdt_addr in xsdt_iter {
            let sdt = unsafe { &*(sdt_addr as *const Sdt) };
            if sdt.match_signature(signature) {
                return Some(sdt_addr);
            }
        }
    } else {
        let sdt = unsafe { &*(rsdp.rsdt_address as *const Sdt) };
        let rsdt = Rsdt(sdt);
        assert!(rsdt.0.match_signature(&b"RSDT"));

        let rsdt_iter = RsdtIter { sdt: rsdt.0, i: 0 };

        for sdt_addr in rsdt_iter {
            let sdt = unsafe { &*(sdt_addr as *const Sdt) };
            if sdt.match_signature(signature) {
                return Some(sdt_addr);
            }
        }
    }
    None
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Tpm2 {
    header: Sdt,
    platform_class: u16,
    reserved: [u8; 2],
    crb_control_area_address: u64,
    pub start_method: u32,
    start_method_specific: [u8; 12],
    log_area_minimum_length: u32,
    pub log_area_start_address: u64,
}