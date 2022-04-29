// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::block::{Error as BlockError, SectorRead};

#[repr(packed)]
/// GPT header
struct Header {
    signature: u64,
    revision: u32,
    header_size: u32,
    header_crc: u32,
    reserved: u32,
    current_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: [u8; 16],
    first_part_lba: u64,
    part_count: u32,
    part_entry_size: u32,
    part_crc: u32,
}

fn dump_header(header: &Header) {
    let signature = header.signature;
    let revision = header.revision;
    let header_size = header.header_size;
    let header_crc = header.header_crc;
    let reserved = header.reserved;
    let current_lba = header.current_lba;
    let backup_lba = header.backup_lba;
    let first_usable_lba = header.first_usable_lba;
    let last_usable_lba = header.last_usable_lba;
    let disk_guid = header.disk_guid;
    let first_part_lba = header.first_part_lba;
    let part_count = header.part_count;
    let part_entry_size = header.part_entry_size;
    let part_crc = header.part_crc;
    log!("signature: {:#x}", signature);
    log!("revision: {:#x}", revision);
    log!("header_size: {:#x}", header_size);
    log!("header_crc: {:#x}", header_crc);
    log!("reserved: {:#x}", reserved);
    log!("current_lba: {:#x}", current_lba);
    log!("backup_lba: {:#x}", backup_lba);
    log!("first_usable_lba: {:#x}", first_usable_lba);
    log!("last_usable_lba: {:#x}", last_usable_lba);
    log!("disk_guid: {:?}", &disk_guid);
    log!("first_part_lba: {:#x}", first_part_lba);
    log!("part_count: {:#x}", part_count);
    log!("part_entry_size: {:#x}", part_entry_size);
    log!("part_crc: {:#x}", part_crc);
}

#[repr(packed)]
#[derive(Clone, Copy)]
pub struct PartitionEntry {
    pub type_guid: [u8; 16],
    pub guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    _flags: u64,
    _partition_name: [u32; 18],
}

impl PartitionEntry {
    pub fn is_efi_partition(&self) -> bool {
        // GUID is C12A7328-F81F-11D2-BA4B-00A0C93EC93B in mixed-endian
        // 0-3, 4-5, 6-7 are LE, 8-19, and 10-15 are BE
        self.type_guid
            == [
                0x28, 0x73, 0x2a, 0xc1, // LE C12A7328
                0x1f, 0xf8, // LE F81F
                0xd2, 0x11, // LE 11D2
                0xba, 0x4b, // BE BA4B
                0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b, // BE 00A0C93EC93B
            ]
    }
    pub fn has_same_guid(&self, guid: &[u8; 16]) -> bool {
        //log!("self.guid: {:?}, guid: {:?}", &self.guid, guid);
        self.guid == *guid
    }
}

#[derive(Debug)]
pub enum Error {
    Block(BlockError),
    HeaderNotFound,
    ViolatesSpecification,
    ExceededPartitionCount,
    NoEFIPartition,
}

pub fn get_partitions(r: &dyn SectorRead, parts_out: &mut [PartitionEntry]) -> Result<u32, Error> {
    const SECTOR_SIZE: usize = 4096;
    let mut data = [0_u8; 512];
    match r.read(SECTOR_SIZE as u64 / 512, &mut data) {
        Ok(_) => {}
        Err(e) => return Err(Error::Block(e)),
    };

    // Safe as sizeof header is less than 512 bytes (size of data)
    let h = unsafe { &*(data.as_ptr() as *const Header) };

    log!("Partition Header signature: {:?}", &data[..8]);

    // GPT magic constant
    if h.signature != 0x5452_4150_2049_4645u64 {
        return Err(Error::HeaderNotFound);
    }

    if h.first_usable_lba < 6 {
        log!("[!] h.first_usable_lba < 6");
        //return Err(Error::ViolatesSpecification);
    }

    //dump_header(h);

    let part_count = h.part_count;
    let mut checked_part_count = 0;

    let first_usable_lba = h.first_usable_lba;
    let first_part_lba = h.first_part_lba;
    log!("first_usable_lba: {}", first_usable_lba);
    log!("first_part_lba: {}", first_part_lba);

    let mut current_part = 0u32;

    for lba in first_part_lba..first_usable_lba {
        let lba = (SECTOR_SIZE as u64 * lba) / 512;
        log!("modified lba: {}", lba);
        match r.read(lba, &mut data) {
            Ok(_) => {}
            Err(e) => return Err(Error::Block(e)),
        }

        // Safe as size of partition struct * 4 is 512 bytes (size of data)
        let parts =
            unsafe { core::slice::from_raw_parts(data.as_ptr() as *const PartitionEntry, 4) };

        for p in parts {
            if p.guid == [0; 16] {
                continue;
            }
            let p_guid = p.guid;
            log!("part entry guid: {:?}", p_guid);
            parts_out[current_part as usize] = *p;
            current_part += 1;
        }

        checked_part_count += 4;
        if checked_part_count >= part_count {
            break;
        }
    }

    Ok(current_part)
}

/// Find EFI partition
pub fn find_efi_partition(r: &dyn SectorRead) -> Result<(u64, u64), Error> {
    // Assume no more than 16 partitions on the disk
    let mut parts: [PartitionEntry; 16] = unsafe { core::mem::zeroed() };

    let part_count = get_partitions(r, &mut parts)? as usize;

    for (checked_part_count, p) in (parts[0..part_count]).iter().enumerate() {
        if p.is_efi_partition() {
            return Ok((p.first_lba, p.last_lba));
        }
        if checked_part_count == part_count {
            return Err(Error::ExceededPartitionCount);
        }
    }

    Err(Error::NoEFIPartition)
}

/// Find partition with specified GUID
pub fn find_partition_with(r: &dyn SectorRead, guid: &[u8; 16]) -> Result<(u64, u64), Error> {
    // Assume no more than 16 partitions on the disk
    let mut parts: [PartitionEntry; 16] = unsafe { core::mem::zeroed() };

    let part_count = get_partitions(r, &mut parts)? as usize;
    log!("part_count: {}", part_count);

    for (checked_part_count, p) in (parts[0..part_count]).iter().enumerate() {
        if p.has_same_guid(guid) {
            return Ok((p.first_lba, p.last_lba));
        }
        if checked_part_count == part_count {
            return Err(Error::ExceededPartitionCount);
        }
    }

    Err(Error::NoEFIPartition)
}

#[cfg(test)]
pub mod tests {
    use std::cell::RefCell;
    use std::env;
    use std::fs;
    use std::fs::File;
    use std::fs::Metadata;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::path::{Path, PathBuf};

    use crate::block;
    use crate::block::SectorRead;

    pub struct FakeDisk {
        file: RefCell<File>,
        metadata: Metadata,
    }

    impl FakeDisk {
        pub fn new<P: AsRef<Path>>(path: &P) -> FakeDisk {
            let file = File::open(path).expect("missing disk image");
            let metadata = fs::metadata(path).expect("error getting file metadata");
            FakeDisk {
                file: RefCell::new(file),
                metadata,
            }
        }

        pub fn len(&self) -> u64 {
            self.metadata.len()
        }
    }

    impl SectorRead for FakeDisk {
        fn read(&self, sector: u64, data: &mut [u8]) -> Result<(), block::Error> {
            let mut file = self.file.borrow_mut();
            match file.seek(SeekFrom::Start(sector * 512)) {
                Ok(_) => {}
                Err(_) => return Err(block::Error::BlockIOError),
            }
            match file.read(data) {
                Ok(_) => {}
                Err(_) => return Err(block::Error::BlockIOError),
            }
            Ok(())
        }
    }

    pub fn clear_disk_path() -> PathBuf {
        let mut disk_path = dirs::home_dir().unwrap();
        disk_path.push("workloads");
        disk_path.push("clear-28660-kvm.img");

        disk_path
    }

    #[test]
    fn test_find_efi_partition() {
        let d = FakeDisk::new(&clear_disk_path());

        match super::find_efi_partition(&d) {
            Ok((start, end)) => {
                assert_eq!(start, 2048);
                assert_eq!(end, 1_048_575);
            }
            Err(e) => panic!("{:?}", e),
        }
    }
}
