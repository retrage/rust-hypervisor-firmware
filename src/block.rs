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

use alloc::boxed::Box;
use core::ffi::c_void;

extern "C" {
    fn nvme_read(nsid: u32, lba: u64, buffer: *mut c_void) -> bool;
}

pub const SECTOR_SIZE: usize = 4096;

#[repr(C, align(4096))]
pub struct SectorBuffer([u8; SECTOR_SIZE]);

pub fn alloc_sector_buf() -> Box<SectorBuffer> {
    let p: Box<SectorBuffer> = unsafe { Box::new_zeroed().assume_init() };
    debug_assert_eq!(0, p.0.as_ptr().align_offset(4096));
    p
}

pub struct NvmeBlockDevice {
    nsid: u32,
    sector_size: usize,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    BlockIOError,

    BlockNotSupported,
}

pub trait SectorRead {
    /// Read a single sector from the block device. `data` must be
    /// exactly same size of a single sector.
    fn read(&self, sector: u64, data: &mut [u8]) -> Result<(), Error>;
}

pub trait SectorWrite {
    /// Write a single sector from the block device. `data` must be
    /// exactly same size of a single sector.
    fn write(&self, sector: u64, data: &mut [u8]) -> Result<(), Error>;
    fn flush(&self) -> Result<(), Error>;
}

impl NvmeBlockDevice {
    pub fn new(nsid: u32) -> NvmeBlockDevice {
        NvmeBlockDevice {
            nsid: nsid,
            sector_size: SECTOR_SIZE,
        }
    }

    pub fn get_capacity(&self) -> u64 {
        67108864 // FIXME: 256 GiB / 4096
    }
}

impl SectorRead for NvmeBlockDevice {
    fn read(&self, sector: u64, data: &mut [u8]) -> Result<(), Error> {
        if data.len() != self.sector_size {
            log!("data size other than {} is not supported", self.sector_size);
            return Err(Error::BlockNotSupported);
        }
        let lba = sector;
        let off = 0;
        // log!("lba: {:#x}, off: {:#x}", lba, off);

        let mut buf = alloc_sector_buf();
        if !unsafe { nvme_read(self.nsid, lba, buf.0.as_mut_ptr() as *mut c_void) } {
            log!("nvme_read({}, {}) failed", self.nsid, lba);
            return Err(Error::BlockIOError);
        }
        data.copy_from_slice(&buf.0);
        Ok(())
    }
}

impl SectorWrite for NvmeBlockDevice {
    fn write(&self, sector: u64, data: &mut [u8]) -> Result<(), Error> {
        Err(Error::BlockIOError)
    }

    fn flush(&self) -> Result<(), Error> {
        Err(Error::BlockIOError)
    }
}
