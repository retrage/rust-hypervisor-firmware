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

use core::ffi::c_void;

extern "C" {
    fn nvme_read(nsid: u32, lba: u64, buffer: *mut c_void) -> bool;
}

const SECTOR_SIZE: usize = 4096;

#[repr(C, align(4096))]
pub struct SectorBuffer([u8; SECTOR_SIZE]);

pub struct NvmeBlockDevice<'a> {
    nsid: u32,
    offset: u64,
    lba: Option<u64>,
    buf: &'a mut SectorBuffer,
    pos: u64,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    BlockIOError,

    BlockNotSupported,
}

pub trait SectorRead {
    /// Read a single sector (512 bytes) from the block device. `data` must be
    /// exactly 512 bytes long.
    fn read(&self, sector: u64, data: &mut [u8]) -> Result<(), Error>;
}

pub trait SectorWrite {
    /// Write a single sector (512 bytes) from the block device. `data` must be
    /// exactly 512 bytes long.
    fn write(&self, sector: u64, data: &mut [u8]) -> Result<(), Error>;
    fn flush(&self) -> Result<(), Error>;
}

impl<'a> NvmeBlockDevice<'a> {
    pub fn new(nsid: u32, offset: u64, buf: &'a mut SectorBuffer) -> NvmeBlockDevice {
        NvmeBlockDevice {
            nsid: nsid,
            offset: offset,
            lba: None,
            buf: buf,
            pos: 0,
        }
    }

    pub fn get_capacity(&self) -> u64 {
        67108864 // 256 GiB / 4096
    }
}

impl<'a> SectorRead for NvmeBlockDevice<'a> {
    fn read(&self, sector: u64, data: &mut [u8]) -> Result<(), Error> {
        /*
        let mut read = 0;
        while !buf.is_empty() {
            let lba = self.pos / SECTOR_SIZE as u64;
            let off = self.pos as usize % SECTOR_SIZE;

            if Some(lba) != self.lba {
                self.lba = Some(lba);
                let lba = lba + self.offset;
                if !unsafe { nvme_read(self.nsid, lba, self.buf.0.as_mut_ptr() as *mut c_void) } {
                    log!("nvme_read({}, {}) failed", self.nsid, lba);
                    return Err(Error::BlockIOError);
                }
            }
            let copy_len = min(SECTOR_SIZE - off, buf.len());
            buf[..copy_len].copy_from_slice(&self.buf.0[off..off + copy_len]);
            buf = &mut buf[copy_len..];
            read += copy_len;
            self.pos += copy_len as u64;
        }
        */
        Ok(())
    }
}

impl<'a> SectorWrite for NvmeBlockDevice<'a> {
    fn write(&self, sector: u64, data: &mut [u8]) -> Result<(), Error> {
        Err(Error::BlockIOError)
    }

    fn flush(&self) -> Result<(), Error> {
        Err(Error::BlockIOError)
    }
}
