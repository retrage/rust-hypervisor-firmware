// SPDX-License-Identifier: Apache-2.0
// Copyright © 2019 Intel Corporation

use core::ffi::c_void;

use r_efi::{
    efi::{self, Status},
    protocols::{
        block_io::{Media, Protocol as BlockIoProtocol, PROTOCOL_GUID as BLOCKIO_PROTOCOL_GUID},
        device_path::{HardDriveMedia, Protocol as DevicePathProtocol},
    },
};

use crate::{
    block::{SectorBuf, VirtioBlockDevice},
    part::{get_partitions, PartitionEntry},
};

#[allow(dead_code)]
#[repr(packed)]
pub struct ControllerDevicePathProtocol {
    pub device_path: DevicePathProtocol,
    pub controller: u32,
}

#[repr(C)]
pub struct BlockWrapper<'a> {
    block: &'a VirtioBlockDevice<'a>,
    media: Media,
    pub proto: BlockIoProtocol,
    // The ordering of these paths are very important, along with the C
    // representation as the device path "flows" from the first.
    pub controller_path: ControllerDevicePathProtocol,
    pub disk_paths: [HardDriveMedia; 2],
    start_lba: u64,
}

pub extern "efiapi" fn reset(_: *mut BlockIoProtocol, _: efi::Boolean) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn read_blocks(
    proto: *mut BlockIoProtocol,
    _: u32,
    start: u64,
    size: usize,
    buffer: *mut c_void,
) -> Status {
    let wrapper = container_of!(proto, BlockWrapper, proto);
    let wrapper = unsafe { &*wrapper };

    let block_size = wrapper.media.block_size as usize;
    let blocks = size / block_size;
    let mut region = crate::mem::MemoryRegion::new(buffer as u64, size as u64);

    for i in 0..blocks {
        use crate::block::SectorRead;
        let data = region.as_mut_slice((i * block_size) as u64, block_size as u64);
        let block = wrapper.block;
        match block.read(wrapper.start_lba + start + i as u64, data) {
            Ok(()) => continue,
            Err(_) => {
                return Status::DEVICE_ERROR;
            }
        };
    }

    Status::SUCCESS
}

pub extern "efiapi" fn write_blocks(
    proto: *mut BlockIoProtocol,
    _: u32,
    start: u64,
    size: usize,
    buffer: *mut c_void,
) -> Status {
    let wrapper = container_of!(proto, BlockWrapper, proto);
    let wrapper = unsafe { &*wrapper };

    let block_size = wrapper.media.block_size as usize;
    let blocks = size / block_size;
    let mut region = crate::mem::MemoryRegion::new(buffer as u64, size as u64);

    for i in 0..blocks {
        use crate::block::SectorWrite;
        let data = region.as_mut_slice((i * block_size) as u64, block_size as u64);
        let block = wrapper.block;
        match block.write(wrapper.start_lba + start + i as u64, data) {
            Ok(()) => continue,
            Err(_) => {
                return Status::DEVICE_ERROR;
            }
        };
    }

    Status::SUCCESS
}

pub extern "efiapi" fn flush_blocks(proto: *mut BlockIoProtocol) -> Status {
    let wrapper = container_of!(proto, BlockWrapper, proto);
    let wrapper = unsafe { &*wrapper };
    use crate::block::SectorWrite;
    let block = wrapper.block;
    match block.flush() {
        Ok(()) => Status::SUCCESS,
        Err(_) => Status::DEVICE_ERROR,
    }
}

impl<'a> BlockWrapper<'a> {
    pub fn new(
        block: &'a VirtioBlockDevice<'a>,
        partition_number: u32,
        start_lba: u64,
        last_lba: u64,
        uuid: [u8; 16],
    ) -> BlockWrapper<'a> {
        let last_block = (*block).get_capacity() - 1;

        let mut bw = BlockWrapper {
            block,
            media: Media {
                media_id: 0,
                removable_media: false,
                media_present: true,
                logical_partition: false,
                read_only: true,
                write_caching: false,
                block_size: SectorBuf::len() as u32,
                io_align: 0,
                last_block,
                lowest_aligned_lba: 0,
                logical_blocks_per_physical_block: 1,
                optimal_transfer_length_granularity: 1,
            },
            proto: BlockIoProtocol {
                revision: 0x0001_0000, // EFI_BLOCK_IO_PROTOCOL_REVISION
                media: core::ptr::null(),
                reset,
                read_blocks,
                write_blocks,
                flush_blocks,
            },
            start_lba,
            controller_path: ControllerDevicePathProtocol {
                device_path: DevicePathProtocol {
                    r#type: 1,
                    sub_type: 5,
                    length: [8, 0],
                },
                controller: 0,
            },
            // full disk vs partition
            disk_paths: if partition_number == 0 {
                [
                    HardDriveMedia {
                        header: DevicePathProtocol {
                            r#type: r_efi::protocols::device_path::TYPE_END,
                            sub_type: 0xff, // End of full path
                            length: [4, 0],
                        },
                        partition_number: 0,
                        partition_format: 0x0,
                        partition_start: 0,
                        partition_size: 0,
                        partition_signature: [0; 16],
                        signature_type: 0,
                    },
                    HardDriveMedia {
                        header: DevicePathProtocol {
                            r#type: r_efi::protocols::device_path::TYPE_END,
                            sub_type: 0xff, // End of full path
                            length: [4, 0],
                        },
                        partition_number: 0,
                        partition_format: 0x0,
                        partition_start: 0,
                        partition_size: 0,
                        partition_signature: [0; 16],
                        signature_type: 0,
                    },
                ]
            } else {
                [
                    HardDriveMedia {
                        header: DevicePathProtocol {
                            r#type: r_efi::protocols::device_path::TYPE_MEDIA,
                            sub_type: 1,
                            length: [42, 0],
                        },
                        partition_number,
                        partition_format: 0x02, // GPT
                        partition_start: start_lba,
                        partition_size: last_lba - start_lba + 1,
                        partition_signature: uuid,
                        signature_type: 0x02,
                    },
                    HardDriveMedia {
                        header: DevicePathProtocol {
                            r#type: r_efi::protocols::device_path::TYPE_END,
                            sub_type: 0xff, // End of full path
                            length: [4, 0],
                        },
                        partition_number: 0,
                        partition_format: 0x0,
                        partition_start: 0,
                        partition_size: 0,
                        partition_signature: [0; 16],
                        signature_type: 0,
                    },
                ]
            },
        };
        bw.proto.media = &bw.media;
        bw
    }
}

pub fn populate_block_wrappers<'a>(
    block: &'a VirtioBlockDevice<'a>,
) -> Result<Option<u32>, super::protocol::Error> {
    let mut parts = [PartitionEntry::default(); 16];

    super::install_protocol_wrapper(
        &BLOCKIO_PROTOCOL_GUID,
        BlockWrapper::new(block, 0, 0, 0, [0; 16]),
    )?;

    let mut efi_part_id = None;
    let part_count = get_partitions(block, &mut parts).unwrap();
    for i in 0..part_count {
        let p = parts[i as usize];
        match super::install_protocol_wrapper(
            &BLOCKIO_PROTOCOL_GUID,
            BlockWrapper::new(block, i + 1, p.first_lba, p.last_lba, p.guid),
        ) {
            Ok(_) => {
                log!("Installed block wrapper for partition {}", i + 1);
                if p.is_efi_partition() {
                    efi_part_id = Some(i + 1);
                }
            }
            Err(e) => {
                log!("Failed to install block wrapper: {:?}", e);
                return Err(e);
            }
        }
    }
    Ok(efi_part_id)
}
