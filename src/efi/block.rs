// SPDX-License-Identifier: Apache-2.0
// Copyright © 2019 Intel Corporation

use core::{
    ffi::c_void,
    mem::size_of,
    ptr::{addr_of, null_mut},
};

use r_efi::{
    efi::{self, Handle, Status},
    protocols::{
        block_io::{Media, Protocol as BlockIoProtocol, PROTOCOL_GUID as BLOCKIO_PROTOCOL_GUID},
        device_path::{HardDriveMedia, Protocol as DevicePathProtocol},
    },
};

use crate::{
    block::{SectorBuf, VirtioBlockDevice},
    efi::{Protocol, ALLOCATOR, PROTOCOL_MANAGER},
    part::{get_partitions, PartitionEntry},
};

#[allow(dead_code)]
#[repr(packed)]
pub struct ControllerDevicePathProtocol {
    pub device_path: DevicePathProtocol,
    pub controller: u32,
}

pub struct BlockWrapper<'a> {
    block: &'a VirtioBlockDevice<'a>,
    pub proto: BlockIoProtocol,
}

#[repr(C)]
pub struct DevicePathWrapper {
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

    let block_size = unsafe { (*wrapper.proto.media).block_size as usize };
    let blocks = size / block_size;
    let mut region = crate::mem::MemoryRegion::new(buffer as u64, size as u64);

    for i in 0..blocks {
        use crate::block::SectorRead;
        let data = region.as_mut_slice((i * block_size) as u64, block_size as u64);
        let block = wrapper.block;
        match block.read(0 + start + i as u64, data) {
            // TODO
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

    let block_size = unsafe { (*wrapper.proto.media).block_size as usize };
    let blocks = size / block_size;
    let mut region = crate::mem::MemoryRegion::new(buffer as u64, size as u64);

    for i in 0..blocks {
        use crate::block::SectorWrite;
        let data = region.as_mut_slice((i * block_size) as u64, block_size as u64);
        let block = wrapper.block;
        match block.write(0 + start + i as u64, data) {
            // TODO
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
    pub fn new(block: &'a VirtioBlockDevice<'a>) -> BlockWrapper<'a> {
        BlockWrapper {
            block,
            proto: BlockIoProtocol {
                revision: 0x0001_0000, // EFI_BLOCK_IO_PROTOCOL_REVISION
                media: core::ptr::null(),
                reset,
                read_blocks,
                write_blocks,
                flush_blocks,
            },
        }
    }
}

impl super::Protocol for BlockWrapper<'_> {
    fn as_proto(&mut self) -> *mut c_void {
        &mut self.proto as *mut _ as *mut c_void
    }
}

impl DevicePathWrapper {
    fn new(
        partition_number: u32,
        start_lba: u64,
        last_lba: u64,
        uuid: [u8; 16],
    ) -> DevicePathWrapper {
        DevicePathWrapper {
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
        }
    }
}

impl super::Protocol for DevicePathWrapper {
    fn as_proto(&mut self) -> *mut c_void {
        &mut self.controller_path as *mut _ as *mut c_void
    }
}

fn install_block_wrapper<'a>(
    handle: Option<efi::Handle>,
    block: &'a VirtioBlockDevice<'a>,
) -> Result<efi::Handle, super::protocol::Error> {
    let (status, address) = ALLOCATOR
        .borrow_mut()
        .allocate_pool(efi::LOADER_DATA, size_of::<BlockWrapper>());
    assert!(status == Status::SUCCESS);

    unsafe {
        (address as *mut BlockWrapper).write(BlockWrapper::new(block));
    }
    let wrapper = unsafe { &mut *(address as *mut BlockWrapper) };

    let (status, address) = ALLOCATOR
        .borrow_mut()
        .allocate_pool(efi::LOADER_DATA, size_of::<Media>());
    assert!(status == Status::SUCCESS);

    let last_block = (*block).get_capacity() - 1;

    unsafe {
        (address as *mut Media).write(Media {
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
        });
    }
    wrapper.proto.media = address as *const Media;

    let handle = handle.unwrap_or(null_mut());
    let handle_ptr = addr_of!(handle) as *mut Handle;

    match PROTOCOL_MANAGER.borrow_mut().install_protocol_interface(
        handle_ptr,
        &BLOCKIO_PROTOCOL_GUID,
        efi::NATIVE_INTERFACE,
        wrapper.as_proto(),
    ) {
        Ok(_) => Ok(unsafe { handle_ptr.read() }),
        Err(e) => Err(e),
    }
}

pub fn populate_block_wrappers<'a>(
    handle: Option<efi::Handle>,
    block: &'a VirtioBlockDevice<'a>,
) -> Result<efi::Handle, super::protocol::Error> {
    let mut parts = [PartitionEntry::default(); 16];

    install_block_wrapper(handle, block)?;

    // TODO: Connect device paths to the block device
    let mut dp_handle = super::install_protocol_wrapper(
        handle,
        &r_efi::protocols::device_path::PROTOCOL_GUID,
        DevicePathWrapper::new(0, 0, block.get_capacity() - 1, [0; 16]),
    )?;

    let part_count = get_partitions(block, &mut parts).unwrap();
    for i in 0..part_count {
        let p = parts[i as usize];
        match super::install_protocol_wrapper(
            None,
            &r_efi::protocols::device_path::PROTOCOL_GUID,
            DevicePathWrapper::new(i + 1, p.first_lba, p.last_lba, p.guid),
        ) {
            Ok(h) => {
                if p.is_efi_partition() {
                    dp_handle = h;
                }
            }
            Err(e) => {
                log!("Failed to install block wrapper: {:?}", e);
                return Err(e);
            }
        }
    }
    Ok(dp_handle)
}
