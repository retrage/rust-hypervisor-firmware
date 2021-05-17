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

use core::{
    alloc as heap_alloc,
    ffi::c_void,
    mem::{size_of, transmute},
    ptr::null_mut,
};

use atomic_refcell::AtomicRefCell;
use linked_list_allocator::LockedHeap;
use r_efi::{
    efi::{
        self, AllocateType, Boolean, CapsuleHeader, Char16, Event, EventNotify, Guid, Handle,
        InterfaceType, LocateSearchType, MemoryDescriptor, MemoryType,
        OpenProtocolInformationEntry, PhysicalAddress, ResetType, Status, Time, TimeCapabilities,
        TimerDelay, Tpl,
    },
    protocols::{
        device_path::Protocol as DevicePathProtocol, loaded_image::Protocol as LoadedImageProtocol,
    },
};

use crate::boot;
use crate::elf;
use crate::rtc;

mod alloc;
mod block;
mod console;
mod file;
mod var;

use alloc::Allocator;
use var::VariableAllocator;

#[derive(Copy, Clone, PartialEq)]
enum HandleType {
    None,
    Block,
    FileSystem,
    LoadedImage,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct HandleWrapper {
    handle_type: HandleType,
}

pub static ALLOCATOR: AtomicRefCell<Allocator> = AtomicRefCell::new(Allocator::new());

#[cfg(not(test))]
#[global_allocator]
pub static HEAP_ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(not(test))]
#[alloc_error_handler]
fn heap_alloc_error_handler(layout: heap_alloc::Layout) -> ! {
    panic!("heap allocation error: {:?}", layout);
}

pub static VARIABLES: AtomicRefCell<VariableAllocator> =
    AtomicRefCell::new(VariableAllocator::new());

static mut ST: *mut efi::SystemTable = null_mut();

static mut BS: efi::BootServices = efi::BootServices {
    hdr: efi::TableHeader {
        signature: efi::BOOT_SERVICES_SIGNATURE,
        revision: efi::BOOT_SERVICES_REVISION,
        header_size: size_of::<efi::BootServices>() as u32,
        crc32: 0, // TODO
        reserved: 0,
    },
    raise_tpl,
    restore_tpl,
    allocate_pages,
    free_pages,
    get_memory_map,
    allocate_pool,
    free_pool,
    create_event,
    set_timer,
    wait_for_event,
    signal_event,
    close_event,
    check_event,
    install_protocol_interface,
    reinstall_protocol_interface,
    uninstall_protocol_interface,
    handle_protocol,
    register_protocol_notify,
    locate_handle,
    locate_device_path,
    install_configuration_table,
    load_image,
    start_image,
    exit,
    unload_image,
    exit_boot_services,
    get_next_monotonic_count,
    stall,
    set_watchdog_timer,
    connect_controller,
    disconnect_controller,
    open_protocol,
    close_protocol,
    open_protocol_information,
    protocols_per_handle,
    locate_handle_buffer,
    locate_protocol,
    install_multiple_protocol_interfaces,
    uninstall_multiple_protocol_interfaces,
    calculate_crc32,
    copy_mem,
    set_mem,
    create_event_ex,
    reserved: null_mut(),
};

static mut BLOCK_WRAPPERS: block::BlockWrappers = block::BlockWrappers {
    wrappers: [null_mut(); 16],
    count: 0,
};

pub extern "win64" fn raise_tpl(_: Tpl) -> Tpl {
    0
}

pub extern "win64" fn restore_tpl(_: Tpl) {}

pub extern "win64" fn allocate_pages(
    allocate_type: AllocateType,
    memory_type: MemoryType,
    pages: usize,
    address: *mut PhysicalAddress,
) -> Status {
    let (status, new_address) =
        ALLOCATOR
            .borrow_mut()
            .allocate_pages(
                allocate_type,
                memory_type,
                pages as u64,
                unsafe { *address } as u64,
            );
    if status == Status::SUCCESS {
        unsafe {
            *address = new_address;
        }
    }
    status
}

pub extern "win64" fn free_pages(address: PhysicalAddress, _: usize) -> Status {
    ALLOCATOR.borrow_mut().free_pages(address)
}

pub extern "win64" fn get_memory_map(
    memory_map_size: *mut usize,
    out: *mut MemoryDescriptor,
    key: *mut usize,
    descriptor_size: *mut usize,
    descriptor_version: *mut u32,
) -> Status {
    if memory_map_size.is_null() {
        return Status::INVALID_PARAMETER;
    }

    if !descriptor_size.is_null() {
        unsafe {
            *descriptor_size = size_of::<MemoryDescriptor>();
        }
    }

    if !descriptor_version.is_null() {
        unsafe {
            *descriptor_version = efi::MEMORY_DESCRIPTOR_VERSION;
        }
    }

    let count = ALLOCATOR.borrow().get_descriptor_count();
    let map_size = size_of::<MemoryDescriptor>() * count;
    if unsafe { *memory_map_size } < map_size {
        unsafe {
            *memory_map_size = map_size;
        }
        return Status::BUFFER_TOO_SMALL;
    }

    if key.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let out =
        unsafe { core::slice::from_raw_parts_mut(out as *mut alloc::MemoryDescriptor, count) };
    let count = ALLOCATOR.borrow().get_descriptors(out);
    let map_size = size_of::<MemoryDescriptor>() * count;
    unsafe {
        *memory_map_size = map_size;
        *key = ALLOCATOR.borrow().get_map_key();
    }

    Status::SUCCESS
}

pub extern "win64" fn allocate_pool(
    memory_type: MemoryType,
    size: usize,
    address: *mut *mut c_void,
) -> Status {
    let (status, new_address) = ALLOCATOR.borrow_mut().allocate_pages(
        AllocateType::AllocateAnyPages,
        memory_type,
        ((size + PAGE_SIZE as usize - 1) / PAGE_SIZE as usize) as u64,
        address as u64,
    );

    if status == Status::SUCCESS {
        unsafe {
            *address = new_address as *mut c_void;
        }
    }

    status
}

pub extern "win64" fn free_pool(ptr: *mut c_void) -> Status {
    ALLOCATOR.borrow_mut().free_pages(ptr as u64)
}

pub extern "win64" fn create_event(
    _: u32,
    _: Tpl,
    _: EventNotify,
    _: *mut c_void,
    _: *mut Event,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn set_timer(_: Event, _: TimerDelay, _: u64) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn wait_for_event(_: usize, _: *mut Event, _: *mut usize) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn signal_event(_: Event) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn close_event(_: Event) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn check_event(_: Event) -> Status {
    Status::UNSUPPORTED
}

const SHIM_LOCK_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x605d_ab50,
    0xe046,
    0x4300,
    0xab,
    0xb6,
    &[0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23],
);

pub extern "win64" fn install_protocol_interface(
    _: *mut Handle,
    guid: *mut Guid,
    _: InterfaceType,
    _: *mut c_void,
) -> Status {
    if unsafe { *guid } == SHIM_LOCK_PROTOCOL_GUID {
        Status::SUCCESS
    } else {
        Status::UNSUPPORTED
    }
}

pub extern "win64" fn reinstall_protocol_interface(
    _: Handle,
    _: *mut Guid,
    _: *mut c_void,
    _: *mut c_void,
) -> Status {
    Status::NOT_FOUND
}

pub extern "win64" fn uninstall_protocol_interface(
    _: Handle,
    _: *mut Guid,
    _: *mut c_void,
) -> Status {
    Status::NOT_FOUND
}

pub extern "win64" fn handle_protocol(
    handle: Handle,
    guid: *mut Guid,
    out: *mut *mut c_void,
) -> Status {
    open_protocol(handle, guid, out, null_mut(), null_mut(), 0)
}

pub extern "win64" fn register_protocol_notify(
    _: *mut Guid,
    _: Event,
    _: *mut *mut c_void,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn locate_handle(
    _: LocateSearchType,
    guid: *mut Guid,
    _: *mut c_void,
    size: *mut usize,
    handles: *mut Handle,
) -> Status {
    if unsafe { *guid } == block::PROTOCOL_GUID {
        let count = unsafe { BLOCK_WRAPPERS.count };
        if unsafe { *size } < size_of::<Handle>() * count {
            unsafe { *size = size_of::<Handle>() * count };
            return Status::BUFFER_TOO_SMALL;
        }

        let handles =
            unsafe { core::slice::from_raw_parts_mut(handles, *size / size_of::<Handle>()) };

        let wrappers_as_handles: &[Handle] = unsafe {
            core::slice::from_raw_parts_mut(
                BLOCK_WRAPPERS.wrappers.as_mut_ptr() as *mut *mut block::BlockWrapper
                    as *mut Handle,
                count,
            )
        };

        handles[0..count].copy_from_slice(wrappers_as_handles);

        unsafe { *size = size_of::<Handle>() * count };

        return Status::SUCCESS;
    }

    Status::UNSUPPORTED
}

pub extern "win64" fn locate_device_path(
    _: *mut Guid,
    _: *mut *mut DevicePathProtocol,
    _: *mut *mut c_void,
) -> Status {
    Status::NOT_FOUND
}

pub extern "win64" fn install_configuration_table(_: *mut Guid, _: *mut c_void) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn load_image(
    _boot_policy: Boolean,
    parent_image_handle: Handle,
    device_path: *mut DevicePathProtocol,
    _source_buffer: *mut c_void,
    _source_size: usize,
    image_handle: *mut Handle,
) -> Status {
    use crate::fat::Read;

    let mut path = [0_u8; 256];
    let device_path = unsafe { &*device_path };
    extract_path(device_path, &mut path);
    let path = crate::common::ascii_strip(&path);

    let li = parent_image_handle as *const LoadedImageWrapper;
    let dh = unsafe { (*li).proto.device_handle };
    let wrapped_fs_ref = unsafe { &*(dh as *const file::FileSystemWrapper) };
    let mut file = match wrapped_fs_ref.fs.open(path) {
        Ok(file) => file,
        Err(_) => return Status::DEVICE_ERROR,
    };

    let file_size = (file.get_size() as u64 + PAGE_SIZE - 1) / PAGE_SIZE;
    // Get free pages address
    let load_addr =
        match ALLOCATOR
            .borrow_mut()
            .find_free_pages(AllocateType::AllocateAnyPages, file_size, 0)
        {
            Some(a) => a,
            None => return Status::OUT_OF_RESOURCES,
        };

    let mut l = crate::pe::Loader::new(&mut file);
    let (entry_addr, load_addr, load_size) = match l.load(load_addr) {
        Ok(load_info) => load_info,
        Err(_) => return Status::DEVICE_ERROR,
    };
    ALLOCATOR.borrow_mut().allocate_pages(
        AllocateType::AllocateAddress,
        MemoryType::LoaderCode,
        file_size,
        load_addr,
    );

    let image = new_image_handle(
        path,
        parent_image_handle,
        wrapped_fs_ref as *const _ as Handle,
        load_addr,
        load_size,
        entry_addr,
    );

    unsafe { *image_handle = image as *mut _ as *mut c_void };

    Status::SUCCESS
}

pub extern "win64" fn start_image(
    image_handle: Handle,
    _: *mut usize,
    _: *mut *mut Char16,
) -> Status {
    let wrapped_handle = image_handle as *const LoadedImageWrapper;
    let address = unsafe { (*wrapped_handle).entry_point };
    let ptr = address as *const ();
    let code: extern "win64" fn(Handle, *mut efi::SystemTable) -> Status =
        unsafe { core::mem::transmute(ptr) };
    (code)(image_handle, unsafe { ST })
}

pub extern "win64" fn exit(_: Handle, _: Status, _: usize, _: *mut Char16) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn unload_image(_: Handle) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn exit_boot_services(_: Handle, _: usize) -> Status {
    Status::SUCCESS
}

pub extern "win64" fn get_next_monotonic_count(_: *mut u64) -> Status {
    Status::DEVICE_ERROR
}

pub extern "win64" fn stall(microseconds: usize) -> Status {
    crate::delay::udelay(microseconds as u64);
    Status::SUCCESS
}

pub extern "win64" fn set_watchdog_timer(_: usize, _: u64, _: usize, _: *mut Char16) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn connect_controller(
    _: Handle,
    _: *mut Handle,
    _: *mut DevicePathProtocol,
    _: Boolean,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn disconnect_controller(_: Handle, _: Handle, _: Handle) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn open_protocol(
    handle: Handle,
    guid: *mut Guid,
    out: *mut *mut c_void,
    _: Handle,
    _: Handle,
    _: u32,
) -> Status {
    let hw = handle as *const HandleWrapper;
    let handle_type = unsafe { (*hw).handle_type };
    if unsafe { *guid } == r_efi::protocols::loaded_image::PROTOCOL_GUID
        && handle_type == HandleType::LoadedImage
    {
        unsafe {
            *out = &mut (*(handle as *mut LoadedImageWrapper)).proto as *mut _ as *mut c_void;
        }
        return Status::SUCCESS;
    }

    if unsafe { *guid } == r_efi::protocols::simple_file_system::PROTOCOL_GUID
        && handle_type == HandleType::FileSystem
    {
        unsafe {
            *out = &mut (*(handle as *mut file::FileSystemWrapper)).proto as *mut _ as *mut c_void;
        }
        return Status::SUCCESS;
    }

    if unsafe { *guid } == r_efi::protocols::device_path::PROTOCOL_GUID
        && handle_type == HandleType::Block
    {
        unsafe {
            *out = &mut (*(handle as *mut block::BlockWrapper)).controller_path as *mut _
                as *mut c_void;
        }

        return Status::SUCCESS;
    }

    if unsafe { *guid } == r_efi::protocols::device_path::PROTOCOL_GUID
        && handle_type == HandleType::FileSystem
    {
        unsafe {
            if let Some(block_part_id) = (*(handle as *mut file::FileSystemWrapper)).block_part_id {
                *out = (&mut (*(BLOCK_WRAPPERS.wrappers[block_part_id as usize])).controller_path)
                    as *mut _ as *mut c_void;

                return Status::SUCCESS;
            }
        }
    }

    if unsafe { *guid } == block::PROTOCOL_GUID && handle_type == HandleType::Block {
        unsafe {
            *out = &mut (*(handle as *mut block::BlockWrapper)).proto as *mut _ as *mut c_void;
        }

        return Status::SUCCESS;
    }

    Status::UNSUPPORTED
}

pub extern "win64" fn close_protocol(_: Handle, _: *mut Guid, _: Handle, _: Handle) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn open_protocol_information(
    _: Handle,
    _: *mut Guid,
    _: *mut *mut OpenProtocolInformationEntry,
    _: *mut usize,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn protocols_per_handle(
    _: Handle,
    _: *mut *mut *mut Guid,
    _: *mut usize,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn locate_handle_buffer(
    _: LocateSearchType,
    _: *mut Guid,
    _: *mut c_void,
    _: *mut usize,
    _: *mut *mut Handle,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn locate_protocol(_: *mut Guid, _: *mut c_void, _: *mut *mut c_void) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn install_multiple_protocol_interfaces(
    _: *mut Handle,
    _: *mut c_void,
    _: *mut c_void,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn uninstall_multiple_protocol_interfaces(
    _: *mut Handle,
    _: *mut c_void,
    _: *mut c_void,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn calculate_crc32(_: *mut c_void, _: usize, _: *mut u32) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn copy_mem(_: *mut c_void, _: *mut c_void, _: usize) {}

pub extern "win64" fn set_mem(_: *mut c_void, _: usize, _: u8) {}

pub extern "win64" fn create_event_ex(
    _: u32,
    _: Tpl,
    _: EventNotify,
    _: *const c_void,
    _: *const Guid,
    _: *mut Event,
) -> Status {
    Status::UNSUPPORTED
}

extern "win64" fn image_unload(_: Handle) -> Status {
    efi::Status::UNSUPPORTED
}

fn extract_path(device_path: &DevicePathProtocol, path: &mut [u8]) {
    let mut dp = device_path;
    loop {
        if dp.r#type == r_efi::protocols::device_path::TYPE_MEDIA && dp.sub_type == 0x04 {
            let ptr =
                (dp as *const _ as u64 + size_of::<DevicePathProtocol>() as u64) as *const u16;
            crate::common::ucs2_to_ascii(ptr, path);
            return;
        }
        if dp.r#type == r_efi::protocols::device_path::TYPE_END && dp.sub_type == 0xff {
            panic!("Failed to extract path");
        }
        let len = unsafe { core::mem::transmute::<[u8; 2], u16>(dp.length) };
        dp = unsafe { &*((dp as *const _ as u64 + len as u64) as *const _) };
    }
}

extern "C" {
    #[link_name = "ram_min"]
    static RAM_MIN: c_void;
    #[link_name = "text_start"]
    static TEXT_START: c_void;
    #[link_name = "text_end"]
    static TEXT_END: c_void;
    #[link_name = "stack_start"]
    static STACK_START: c_void;
}

const PAGE_SIZE: u64 = 4096;
const HEAP_SIZE: usize = 256 * 1024 * 1024;

// Populate allocator from E820, fixed ranges for the firmware and the loaded binary.
fn populate_allocator(info: &dyn boot::Info, image_address: u64, image_size: u64) {
    for i in 0..info.num_entries() {
        let entry = info.entry(i);
        if entry.entry_type == boot::E820Entry::RAM_TYPE {
            ALLOCATOR.borrow_mut().add_initial_allocation(
                MemoryType::ConventionalMemory,
                entry.size / PAGE_SIZE,
                entry.addr,
                efi::MEMORY_WB,
            );
        }
    }

    let ram_min = unsafe { &RAM_MIN as *const _ as u64 };
    let text_start = unsafe { &TEXT_START as *const _ as u64 };
    let text_end = unsafe { &TEXT_END as *const _ as u64 };
    let stack_start = unsafe { &STACK_START as *const _ as u64 };
    let reloc_bin_start = unsafe { &EFI_RUNTIME_START as *const _ as u64 };
    let reloc_bin_end = unsafe { &EFI_RUNTIME_END as *const _ as u64 };
    assert!(ram_min % PAGE_SIZE == 0);
    assert!(text_start % PAGE_SIZE == 0);
    assert!(text_end % PAGE_SIZE == 0);
    assert!(stack_start % PAGE_SIZE == 0);

    // Add ourselves
    ALLOCATOR.borrow_mut().allocate_pages(
        AllocateType::AllocateAddress,
        MemoryType::RuntimeServicesData,
        (text_start - ram_min) / PAGE_SIZE,
        ram_min,
    );
    ALLOCATOR.borrow_mut().allocate_pages(
        AllocateType::AllocateAddress,
        MemoryType::RuntimeServicesCode,
        (text_end - text_start) / PAGE_SIZE,
        text_start,
    );
    ALLOCATOR.borrow_mut().allocate_pages(
        AllocateType::AllocateAddress,
        MemoryType::RuntimeServicesData,
        (stack_start - text_end) / PAGE_SIZE,
        text_end,
    );
    ALLOCATOR.borrow_mut().allocate_pages(
        AllocateType::AllocateAddress,
        MemoryType::RuntimeServicesCode,
        (reloc_bin_end - reloc_bin_start) / PAGE_SIZE,
        reloc_bin_start,
    );

    // Add the loaded binary
    ALLOCATOR.borrow_mut().allocate_pages(
        AllocateType::AllocateAddress,
        MemoryType::LoaderCode,
        image_size / PAGE_SIZE,
        image_address,
    );

    // Initialize heap allocator
    init_heap_allocator(HEAP_SIZE);
}

#[cfg(not(test))]
fn init_heap_allocator(size: usize) {
    let (status, heap_start) = ALLOCATOR.borrow_mut().allocate_pages(
        AllocateType::AllocateAnyPages,
        MemoryType::BootServicesCode,
        size as u64 / PAGE_SIZE,
        0,
    );
    assert!(status == Status::SUCCESS);
    unsafe {
        HEAP_ALLOCATOR.lock().init(heap_start as usize, size);
    }
}

#[cfg(test)]
fn init_heap_allocator(_: usize) {}

#[repr(C)]
struct LoadedImageWrapper {
    hw: HandleWrapper,
    proto: LoadedImageProtocol,
    entry_point: u64,
}

type DevicePaths = [file::FileDevicePathProtocol; 2];

fn new_image_handle(
    path: &str,
    parent_handle: Handle,
    device_handle: Handle,
    load_addr: u64,
    load_size: u64,
    entry_addr: u64,
) -> *mut LoadedImageWrapper {
    let mut file_paths = null_mut();
    let status = allocate_pool(
        MemoryType::LoaderData,
        size_of::<DevicePaths>(),
        &mut file_paths as *mut *mut c_void,
    );
    assert!(status == Status::SUCCESS);
    let file_paths = unsafe { &mut *(file_paths as *mut DevicePaths) };
    *file_paths = [
        file::FileDevicePathProtocol {
            device_path: DevicePathProtocol {
                r#type: r_efi::protocols::device_path::TYPE_MEDIA,
                sub_type: 4, // Media Path type file
                length: [132, 0],
            },
            filename: [0; 64],
        },
        file::FileDevicePathProtocol {
            device_path: DevicePathProtocol {
                r#type: r_efi::protocols::device_path::TYPE_END,
                sub_type: 0xff, // End of full path
                length: [4, 0],
            },
            filename: [0; 64],
        },
    ];

    crate::common::ascii_to_ucs2(path, &mut file_paths[0].filename);

    let mut image = null_mut();
    allocate_pool(
        MemoryType::LoaderData,
        size_of::<LoadedImageWrapper>(),
        &mut image as *mut *mut c_void,
    );
    assert!(status == Status::SUCCESS);
    let image = unsafe { &mut *(image as *mut LoadedImageWrapper) };
    *image = LoadedImageWrapper {
        hw: HandleWrapper {
            handle_type: HandleType::LoadedImage,
        },
        proto: LoadedImageProtocol {
            revision: r_efi::protocols::loaded_image::REVISION,
            parent_handle,
            system_table: unsafe { ST },
            device_handle,
            file_path: &mut file_paths[0].device_path, // Pointer to first path entry
            load_options_size: 0,
            load_options: null_mut(),
            image_base: load_addr as *mut _,
            image_size: load_size,
            image_code_type: efi::MemoryType::LoaderCode,
            image_data_type: efi::MemoryType::LoaderData,
            unload: image_unload,
            reserved: null_mut(),
        },
        entry_point: entry_addr,
    };
    image
}

extern "C" {
    #[link_name = "_binary_efi_runtime_start"]
    static EFI_RUNTIME_START: c_void;
    #[link_name = "_binary_efi_runtime_end"]
    static EFI_RUNTIME_END: c_void;
}

pub fn efi_exec(
    address: u64,
    loaded_address: u64,
    loaded_size: u64,
    info: &dyn boot::Info,
    fs: &crate::fat::Filesystem,
    block: *const crate::block::VirtioBlockDevice,
) {
    populate_allocator(info, loaded_address, loaded_size);

    let bin_start = unsafe { &EFI_RUNTIME_START as *const _ as u64 };
    let bin_end = unsafe { &EFI_RUNTIME_END as *const _ as u64};
    let header = elf::parse_header(bin_start, bin_end).unwrap();
    match elf::relocate(&header, bin_start, bin_start) {
        Ok(_) => (),
        Err(_) => log!("relocation failed"),
    };
    log!("bin_start: {:#x}", bin_start);

    let entry = elf::get_entry(bin_start, &header).unwrap();
    log!("Run efi_runtime::main() at {:#x}...", entry);
    let ptr = entry as *const ();
    let code: fn() -> *mut efi::SystemTable = unsafe { transmute(ptr) };
    unsafe { ST = (code)(); }
    log!("SystemTable: {:#x}", unsafe { ST } as u64);

    let vendor_data = 0u32;
    let acpi_rsdp_ptr = info.rsdp_addr();

    let mut ct = if acpi_rsdp_ptr != 0 {
        efi::ConfigurationTable {
            vendor_guid: Guid::from_fields(
                0x8868_e871,
                0xe4f1,
                0x11d3,
                0xbc,
                0x22,
                &[0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
            ),
            vendor_table: acpi_rsdp_ptr as u64 as *mut _,
        }
    } else {
        efi::ConfigurationTable {
            vendor_guid: Guid::from_fields(
                0x678a_9665,
                0x9957,
                0x4e7c,
                0xa6,
                0x27,
                &[0x34, 0xc9, 0x46, 0x3d, 0xd2, 0xac],
            ),
            vendor_table: &vendor_data as *const _ as *mut _,
        }
    };

    let mut st = unsafe { &mut (*ST) };
    let mut stdin = console::STDIN;
    let mut stdout = console::STDOUT;
    st.con_in = &mut stdin;
    st.con_out = &mut stdout;
    st.std_err = &mut stdout;
    st.console_in_handle = console::STDIN_HANDLE;
    st.console_out_handle = console::STDOUT_HANDLE;
    st.standard_error_handle = console::STDERR_HANDLE;
    st.boot_services = unsafe { &mut BS };
    st.number_of_table_entries = 1;
    st.configuration_table = &mut ct;

    let efi_part_id = unsafe { block::populate_block_wrappers(&mut BLOCK_WRAPPERS, block) };

    let wrapped_fs = file::FileSystemWrapper::new(fs, efi_part_id);

    let image = new_image_handle(
        "\\EFI\\BOOT\\BOOTX64.EFI",
        0 as Handle,
        &wrapped_fs as *const _ as Handle,
        loaded_address,
        loaded_size,
        address,
    );

    log!("Jumping in");
    let ptr = address as *const ();
    let code: extern "win64" fn(Handle, *mut efi::SystemTable) -> Status =
        unsafe { core::mem::transmute(ptr) };
    (code)((image as *const _) as Handle, unsafe { ST });
}
