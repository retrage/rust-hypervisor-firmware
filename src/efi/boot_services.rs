// SPDX-License-Identifier: Apache-2.0
// Copyright © 2019 Intel Corporation

use core::{cell::SyncUnsafeCell, ffi::c_void, mem::size_of, ptr::null_mut};

use r_efi::{
    efi::{
        self, AllocateType, Boolean, Char16, Event, EventNotify, Guid, Handle, InterfaceType,
        LocateSearchType, MemoryDescriptor, MemoryType, OpenProtocolInformationEntry,
        PhysicalAddress, Status, TimerDelay, Tpl,
    },
    protocols::device_path::Protocol as DevicePathProtocol,
};

#[cfg(target_arch = "riscv64")]
use r_efi::{eficall, eficall_abi};

use crate::{efi::PROTOCOL_MANAGER, fat};

use super::{
    device_path::DevicePath, file, mem_file, new_image_handle, LoadedImageWrapper, ALLOCATOR, ST,
};

pub static mut BS: SyncUnsafeCell<efi::BootServices> = SyncUnsafeCell::new(efi::BootServices {
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
});

const INVALID_GUID: Guid = Guid::from_fields(0, 0, 0, 0, 0, &[0_u8; 6]);
const MAX_CT_ENTRIES: usize = 8;
pub static mut CT: SyncUnsafeCell<[efi::ConfigurationTable; MAX_CT_ENTRIES]> = SyncUnsafeCell::new(
    [efi::ConfigurationTable {
        vendor_guid: INVALID_GUID,
        vendor_table: null_mut(),
    }; MAX_CT_ENTRIES],
);

fn log_guid(guid: &Guid) {
    let (time_low, time_mid, time_hi_and_version, clk_seq_hi_res, clk_seq_low, node) =
        guid.as_fields();
    log!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        time_low,
        time_mid,
        time_hi_and_version,
        clk_seq_hi_res,
        clk_seq_low,
        node[0],
        node[1],
        node[2],
        node[3],
        node[4],
        node[5],
    );
}

pub extern "efiapi" fn raise_tpl(_: Tpl) -> Tpl {
    0
}

pub extern "efiapi" fn restore_tpl(_: Tpl) {}

pub extern "efiapi" fn allocate_pages(
    allocate_type: AllocateType,
    memory_type: MemoryType,
    pages: usize,
    address: *mut PhysicalAddress,
) -> Status {
    let (status, new_address) =
        ALLOCATOR
            .borrow_mut()
            .allocate_pages(allocate_type, memory_type, pages as u64, unsafe {
                *address
            });
    if status == Status::SUCCESS {
        unsafe {
            *address = new_address;
        }
    }
    status
}

pub extern "efiapi" fn free_pages(address: PhysicalAddress, _: usize) -> Status {
    ALLOCATOR.borrow_mut().free_pages(address)
}

pub extern "efiapi" fn get_memory_map(
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

    let out = unsafe { core::slice::from_raw_parts_mut(out, count) };
    let count = ALLOCATOR.borrow().get_descriptors(out);
    let map_size = size_of::<MemoryDescriptor>() * count;
    unsafe {
        *memory_map_size = map_size;
        *key = ALLOCATOR.borrow().get_map_key();
    }

    Status::SUCCESS
}

pub extern "efiapi" fn allocate_pool(
    memory_type: MemoryType,
    size: usize,
    address: *mut *mut c_void,
) -> Status {
    let (status, new_address) = ALLOCATOR.borrow_mut().allocate_pool(memory_type, size);

    if status == Status::SUCCESS {
        unsafe {
            *address = new_address as *mut c_void;
        }
    }

    status
}

pub extern "efiapi" fn free_pool(ptr: *mut c_void) -> Status {
    ALLOCATOR.borrow_mut().free_pool(ptr as u64)
}

pub extern "efiapi" fn create_event(
    _: u32,
    _: Tpl,
    _: Option<EventNotify>,
    _: *mut c_void,
    _: *mut Event,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn set_timer(_: Event, _: TimerDelay, _: u64) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn wait_for_event(_: usize, _: *mut Event, _: *mut usize) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn signal_event(_: Event) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn close_event(_: Event) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn check_event(_: Event) -> Status {
    Status::UNSUPPORTED
}

#[allow(dead_code)]
const SHIM_LOCK_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x605d_ab50,
    0xe046,
    0x4300,
    0xab,
    0xb6,
    &[0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23],
);

pub extern "efiapi" fn install_protocol_interface(
    handle: *mut Handle,
    guid: *mut Guid,
    interface_type: InterfaceType,
    interface: *mut c_void,
) -> Status {
    log!(
        "install_protocol_interface: {:p} {:p} {:?} {:p}\n",
        handle,
        guid,
        interface_type,
        interface
    );
    // if unsafe { *guid } == SHIM_LOCK_PROTOCOL_GUID {
    //     Status::SUCCESS
    // } else {
    //     Status::UNSUPPORTED
    // }
    match PROTOCOL_MANAGER.borrow_mut().install_protocol_interface(
        handle,
        guid,
        interface_type,
        interface,
    ) {
        Ok(_) => Status::SUCCESS,
        Err(e) => e.into(),
    }
}

pub extern "efiapi" fn reinstall_protocol_interface(
    handle: Handle,
    guid: *mut Guid,
    old_interface: *mut c_void,
    new_interface: *mut c_void,
) -> Status {
    log!(
        "reinstall_protocol_interface: {:?} {:p} {:p} {:p}\n",
        handle,
        guid,
        old_interface,
        new_interface
    );
    match PROTOCOL_MANAGER.borrow_mut().reinstall_protocol_interface(
        handle,
        guid,
        old_interface,
        new_interface,
    ) {
        Ok(_) => Status::SUCCESS,
        Err(e) => e.into(),
    }
}

pub extern "efiapi" fn uninstall_protocol_interface(
    handle: Handle,
    guid: *mut Guid,
    interface: *mut c_void,
) -> Status {
    log!(
        "uninstall_protocol_interface: {:?} {:p} {:p}\n",
        handle,
        guid,
        interface
    );
    match PROTOCOL_MANAGER
        .borrow_mut()
        .uninstall_protocol_interface(handle, guid, interface)
    {
        Ok(_) => Status::SUCCESS,
        Err(e) => e.into(),
    }
}

pub extern "efiapi" fn handle_protocol(
    handle: Handle,
    guid: *mut Guid,
    interface: *mut *mut c_void,
) -> Status {
    log!("handle_protocol: {:?} {:p} {:p}\n", handle, guid, interface);
    log_guid(unsafe { &*guid });
    match PROTOCOL_MANAGER
        .borrow_mut()
        .handle_protocol(handle, guid, interface)
    {
        Ok(_) => Status::SUCCESS,
        Err(e) => {
            log!("handle_protocol: {:?}\n", e);
            e.into()
        }
    }
}

pub extern "efiapi" fn register_protocol_notify(
    protocol: *mut Guid,
    event: Event,
    registration: *mut *mut c_void,
) -> Status {
    log!(
        "register_protocol_notify: {:p} {:p} {:p}\n",
        protocol,
        event,
        registration
    );
    match PROTOCOL_MANAGER
        .borrow_mut()
        .register_protocol_notify(protocol, event, registration)
    {
        Ok(_) => Status::SUCCESS,
        Err(e) => e.into(),
    }
}

pub extern "efiapi" fn locate_handle(
    search_type: LocateSearchType,
    guid: *mut Guid,
    search_key: *mut c_void,
    size: *mut usize,
    handles: *mut Handle,
) -> Status {
    log!(
        "locate_handle: {:?} {:p} {:p} {:p} {:p}\n",
        search_type,
        guid,
        search_key,
        size,
        handles
    );
    log_guid(unsafe { &*guid });
    match PROTOCOL_MANAGER
        .borrow_mut()
        .locate_handle(search_type, guid, search_key, size, handles)
    {
        Ok(_) => Status::SUCCESS,
        Err(e) => {
            log!("locate_handle: {:?}\n", e);
            e.into()
        }
    }
}

/*
pub extern "efiapi" fn locate_handle(
    _: LocateSearchType,
    guid: *mut Guid,
    _: *mut c_void,
    size: *mut usize,
    handles: *mut Handle,
) -> Status {
    if unsafe { *guid } == r_efi::protocols::block_io::PROTOCOL_GUID {
        let count = unsafe { BLOCK_WRAPPERS.get_mut().count };
        if unsafe { *size } < size_of::<Handle>() * count {
            unsafe { *size = size_of::<Handle>() * count };
            return Status::BUFFER_TOO_SMALL;
        }

        let handles =
            unsafe { core::slice::from_raw_parts_mut(handles, *size / size_of::<Handle>()) };

        let wrappers_as_handles: &[Handle] = unsafe {
            core::slice::from_raw_parts_mut(
                BLOCK_WRAPPERS.get_mut().wrappers.as_mut_ptr() as *mut Handle,
                count,
            )
        };

        handles[0..count].copy_from_slice(wrappers_as_handles);

        unsafe { *size = size_of::<Handle>() * count };

        return Status::SUCCESS;
    }

    Status::UNSUPPORTED
}
*/

pub extern "efiapi" fn locate_device_path(
    protocol: *mut Guid,
    device_path: *mut *mut DevicePathProtocol,
    device: *mut Handle,
) -> Status {
    log!(
        "locate_device_path: {:p} {:p} {:p}\n",
        protocol,
        device_path,
        device
    );
    match PROTOCOL_MANAGER
        .borrow_mut()
        .locate_device_path(protocol, device_path, device)
    {
        Ok(_) => Status::SUCCESS,
        Err(e) => e.into(),
    }
}

pub extern "efiapi" fn install_configuration_table(guid: *mut Guid, table: *mut c_void) -> Status {
    let st = unsafe { ST.get_mut() };
    let ct = unsafe { CT.get_mut() };

    for entry in ct.iter_mut() {
        if entry.vendor_guid == unsafe { *guid } {
            if table.is_null() {
                entry.vendor_guid = INVALID_GUID;
                entry.vendor_table = null_mut();
                st.number_of_table_entries -= 1;
            } else {
                entry.vendor_table = table;
            }
            return Status::SUCCESS;
        }
    }

    if table.is_null() {
        // Trying to delete the table, but not found.
        return Status::NOT_FOUND;
    }

    for entry in ct.iter_mut() {
        if entry.vendor_guid == INVALID_GUID && entry.vendor_table.is_null() {
            entry.vendor_guid = unsafe { *guid };
            entry.vendor_table = table;
            st.number_of_table_entries += 1;
            return Status::SUCCESS;
        }
    }

    Status::OUT_OF_RESOURCES
}

pub extern "efiapi" fn load_image(
    _boot_policy: Boolean,
    parent_image_handle: Handle,
    device_path: *mut DevicePathProtocol,
    _source_buffer: *mut c_void,
    _source_size: usize,
    image_handle: *mut Handle,
) -> Status {
    let device_path = unsafe { &*device_path };
    match &DevicePath::parse(device_path) {
        dp @ DevicePath::File(path) => {
            let path = crate::common::ascii_strip(path);

            let li = parent_image_handle as *const LoadedImageWrapper;
            let dh = unsafe { (*li).proto.device_handle };
            let wrapped_fs_ref = unsafe { &*(dh as *const file::FileSystemWrapper) };
            let device_handle = wrapped_fs_ref as *const _ as Handle;

            let mut file = match wrapped_fs_ref.fs.open(path) {
                Ok(file) => file,
                Err(_) => return Status::DEVICE_ERROR,
            };

            load_from_file(
                &mut file,
                dp,
                parent_image_handle,
                device_handle,
                image_handle,
            )
        }
        dp @ DevicePath::Memory(_memory_type, start, end) => {
            let mut file = mem_file::MemoryFile::new(*start, (*end - *start) as u32);
            load_from_file(&mut file, dp, parent_image_handle, null_mut(), image_handle)
        }
        _ => Status::UNSUPPORTED,
    }
}

fn load_from_file(
    file: &mut dyn fat::Read,
    dp: &DevicePath,
    parent_image_handle: *mut c_void,
    device_handle: *mut c_void,
    image_handle: *mut *mut c_void,
) -> Status {
    let file_size = ALLOCATOR.borrow_mut().page_count(file.get_size() as usize);
    // Get free pages address
    let load_addr =
        match ALLOCATOR
            .borrow_mut()
            .find_free_pages(efi::ALLOCATE_ANY_PAGES, file_size, 0)
        {
            Some(a) => a,
            None => return Status::OUT_OF_RESOURCES,
        };

    let mut l = crate::pe::Loader::new(file);
    let (entry_addr, load_addr, load_size) = match l.load(load_addr) {
        Ok(load_info) => load_info,
        Err(_) => return Status::DEVICE_ERROR,
    };
    ALLOCATOR.borrow_mut().allocate_pages(
        efi::ALLOCATE_ADDRESS,
        efi::LOADER_CODE,
        file_size,
        load_addr,
    );

    match new_image_handle(
        dp.generate(),
        parent_image_handle,
        device_handle,
        load_addr,
        load_size,
        entry_addr,
    ) {
        Ok(handle) => {
            unsafe { *image_handle = handle };
            Status::SUCCESS
        }
        Err(e) => e.into(),
    }
}

pub extern "efiapi" fn start_image(
    image_handle: Handle,
    _: *mut usize,
    _: *mut *mut Char16,
) -> Status {
    let wrapped_handle = image_handle as *const LoadedImageWrapper;
    let address = unsafe { (*wrapped_handle).entry_point };
    let ptr = address as *const ();
    let code: extern "efiapi" fn(Handle, *mut efi::SystemTable) -> Status =
        unsafe { core::mem::transmute(ptr) };
    (code)(image_handle, unsafe { ST.get() })
}

pub extern "efiapi" fn exit(_: Handle, _: Status, _: usize, _: *mut Char16) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn unload_image(_: Handle) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn exit_boot_services(_: Handle, _: usize) -> Status {
    Status::SUCCESS
}

pub extern "efiapi" fn get_next_monotonic_count(_: *mut u64) -> Status {
    Status::DEVICE_ERROR
}

pub extern "efiapi" fn stall(microseconds: usize) -> Status {
    crate::delay::udelay(microseconds as u64);
    Status::SUCCESS
}

pub extern "efiapi" fn set_watchdog_timer(_: usize, _: u64, _: usize, _: *mut Char16) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn connect_controller(
    controller_handle: Handle,
    driver_image_handle: *mut Handle,
    remaining_device_path: *mut DevicePathProtocol,
    recursive: Boolean,
) -> Status {
    log!(
        "connect_controller: {:?} {:p} {:p} {:?}\n",
        controller_handle,
        driver_image_handle,
        remaining_device_path,
        recursive
    );
    match PROTOCOL_MANAGER.borrow_mut().connect_controller(
        controller_handle,
        driver_image_handle,
        remaining_device_path,
        recursive,
    ) {
        Ok(_) => Status::SUCCESS,
        Err(e) => e.into(),
    }
}

pub extern "efiapi" fn disconnect_controller(
    controller_handle: Handle,
    driver_image_handle: Handle,
    child_handle: Handle,
) -> Status {
    log!(
        "disconnect_controller: {:?} {:?} {:?}\n",
        controller_handle,
        driver_image_handle,
        child_handle
    );
    match PROTOCOL_MANAGER.borrow_mut().disconnect_controller(
        controller_handle,
        driver_image_handle,
        child_handle,
    ) {
        Ok(_) => Status::SUCCESS,
        Err(e) => e.into(),
    }
}

pub extern "efiapi" fn open_protocol(
    user_handle: Handle,
    protocol_guid: *mut Guid,
    interface: *mut *mut c_void,
    agent_handle: Handle,
    controller_handle: Handle,
    attributes: u32,
) -> Status {
    log!(
        "open_protocol: {:?} {:p} {:p} {:p} {:p} {:x}\n",
        user_handle,
        protocol_guid,
        interface,
        agent_handle,
        controller_handle,
        attributes
    );
    match PROTOCOL_MANAGER.borrow_mut().open_protocol(
        user_handle,
        protocol_guid,
        interface,
        agent_handle,
        controller_handle,
        attributes,
    ) {
        Ok(_) => Status::SUCCESS,
        Err(e) => e.into(),
    }
}

/*
pub extern "efiapi" fn open_protocol(
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
                *out = (&mut (*(BLOCK_WRAPPERS.get_mut().wrappers[block_part_id as usize]))
                    .controller_path) as *mut _ as *mut c_void;

                return Status::SUCCESS;
            }
        }
    }

    if unsafe { *guid } == r_efi::protocols::block_io::PROTOCOL_GUID
        && handle_type == HandleType::Block
    {
        unsafe {
            *out = &mut (*(handle as *mut block::BlockWrapper)).proto as *mut _ as *mut c_void;
        }

        return Status::SUCCESS;
    }

    Status::UNSUPPORTED
}
*/

pub extern "efiapi" fn close_protocol(
    user_handle: Handle,
    protocol: *mut Guid,
    agent_handle: Handle,
    controller_handle: Handle,
) -> Status {
    log!(
        "close_protocol: {:?} {:p} {:?} {:?}\n",
        user_handle,
        protocol,
        agent_handle,
        controller_handle
    );
    match PROTOCOL_MANAGER.borrow_mut().close_protocol(
        user_handle,
        protocol,
        agent_handle,
        controller_handle,
    ) {
        Ok(_) => Status::SUCCESS,
        Err(e) => e.into(),
    }
}

pub extern "efiapi" fn open_protocol_information(
    handle: Handle,
    protocol_guid: *mut Guid,
    entry_buffer: *mut *mut OpenProtocolInformationEntry,
    entry_count: *mut usize,
) -> Status {
    log!(
        "open_protocol_information: {:?} {:p} {:p} {:p}\n",
        handle,
        protocol_guid,
        entry_buffer,
        entry_count
    );
    match PROTOCOL_MANAGER.borrow_mut().open_protocol_information(
        handle,
        protocol_guid,
        entry_buffer,
        entry_count,
    ) {
        Ok(_) => Status::SUCCESS,
        Err(e) => e.into(),
    }
}

pub extern "efiapi" fn protocols_per_handle(
    handle: Handle,
    protocol_buffer: *mut *mut *mut Guid,
    protocol_buffer_count: *mut usize,
) -> Status {
    log!(
        "protocols_per_handle: {:?} {:p} {:p}\n",
        handle,
        protocol_buffer,
        protocol_buffer_count
    );
    match PROTOCOL_MANAGER.borrow_mut().protocols_per_handle(
        handle,
        protocol_buffer,
        protocol_buffer_count,
    ) {
        Ok(_) => Status::SUCCESS,
        Err(e) => e.into(),
    }
}

pub extern "efiapi" fn locate_handle_buffer(
    search_type: LocateSearchType,
    protocol: *mut Guid,
    search_key: *mut c_void,
    no_handles: *mut usize,
    buffer: *mut *mut Handle,
) -> Status {
    log!(
        "locate_handle_buffer: {:?} {:p} {:p} {:p} {:p}\n",
        search_type,
        protocol,
        search_key,
        no_handles,
        buffer
    );
    match PROTOCOL_MANAGER.borrow_mut().locate_handle_buffer(
        search_type,
        protocol,
        search_key,
        no_handles,
        buffer,
    ) {
        Ok(_) => Status::SUCCESS,
        Err(e) => e.into(),
    }
}

#[allow(dead_code)]
#[cfg(target_arch = "riscv64")]
#[repr(C)]
struct RiscVBootProtocol {
    revision: u64,
    get_boot_hart_id: eficall! {fn(*const RiscVBootProtocol, *mut u64) -> Status },
}

#[allow(dead_code)]
#[cfg(target_arch = "riscv64")]
extern "efiapi" fn get_boot_hart_id(_: *const RiscVBootProtocol, hart: *mut u64) -> Status {
    unsafe { *hart = 0 };
    Status::SUCCESS
}

#[allow(dead_code)]
#[cfg(target_arch = "riscv64")]
const RISC_V_BOOT_PROTOCOL: RiscVBootProtocol = RiscVBootProtocol {
    revision: 0,
    get_boot_hart_id,
};

#[allow(dead_code)]
#[cfg(target_arch = "riscv64")]
pub const RISV_V_BOOT_PROTOCOL_GUID: Guid = Guid::from_fields(
    0xccd15fec,
    0x6f73,
    0x4eec,
    0x83,
    0x95,
    &[0x3e, 0x69, 0xe4, 0xb9, 0x40, 0xbf],
);

pub extern "efiapi" fn locate_protocol(
    guid: *mut Guid,
    registration: *mut c_void,
    interface: *mut *mut c_void,
) -> Status {
    log!(
        "locate_protocol: {:p} {:p} {:p}\n",
        guid,
        registration,
        interface
    );
    match PROTOCOL_MANAGER
        .borrow_mut()
        .locate_protocol(guid, registration, interface)
    {
        Ok(_) => Status::SUCCESS,
        Err(e) => e.into(),
    }
    // #[cfg(target_arch = "riscv64")]
    // if unsafe { *_guid } == RISV_V_BOOT_PROTOCOL_GUID {
    //     unsafe { *_out = &RISC_V_BOOT_PROTOCOL as *const RiscVBootProtocol as *mut c_void };
    //     return Status::SUCCESS;
    // }
    // // XXX: A recent version of Linux kernel fails to boot if EFI_UNSUPPORTED returned.
    // Status::NOT_FOUND
}

pub extern "efiapi" fn install_multiple_protocol_interfaces(
    _: *mut Handle,
    _: *mut c_void,
    _: *mut c_void,
) -> Status {
    log!("install_multiple_protocol_interfaces");
    Status::UNSUPPORTED
}

pub extern "efiapi" fn uninstall_multiple_protocol_interfaces(
    _: Handle,
    _: *mut c_void,
    _: *mut c_void,
) -> Status {
    log!("uninstall_multiple_protocol_interfaces");
    Status::UNSUPPORTED
}

pub extern "efiapi" fn calculate_crc32(_: *mut c_void, _: usize, _: *mut u32) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn copy_mem(dst: *mut c_void, src: *mut c_void, count: usize) {
    unsafe { core::ptr::copy(src as *const u8, dst as *mut u8, count) }
}

pub extern "efiapi" fn set_mem(dst: *mut c_void, count: usize, val: u8) {
    unsafe { core::ptr::write_bytes(dst as *mut u8, val, count) }
}

pub extern "efiapi" fn create_event_ex(
    _: u32,
    _: Tpl,
    _: Option<EventNotify>,
    _: *const c_void,
    _: *const Guid,
    _: *mut Event,
) -> Status {
    Status::UNSUPPORTED
}
