// SPDX-License-Identifier: Apache-2.0
// Copyright © 2019 Intel Corporation

use core::{
    cell::SyncUnsafeCell,
    ffi::c_void,
    mem::size_of,
    ptr::{addr_of, null_mut},
};

use atomic_refcell::AtomicRefCell;
use r_efi::{
    efi::{self, Guid, Handle, Status},
    protocols::loaded_image::{self, Protocol as LoadedImageProtocol},
};

use crate::{bootinfo, layout};

mod alloc;
mod block;
mod boot_services;
mod console;
mod device_path;
mod file;
mod mem_file;
mod protocol;
mod runtime_services;
mod var;

use alloc::Allocator;
use boot_services::{BS, CT};
use device_path::DevicePath;
use protocol::ProtocolManager;
use runtime_services::RS;
use var::VariableAllocator;

#[cfg(target_arch = "aarch64")]
pub const EFI_BOOT_PATH: &str = "\\EFI\\BOOT\\BOOTAA64.EFI";
#[cfg(target_arch = "x86_64")]
pub const EFI_BOOT_PATH: &str = "\\EFI\\BOOT\\BOOTX64.EFI";
#[cfg(target_arch = "riscv64")]
pub const EFI_BOOT_PATH: &str = "\\EFI\\BOOT\\BOOTRISCV64.EFI";

pub static ALLOCATOR: AtomicRefCell<Allocator> =
    AtomicRefCell::new(Allocator::new(layout::MemoryDescriptor::PAGE_SIZE as u64));

static PROTOCOL_MANAGER: AtomicRefCell<ProtocolManager> =
    AtomicRefCell::new(ProtocolManager::new());

pub static VARIABLES: AtomicRefCell<VariableAllocator> =
    AtomicRefCell::new(VariableAllocator::new());

// RHF string in UCS-2
const FIRMWARE_STRING: [u16; 4] = [0x0052, 0x0048, 0x0046, 0x0000];

static mut ST: SyncUnsafeCell<efi::SystemTable> = SyncUnsafeCell::new(efi::SystemTable {
    hdr: efi::TableHeader {
        signature: efi::SYSTEM_TABLE_SIGNATURE,
        revision: (2 << 16) | (80),
        header_size: size_of::<efi::SystemTable>() as u32,
        crc32: 0, // TODO
        reserved: 0,
    },
    firmware_vendor: FIRMWARE_STRING.as_ptr() as *mut u16,
    firmware_revision: 0,
    console_in_handle: null_mut(),
    con_in: null_mut(),
    console_out_handle: null_mut(),
    con_out: null_mut(),
    standard_error_handle: null_mut(),
    std_err: null_mut(),
    runtime_services: null_mut(),
    boot_services: null_mut(),
    number_of_table_entries: 0,
    configuration_table: null_mut(),
});

// Populate allocator from E820, fixed ranges for the firmware and the loaded binary.
fn populate_allocator(info: &dyn bootinfo::Info, image_address: u64, image_size: u64) {
    for i in 0..info.num_entries() {
        let entry = info.entry(i);
        match entry.entry_type {
            bootinfo::EntryType::Ram => {
                let page_count = ALLOCATOR.borrow().page_count(entry.size as usize);
                ALLOCATOR.borrow_mut().add_initial_allocation(
                    efi::CONVENTIONAL_MEMORY,
                    page_count,
                    entry.addr,
                    efi::MEMORY_WB,
                );
            }
            _ => continue,
        }
    }

    for descriptor in info.memory_layout() {
        let memory_type = match descriptor.attribute {
            layout::MemoryAttribute::Code => efi::RUNTIME_SERVICES_CODE,
            layout::MemoryAttribute::Data => efi::RUNTIME_SERVICES_DATA,
            layout::MemoryAttribute::Unusable => efi::UNUSABLE_MEMORY,
            layout::MemoryAttribute::Mmio => efi::MEMORY_MAPPED_IO,
        };
        ALLOCATOR.borrow_mut().allocate_pages(
            efi::ALLOCATE_ADDRESS,
            memory_type,
            descriptor.page_count() as u64,
            descriptor.range_start() as u64,
        );
    }

    if let Some(fdt_entry) = info.fdt_reservation() {
        let page_count = ALLOCATOR.borrow().page_count(fdt_entry.size as usize);
        ALLOCATOR.borrow_mut().allocate_pages(
            efi::ALLOCATE_ADDRESS,
            efi::UNUSABLE_MEMORY,
            page_count,
            fdt_entry.addr,
        );
    }

    // Add the loaded binary
    let page_count = ALLOCATOR.borrow().page_count(image_size as usize);
    ALLOCATOR.borrow_mut().allocate_pages(
        efi::ALLOCATE_ADDRESS,
        efi::LOADER_CODE,
        page_count,
        image_address,
    );
}

trait Protocol {
    fn as_proto(&mut self) -> *mut core::ffi::c_void {
        self as *mut _ as *mut core::ffi::c_void
    }
}

#[repr(C)]
struct LoadedImageWrapper {
    proto: LoadedImageProtocol,
    entry_point: u64,
}

impl LoadedImageWrapper {
    fn new(
        file_path: *mut r_efi::protocols::device_path::Protocol,
        parent_handle: Handle,
        device_handle: Handle,
        load_addr: u64,
        load_size: u64,
        entry_addr: u64,
    ) -> LoadedImageWrapper {
        LoadedImageWrapper {
            proto: LoadedImageProtocol {
                revision: r_efi::protocols::loaded_image::REVISION,
                parent_handle,
                system_table: unsafe { ST.get_mut() },
                device_handle,
                file_path,
                load_options_size: 0,
                load_options: null_mut(),
                image_base: load_addr as *mut _,
                image_size: load_size,
                image_code_type: efi::LOADER_CODE,
                image_data_type: efi::LOADER_DATA,
                unload: boot_services::unload_image,
                reserved: null_mut(),
            },
            entry_point: entry_addr,
        }
    }
}

impl Protocol for LoadedImageWrapper {
    fn as_proto(&mut self) -> *mut c_void {
        &mut self.proto as *mut _ as *mut c_void
    }
}

fn new_image_handle(
    handle: Option<Handle>,
    file_path: *mut r_efi::protocols::device_path::Protocol,
    parent_handle: Handle,
    device_handle: Handle,
    load_addr: u64,
    load_size: u64,
    entry_addr: u64,
) -> Result<Handle, protocol::Error> {
    install_protocol_wrapper(
        handle,
        &loaded_image::PROTOCOL_GUID,
        LoadedImageWrapper::new(
            file_path,
            parent_handle,
            device_handle,
            load_addr,
            load_size,
            entry_addr,
        ),
    )
}

fn install_protocol_wrapper<T>(
    handle: Option<Handle>,
    guid: &Guid,
    val: T,
) -> Result<efi::Handle, protocol::Error>
where
    T: Protocol,
{
    let (status, address) = ALLOCATOR
        .borrow_mut()
        .allocate_pool(efi::LOADER_DATA, size_of::<T>());
    assert!(status == Status::SUCCESS);

    unsafe {
        (address as *mut T).write(val);
    }
    let wrapper = unsafe { &mut *(address as *mut T) };
    let handle = handle.unwrap_or(null_mut());
    let handle_ptr = addr_of!(handle) as *mut Handle;

    match PROTOCOL_MANAGER.borrow_mut().install_protocol_interface(
        handle_ptr,
        guid,
        efi::NATIVE_INTERFACE,
        wrapper.as_proto(),
    ) {
        Ok(_) => Ok(unsafe { handle_ptr.read() }),
        Err(e) => Err(e),
    }
}

#[allow(dead_code)]
fn add_shim_debug_vars() {
    const SHIM_LOCK_PROTOCOL_GUID: Guid = Guid::from_fields(
        0x605d_ab50,
        0xe046,
        0x4300,
        0xab,
        0xb6,
        &[0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23],
    );

    const SHIM_VERBOSE_VAR_NAME: [u16; 13] = [83, 72, 73, 77, 95, 86, 69, 82, 66, 79, 83, 69, 0];
    const SHIM_VERBOSE_DATA: [u8; 1] = [1];
    VARIABLES.borrow_mut().set(
        SHIM_VERBOSE_VAR_NAME.as_ptr(),
        &SHIM_LOCK_PROTOCOL_GUID,
        efi::VARIABLE_BOOTSERVICE_ACCESS,
        SHIM_VERBOSE_DATA.len(),
        SHIM_VERBOSE_DATA.as_ptr() as *const _,
    );
}

pub fn efi_exec<'a>(
    address: u64,
    loaded_address: u64,
    loaded_size: u64,
    info: &dyn bootinfo::Info,
    fs: &crate::fat::Filesystem,
    block: &'a crate::block::VirtioBlockDevice<'a>,
) {
    let vendor_data = 0u32;

    let ct = unsafe { CT.get_mut() };
    let mut ct_index = 0;

    // Populate with FDT table if present
    // To ensure ACPI is used during boot do not include FDT table on aarch64
    // https://github.com/torvalds/linux/blob/d528014517f2b0531862c02865b9d4c908019dc4/arch/arm64/kernel/acpi.c#L203
    #[cfg(not(target_arch = "aarch64"))]
    if let Some(fdt_entry) = info.fdt_reservation() {
        ct[ct_index] = efi::ConfigurationTable {
            vendor_guid: Guid::from_fields(
                0xb1b621d5,
                0xf19c,
                0x41a5,
                0x83,
                0x0b,
                &[0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0],
            ),
            vendor_table: fdt_entry.addr as *const u64 as *mut _,
        };
        ct_index += 1;
    }

    // Populate with ACPI RSDP table if present
    if let Some(acpi_rsdp_ptr) = info.rsdp_addr() {
        ct[ct_index] = efi::ConfigurationTable {
            vendor_guid: Guid::from_fields(
                0x8868_e871,
                0xe4f1,
                0x11d3,
                0xbc,
                0x22,
                &[0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
            ),
            vendor_table: acpi_rsdp_ptr as *mut _,
        };
        ct_index += 1;
    }

    // Othwerwise fill with zero vendor data
    if ct_index == 0 {
        ct[ct_index] = efi::ConfigurationTable {
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

    populate_allocator(info, loaded_address, loaded_size);

    // add_shim_debug_vars();

    // Create a new handle
    let (status, handle_addr) = ALLOCATOR
        .borrow_mut()
        .allocate_pool(efi::BOOT_SERVICES_DATA, size_of::<efi::Handle>());
    assert!(status == efi::Status::SUCCESS);
    let core_handle = handle_addr as efi::Handle;

    let dp_handle = block::populate_block_wrappers(Some(core_handle), block).unwrap();

    let fs_handle = file::populate_fs_wrapper(Some(dp_handle), fs).unwrap();

    let stdin_handle = console::populate_stdin_wrapper(Some(core_handle)).unwrap();
    let stdout_handle = console::populate_stdout_wrapper(Some(core_handle)).unwrap();

    let mut stdin = console::STDIN;
    let mut stdout = console::STDOUT;
    let st = unsafe { ST.get_mut() };
    st.console_in_handle = stdin_handle;
    st.con_in = &mut stdin;
    st.console_out_handle = stdout_handle;
    st.con_out = &mut stdout;
    st.standard_error_handle = stdout_handle;
    st.std_err = &mut stdout;
    st.runtime_services = unsafe { RS.get_mut() };
    st.boot_services = unsafe { BS.get_mut() };
    st.number_of_table_entries = 1;
    st.configuration_table = &mut ct[0];

    let mut path = [0u8; 256];
    path[0..crate::efi::EFI_BOOT_PATH.as_bytes().len()]
        .copy_from_slice(crate::efi::EFI_BOOT_PATH.as_bytes());
    let device_path = DevicePath::File(path);
    let image = new_image_handle(
        None,
        device_path.generate(),
        core_handle,
        fs_handle,
        loaded_address,
        loaded_size,
        address,
    )
    .unwrap();

    let ptr = address as *const ();
    let code: extern "efiapi" fn(Handle, *mut efi::SystemTable) -> Status =
        unsafe { core::mem::transmute(ptr) };
    (code)(image, &mut *st);
}
