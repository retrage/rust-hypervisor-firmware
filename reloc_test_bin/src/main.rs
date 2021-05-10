#![no_std]
#![no_main]

use core::{
    ffi::c_void,
    mem::size_of,
    panic::PanicInfo,
};

use x86_64::instructions::hlt;
#[allow(unused_imports)]
use r_efi::{
    efi::{
        self, AllocateType, Boolean, CapsuleHeader, Char16, Event, EventNotify, Guid, Handle,
        InterfaceType, LocateSearchType, MemoryDescriptor, MemoryType,
        OpenProtocolInformationEntry, PhysicalAddress, ResetType, Status, Time, TimeCapabilities,
        TimerDelay, Tpl,
    },
};

#[macro_use]
mod serial;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log!("PANIC: {}", info);
    loop {
        hlt()
    }
}

#[used]
#[link_section = ".efi_rs.data"]
static RS: efi::RuntimeServices = efi::RuntimeServices {
    hdr: efi::TableHeader {
        signature: efi::RUNTIME_SERVICES_SIGNATURE,
        revision: efi::RUNTIME_SERVICES_REVISION,
        header_size: size_of::<efi::RuntimeServices>() as u32, 
        crc32: 0, // TODO
        reserved: 0,
    },   
    get_time,
    set_time,
    get_wakeup_time,
    set_wakeup_time,
    set_virtual_address_map,
    convert_pointer,
    get_variable,
    get_next_variable_name,
    set_variable,
    get_next_high_mono_count,
    reset_system,
    update_capsule,
    query_capsule_capabilities,
    query_variable_info,
};

pub extern "win64" fn get_time(_: *mut Time, _: *mut TimeCapabilities) -> Status {
    log!("get_time");
    Status::UNSUPPORTED
}

pub extern "win64" fn set_time(_: *mut Time) -> Status {
    log!("set_time");
    Status::DEVICE_ERROR
}

pub extern "win64" fn get_wakeup_time(_: *mut Boolean, _: *mut Boolean, _: *mut Time) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn set_wakeup_time(_: Boolean, _: *mut Time) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn set_virtual_address_map(
    _: usize,
    _: usize,
    _: u32, 
    _: *mut MemoryDescriptor,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn convert_pointer(_: usize, _: *mut *mut c_void) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn get_variable(
    _: *mut Char16,
    _: *mut Guid,
    _: *mut u32,
    _: *mut usize,
    _: *mut c_void,
) -> Status {
    log!("get_variable");
    Status::NOT_FOUND
}

pub extern "win64" fn get_next_variable_name(
    _: *mut usize,
    _: *mut Char16,
    _: *mut Guid,
) -> Status {
    Status::NOT_FOUND
}

pub extern "win64" fn set_variable(
    _: *mut Char16,
    _: *mut Guid,
    _: u32,
    _: usize,
    _: *mut c_void,
) -> Status {
    log!("set_variable");
    Status::DEVICE_ERROR
}

pub extern "win64" fn get_next_high_mono_count(_: *mut u32) -> Status {
    Status::DEVICE_ERROR
}

pub extern "win64" fn reset_system(_: ResetType, _: Status, _: usize, _: *mut c_void) {
    // Don't do anything to force the kernel to use ACPI for shutdown and triple-fault for reset
}

pub extern "win64" fn update_capsule(
    _: *mut *mut CapsuleHeader,
    _: usize,
    _: PhysicalAddress,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn query_capsule_capabilities(
    _: *mut *mut CapsuleHeader,
    _: usize,
    _: *mut u64,
    _: *mut ResetType,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn query_variable_info(
    _: u32,
    max_storage: *mut u64,
    remaining_storage: *mut u64,
    max_size: *mut u64,
) -> Status {
    unsafe {
        *max_storage = 0;
        *remaining_storage = 0;
        *max_size = 0;
    }
    Status::SUCCESS
}

#[no_mangle]
fn main() {
    serial::PORT.borrow_mut().init();

    log!("Hello, world from outer section!");

    let rs = &RS as *const _ as u64;
    log!("RuntimeServices is at {:#x}", rs);
}