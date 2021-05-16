#![feature(asm)]
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

mod common;
mod delay;
mod elf;
mod rtc;
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

pub extern "win64" fn get_time(time: *mut Time, _: *mut TimeCapabilities) -> Status {
    if time.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let (year, month, day) = match rtc::read_date() {
        Ok((y, m, d)) => (y, m, d),
        Err(()) => return Status::DEVICE_ERROR,
    };
    let (hour, minute, second) = match rtc::read_time() {
        Ok((h, m, s)) => (h, m, s),
        Err(()) => return Status::DEVICE_ERROR,
    };

    unsafe {
        (*time).year = 2000 + year as u16;
        (*time).month = month;
        (*time).day = day;
        (*time).hour = hour;
        (*time).minute = minute;
        (*time).second = second;
        (*time).nanosecond = 0;
        (*time).timezone = 0;
        (*time).daylight = 0;
    }

    Status::SUCCESS
}

pub extern "win64" fn set_time(_: *mut Time) -> Status {
    Status::DEVICE_ERROR
}

pub extern "win64" fn get_wakeup_time(_: *mut Boolean, _: *mut Boolean, _: *mut Time) -> Status {
    Status::UNSUPPORTED
}

pub extern "win64" fn set_wakeup_time(_: Boolean, _: *mut Time) -> Status {
    Status::UNSUPPORTED
}

extern "C" {
    #[link_name = "start"]
    static START: core::ffi::c_void;
    #[link_name = "end"]
    static END: core::ffi::c_void;
}

pub extern "win64" fn set_virtual_address_map(
    map_size: usize,
    descriptor_size: usize,
    version: u32, 
    descriptors: *mut MemoryDescriptor,
) -> Status {
    let count = map_size / descriptor_size;

    if version != efi::MEMORY_DESCRIPTOR_VERSION {
        return Status::INVALID_PARAMETER;
    }

    let descriptors = unsafe {
        core::slice::from_raw_parts_mut(descriptors, count)
    };

    let start = unsafe { &START as *const _ as u64 };
    let end = unsafe { &END as *const _ as u64 };
    let mut bytes = [0_u8; goblin::elf64::header::SIZEOF_EHDR];
    let bin = unsafe { core::slice::from_raw_parts(start as *const u8, goblin::elf64::header::SIZEOF_EHDR) };
    bytes.clone_from_slice(bin);
    let header = goblin::elf64::header::Header::from_bytes(&bytes);

    for descriptor in descriptors.iter() {
        if descriptor.r#type == MemoryType::RuntimeServicesCode as u32 && descriptor.physical_start == start {
            match elf::relocate(header, descriptor.physical_start, descriptor.virtual_start) {
                Ok(_) => (),
                Err(_) => log!("relocation failed"),
            };
        }
    }

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
