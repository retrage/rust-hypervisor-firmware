#![no_std]
#![no_main]
#![feature(sync_unsafe_cell)]

use core::{cell::SyncUnsafeCell, panic::PanicInfo};

use atomic_refcell::AtomicRefCell;
use r_efi::efi::{
    self, Boolean, CapsuleHeader, Char16, Guid, MemoryDescriptor, PhysicalAddress, ResetType,
    Status, Time, TimeCapabilities,
};

#[cfg(target_arch = "x86_64")]
mod cmos;
mod common;
mod delay;
mod rtc;
#[cfg(target_arch = "riscv64")]
mod rtc_goldfish;
#[cfg(target_arch = "aarch64")]
mod rtc_pl031;
mod var;

use crate::var::VariableAllocator;

pub static VARIABLES: AtomicRefCell<VariableAllocator> =
    AtomicRefCell::new(VariableAllocator::new());

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

pub extern "efiapi" fn get_time(time: *mut Time, _tc: *mut TimeCapabilities) -> Status {
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

pub extern "efiapi" fn set_time(_time: *mut Time) -> Status {
    Status::DEVICE_ERROR
}

pub extern "efiapi" fn get_wakeup_time(
    _enabled: *mut Boolean,
    _pending: *mut Boolean,
    _time: *mut Time,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn set_wakeup_time(_enabled: Boolean, _time: *mut Time) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn set_virtual_address_map(
    _map_size: usize,
    _descriptor_size: usize,
    _version: u32,
    _descriptors: *mut MemoryDescriptor,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn convert_pointer(
    _debug_disposition: usize,
    _address: *mut *mut core::ffi::c_void,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn get_variable(
    variable_name: *mut Char16,
    vendor_guid: *mut Guid,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut core::ffi::c_void,
) -> Status {
    VARIABLES
        .borrow_mut()
        .get(variable_name, vendor_guid, attributes, data_size, data)
}

pub extern "efiapi" fn get_next_variable_name(
    _name_size: *mut usize,
    _name: *mut Char16,
    _guid: *mut Guid,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn set_variable(
    variable_name: *mut Char16,
    vendor_guid: *mut Guid,
    attributes: u32,
    data_size: usize,
    data: *mut core::ffi::c_void,
) -> Status {
    VARIABLES
        .borrow_mut()
        .set(variable_name, vendor_guid, attributes, data_size, data)
}

pub extern "efiapi" fn get_next_high_mono_count(_count: *mut u32) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn reset_system(
    _ty: ResetType,
    _status: Status,
    _data_size: usize,
    _reset_data: *mut core::ffi::c_void,
) {
    // stub
}

pub extern "efiapi" fn update_capsule(
    _capsule_header: *mut *mut CapsuleHeader,
    _count: usize,
    _sg_list: PhysicalAddress,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn query_capsule_capabilities(
    _capsule_header: *mut *mut CapsuleHeader,
    _count: usize,
    _max_size: *mut u64,
    _reset_type: *mut ResetType,
) -> Status {
    Status::UNSUPPORTED
}

pub extern "efiapi" fn query_variable_info(
    _attributes: u32,
    _max_storage: *mut u64,
    _remaining: *mut u64,
    _max_size: *mut u64,
) -> Status {
    Status::UNSUPPORTED
}

static mut RS: SyncUnsafeCell<efi::RuntimeServices> = SyncUnsafeCell::new(efi::RuntimeServices {
    hdr: efi::TableHeader {
        signature: efi::RUNTIME_SERVICES_SIGNATURE,
        revision: efi::RUNTIME_SERVICES_REVISION,
        header_size: core::mem::size_of::<efi::RuntimeServices>() as u32,
        crc32: 0,
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
});

#[no_mangle]
pub extern "efiapi" fn efi_get_runtime_services() -> *mut efi::RuntimeServices {
    unsafe { &mut *RS.get() }
}

#[no_mangle]
pub extern "efiapi" fn efi_main() -> efi::Status {
    // This is a placeholder for the main function.
    // In a real EFI application, you would typically initialize your application here.
    efi::Status::SUCCESS
}
