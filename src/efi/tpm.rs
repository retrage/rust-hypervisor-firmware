
use crate::tpm;

use core::mem::size_of;
use core::slice::from_raw_parts;
use core::slice::from_raw_parts_mut;

use r_efi::{
  efi::{Boolean, Guid, PhysicalAddress, Status},
};

pub const PROTOCOL_GUID: Guid = Guid::from_fields(
  0x607f766c,
  0x7455,
  0x42be,
  0x93,
  0x0b,
  &[0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f],
);

#[derive(Clone, Copy)]
#[repr(C)]
struct Version {
  major: u8,
  minor: u8,
}

pub const EVENT_LOG_TCG_1_2: u32 = 0x00000001;
pub const EVENT_LOG_TCG_2: u32 = 0x00000002;

type EventLogBitmap = u32;
type EventAlgorithmBitmap = u32;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct BootServiceCapability {
  size: u8,
  structure_version: Version,
  protocol_version: Version,
  hash_algorithm_bitmap: EventAlgorithmBitmap,
  supported_event_logs: EventLogBitmap,
  tpm_present_flag: Boolean,
  max_command_size: u16,
  max_response_size: u16,
  manufacturer_id: u32,
  number_of_pcr_banks: u32,
  active_pcr_banks: EventAlgorithmBitmap,
}

#[repr(u32)]
pub enum EventLogFormat {
  Tcg12 = 1,
  Tcg2 = 2,
}

type TcgPcrIndex = u32;
type TcgEventType = u32;

#[repr(C)]
struct EventHeader {
  header_size: u32,
  header_version: u16,
  pcr_index: TcgPcrIndex,
  event_type: TcgEventType,
}

#[repr(C)]
pub struct Event {
  size: u32,
  header: EventHeader,
  event: [u8; 0],
}

pub extern "win64" fn get_capability(this: *mut Protocol, protocol_capability: *mut BootServiceCapability) -> Status {
  if this.is_null() || protocol_capability.is_null() {
    return Status::INVALID_PARAMETER;
  }

  let wrapper = unsafe { &*container_of!(this, Wrapper, proto) };

  let mut protocol_capability = unsafe { &mut *protocol_capability };
  if (protocol_capability.size as usize) < size_of::<BootServiceCapability>() {
    protocol_capability.size = size_of::<BootServiceCapability>() as u8;
    return Status::BUFFER_TOO_SMALL;
  }

  protocol_capability.clone_from(&wrapper.cap);

  Status::SUCCESS
}

pub extern "win64" fn get_event_log(this: *mut Protocol, event_log_format: EventLogFormat, event_log_location: *mut PhysicalAddress, event_log_last_entry: *mut PhysicalAddress, event_log_truncated: *mut Boolean) -> Status {
  if this.is_null() {
    return Status::INVALID_PARAMETER;
  }

  let wrapper = unsafe { &*container_of!(this, Wrapper, proto) };
  if wrapper.cap.tpm_present_flag != Boolean::TRUE {
    return Status::DEVICE_ERROR;
  }

  if event_log_format as u32 & EventLogFormat::Tcg2 as u32 == 0 {
    // FIXME: TCG2 event log format only
    return Status::INVALID_PARAMETER;
  }

  if wrapper.cap.tpm_present_flag != Boolean::TRUE {
    if !event_log_location.is_null() {
      unsafe { *event_log_location = 0; }
    }
    if !event_log_last_entry.is_null() {
      unsafe { *event_log_last_entry = 0; }
    }
    if !event_log_truncated.is_null() {
      unsafe { *event_log_truncated = Boolean::FALSE; }
    }
    return Status::SUCCESS;
  }

  if !event_log_location.is_null() {
    unsafe { *event_log_location = wrapper.tis.lasa; }
  }

  if !event_log_last_entry.is_null() {
    // TODO: Check if event log started
    unsafe { *event_log_last_entry = 0; }
  }

  if !event_log_truncated.is_null() {
    if wrapper.tis.event_log_truncated {
      unsafe { *event_log_truncated = Boolean::TRUE; }
    } else {
      unsafe { *event_log_truncated = Boolean::FALSE; }
    }
  }

  Status::SUCCESS
}

pub extern "win64" fn hash_log_extend_event(this: *mut Protocol, flags: u64, data_to_hash: PhysicalAddress, data_to_hash_len: u64, efi_tcg_event: *mut Event) -> Status {
  dbg!();

  if this.is_null() || efi_tcg_event.is_null() {
    return Status::INVALID_PARAMETER;
  }

  // TODO: Check event_type != EV_NO_ACTION && data_to_hash_len == 0

  let wrapper = unsafe { &*container_of_mut!(this, Wrapper, proto) };
  if wrapper.cap.tpm_present_flag != Boolean::TRUE {
    return Status::DEVICE_ERROR;
  }

  Status::SUCCESS
}

pub extern "win64" fn submit_command(this: *mut Protocol, input_parameter_block_size: u32, input_parameter_block: *mut u8, output_parameter_block_size: u32, output_parameter_block: *mut u8) -> Status {
  if this.is_null() || input_parameter_block_size == 0 || input_parameter_block.is_null() || output_parameter_block_size == 0 || output_parameter_block.is_null() {
    return Status::INVALID_PARAMETER;
  }

  let wrapper = unsafe { &mut *container_of_mut!(this, Wrapper, proto) };
  if wrapper.cap.tpm_present_flag != Boolean::TRUE {
    return Status::DEVICE_ERROR;
  }

  if input_parameter_block_size > wrapper.cap.max_command_size as u32 {
    return Status::INVALID_PARAMETER;
  }

  if output_parameter_block_size > wrapper.cap.max_response_size as u32 {
    return Status::INVALID_PARAMETER;
  }

  let buf_in = unsafe { from_raw_parts(input_parameter_block as *const u8, input_parameter_block_size as usize) };
  let buf_out = unsafe { from_raw_parts_mut(output_parameter_block, output_parameter_block_size as usize) };

  if wrapper.tis.send_command(buf_in, buf_out).is_err() {
    return Status::DEVICE_ERROR;
  }

  Status::SUCCESS
}

pub extern "win64" fn get_active_pcr_banks(this: *mut Protocol, active_pcr_banks: *mut u32) -> Status {
  log!("{}:{}", file!(), line!());
  Status::UNSUPPORTED
}

pub extern "win64" fn set_active_pcr_banks(this: *mut Protocol, active_pcr_banks: u32) -> Status {
  log!("{}:{}", file!(), line!());
  Status::UNSUPPORTED
}

pub extern "win64" fn get_result_of_set_active_pcr_banks(this: *mut Protocol, operation_present: *mut u32, response: *mut u32) -> Status {
  log!("{}:{}", file!(), line!());
  Status::UNSUPPORTED
}

#[repr(C)]
pub struct Protocol {
  pub get_capability: extern "win64" fn (
    this: *mut Protocol,
    protocol_capability: *mut BootServiceCapability,
  ) -> Status,
  pub get_event_log: extern "win64" fn (
    this: *mut Protocol,
    event_log_format: EventLogFormat,
    event_log_location: *mut PhysicalAddress,
    event_log_last_entry: *mut PhysicalAddress,
    event_log_truncated: *mut Boolean,
  ) -> Status,
  pub hash_log_extend_event: extern "win64" fn (
    this: *mut Protocol,
    flags: u64,
    data_to_hash: PhysicalAddress,
    data_to_hash_len: u64,
    efi_tcg_event: *mut Event,
  ) -> Status,
  pub submit_command: extern "win64" fn (
    this: *mut Protocol,
    input_parameter_block_size: u32,
    input_parameter_block: *mut u8,
    output_parameter_block_size: u32,
    output_parameter_block: *mut u8,
  ) -> Status,
  pub get_active_pcr_banks: extern "win64" fn (
    this: *mut Protocol,
    active_pcr_banks: *mut u32,
  ) -> Status,
  pub set_active_pcr_banks: extern "win64" fn (
    this: *mut Protocol,
    active_pcr_banks: u32,
  ) -> Status,
  pub get_result_of_set_active_pcr_banks: extern "win64" fn (
    this: *mut Protocol,
    operation_present: *mut u32,
    response: *mut u32,
  ) -> Status,
}

#[repr(C)]
pub struct Wrapper {
  hw: super::HandleWrapper,
  pub proto: Protocol,
  cap: BootServiceCapability,
  tis: tpm::Tis,
}

impl Wrapper {
  pub const fn new() -> Self {
    Self {
      hw: super::HandleWrapper {
        handle_type: super::HandleType::Tpm,
      },
      proto: Protocol {
        get_capability,
        get_event_log,
        hash_log_extend_event,
        submit_command,
        get_active_pcr_banks,
        set_active_pcr_banks,
        get_result_of_set_active_pcr_banks,
      },
      cap: BootServiceCapability {
        size: size_of::<BootServiceCapability>() as u8,
        structure_version: Version { major: 1, minor: 1 },
        protocol_version: Version { major: 1, minor: 1 },
        hash_algorithm_bitmap: 0, // TODO
        supported_event_logs: EVENT_LOG_TCG_2, // TODO
        tpm_present_flag: Boolean::FALSE,
        max_command_size: 0x1000, // TODO
        max_response_size: 0x1000, // TODO
        manufacturer_id: 0, // TODO
        number_of_pcr_banks: 0, // TODO
        active_pcr_banks: 0, // TODO
      },
      tis: tpm::Tis::new(tpm::LOCALITY0_ADDR as u64),
    }
  }
  pub fn init(&mut self, lasa: u64) -> Result<(), ()> {
    self.tis.lasa = lasa;
    self.tis.request_use_tpm()?;
    self.cap.tpm_present_flag = Boolean::TRUE;
    // TODO: Fill other cap fields
    Ok(())
  }
}

pub struct Wrappers {
    pub wrappers: [*const Wrapper; 1],
    pub count: usize,
}