
use core::mem::size_of;
use core::slice::from_raw_parts;

type TpmSt = u16;
type TpmRc = u32;
type TpmCc = u32;
type TpmCap = u32;

#[derive(Default)]
#[repr(C, packed)]
struct CommandHeader {
  tag: TpmSt,
  param_size: u32,
  command_code: TpmCc,
}

#[derive(Copy, Clone, Default)]
#[repr(C, packed)]
struct ResponseHeader {
  tag: TpmSt,
  param_size: u32,
  response_code: TpmRc,
}

pub const LOCALITY0_ADDR: usize = 0xfed4_0000;
pub const LOCALITY1_ADDR: usize = 0xfed4_1000;
pub const LOCALITY2_ADDR: usize = 0xfed4_2000;
pub const LOCALITY3_ADDR: usize = 0xfed4_3000;
pub const LOCALITY4_ADDR: usize = 0xfed4_4000;

use crate::mem;
use crate::delay;

pub struct Tis {
  regs: mem::MemoryRegion,
  pub lasa: u64, // Log Area Start Address
  pub event_log_truncated: bool,
}

impl Tis {
  const REG_SIZE: u64 = 0x1000;
  const ACCESS: u64 = 0x00;
  const ACC_RQUUSE: u8 = 1 << 1;
  const ACC_ACTIVE: u8 = 1 << 5;
  const VALID: u8 = 1 << 7;
  const STATUS: u64 = 0x18;
  const STS_EXPECT: u8 = 1 << 3;
  const STS_DATA: u8 = 1 << 4;
  const STS_GO: u8 = 1 << 5;
  const STS_READY: u8 = 1 << 6;
  const STS_VALID: u8 = 1 << 7;
  const STS_CANCEL: u32 = 1 << 24;
  const BURST_COUNT: u64 = 0x19;
  const DATA_FIFO: u64 = 0x24;
  const TIMEOUT_A: u64 = 750;
  const TIMEOUT_B: u64 = 2000;
  const TIMEOUT_C: u64 = 750;
  const TIMEOUT_D: u64 = 750;
  const TIMEOUT_MAX: u64 = 9000;
  pub const fn new(regs_base: u64) -> Self {
    Self {
      regs: mem::MemoryRegion::new(regs_base, Self::REG_SIZE),
      lasa: 0,
      event_log_truncated: false,
    }
  }
  fn prepare_command(&mut self) -> bool {
    self.regs.io_write_u8(Self::STATUS, Self::STS_READY);
    delay::wait_until(Self::TIMEOUT_B, || -> bool {
      self.regs.io_read_u8(Self::STATUS) & Self::STS_READY == Self::STS_READY
    })
  }
  fn read_burst_count(&mut self) -> Result<u16, ()> {
    if delay::wait_until(Self::TIMEOUT_D, || -> bool {
      let lower = self.regs.io_read_u8(Self::BURST_COUNT);
      let upper = self.regs.io_read_u8(Self::BURST_COUNT + 1);
      ((upper as u16) << 8) | (lower as u16) != 0
    }) == false {
      Err(())
    } else {
      let lower = self.regs.io_read_u8(Self::BURST_COUNT);
      let upper = self.regs.io_read_u8(Self::BURST_COUNT + 1);
      Ok(((upper as u16) << 8) | (lower as u16))
    }
  }
  pub fn send_command(&mut self, buf_in: &[u8], buf_out: &mut[u8]) -> Result<(), ()> {
    if self.prepare_command() == false {
      return Err(());
    }
    let mut index: usize = 0;
    while index < buf_in.len() {
      let mut burst_count = self.read_burst_count()?;
      while burst_count > 0 && index < buf_in.len() {
        dbg!(burst_count, index, buf_in[index]);
        self.regs.io_write_u8(Self::DATA_FIFO, buf_in[index]);
        index += 1;
        burst_count -= 1;
      }
    }
    if delay::wait_until(Self::TIMEOUT_C, || -> bool {
      let status = self.regs.io_read_u8(Self::STATUS);
      dbg!(status);
      (status & Self::STS_VALID) == Self::STS_VALID && (status & Self::STS_EXPECT) == 0
    }) == false {
      return Err(());
    }
    self.regs.io_write_u8(Self::STATUS, Self::STS_GO);
    if delay::wait_until(Self::TIMEOUT_MAX, || -> bool {
      let status = self.regs.io_read_u8(Self::STATUS);
      (status & (Self::STS_VALID | Self::STS_DATA)) == Self::STS_VALID | Self::STS_DATA
    }) == false {
      log!("Wait for TPM TIS response data timeout");
      self.regs.io_write_u32(Self::STATUS, Self::STS_CANCEL);
      if delay::wait_until(Self::TIMEOUT_B, || -> bool {
        let status = self.regs.io_read_u8(Self::STATUS);
        dbg!(status);
        (status & (Self::STS_VALID | Self::STS_DATA)) == Self::STS_VALID | Self::STS_DATA
      }) == false {
        return Err(());
      }
    }
    let mut index = 0;
    while index < size_of::<ResponseHeader>() {
      let mut burst_count = self.read_burst_count()?;
      while burst_count > 0 && index < size_of::<ResponseHeader>() {
        buf_out[index] = self.regs.io_read_u8(Self::DATA_FIFO);
        dbg!(buf_out[index]);
        index += 1;
        burst_count -= 1;
      }
    }
    let res_tag = unsafe { (&buf_out[0] as *const _ as *const u16).as_ref().unwrap().swap_bytes() };
    let out_size = unsafe { (&buf_out[2] as *const _ as *const u32).as_ref().unwrap().swap_bytes() };
    log!("response tag: {:#x}", res_tag);
    log!("out_size: {:#x}", out_size);
    while index < out_size as usize {
      let mut burst_count = self.read_burst_count()?;
      while burst_count > 0 && index < out_size as usize {
        buf_out[index] = self.regs.io_read_u8(Self::DATA_FIFO);
        dbg!(buf_out[index]);
        index += 1;
        burst_count -= 1;
      }
    }
    Ok(())
  }
  fn presence_check(&mut self) -> bool {
    self.regs.io_read_u8(Self::ACCESS) != u8::MAX
  }
  pub fn request_use_tpm(&mut self) -> Result<(), ()> {
    if self.presence_check() != true {
        return Err(());
    }
    self.regs.io_write_u8(Self::ACCESS, Self::ACC_RQUUSE);
    if delay::wait_until(Self::TIMEOUT_A, || -> bool {
        let access = self.regs.io_read_u8(Self::ACCESS);
        (access & (Self::ACC_ACTIVE | Self::VALID)) == Self::ACC_ACTIVE | Self::VALID
    }) == false {
        return Err(());
    }
    Ok(())
  }
}

#[repr(C, packed)]
struct GetCapabilityCommand {
  header: CommandHeader,
  capability: TpmCap,
  property: u32,
  property_count: u32,
}

type YesNo = u8;

type TpmPt = u32;

const MAX_CAP_BUFFER: usize = 1024;
const MAX_CAP_DATA: usize = MAX_CAP_BUFFER - size_of::<TpmCap>() - size_of::<u32>();
const MAX_TPM_PROPERTIES: usize = MAX_CAP_DATA / size_of::<TpmsTaggedProperty>();

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct TpmsTaggedProperty {
  property: TpmPt,
  value: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct TpmlTaggedTpmProperty {
  count: u32,
  tpm_property: [TpmsTaggedProperty; MAX_TPM_PROPERTIES],
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
union TpmuCapabilities {
  tpm_properties: TpmlTaggedTpmProperty,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct TpmuCapabilityData {
  capability: TpmCap,
  data: TpmuCapabilities,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct GetCapabilityResponse {
  header: ResponseHeader,
  more_data: YesNo,
  capability_data: TpmuCapabilityData,
}

pub fn get_capability(tis: &mut Tis, capability: TpmCap, property: u32, property_count: u32) -> Result<u32, ()> {
  const TPM_ST_NO_SESSIONS: u16 = 0x8001;
  const TPM_CC_GET_CAPABILITY: u32 = 0x0000017A;
  let send_buf = GetCapabilityCommand {
    header: CommandHeader {
      tag: TPM_ST_NO_SESSIONS.swap_bytes(),
      param_size: (size_of::<GetCapabilityCommand>() as u32).swap_bytes(),
      command_code: TPM_CC_GET_CAPABILITY.swap_bytes(),
    },
    capability: capability.swap_bytes(),
    property: property.swap_bytes(),
    property_count: property_count.swap_bytes(),
  };
  let send_buf = unsafe { from_raw_parts(&send_buf as *const _ as *const u8, size_of::<GetCapabilityCommand>()) };
  let mut recv_buf = [0_u8; size_of::<GetCapabilityResponse>()];
  tis.send_command(send_buf, &mut recv_buf)?;
  let recv_buf = unsafe { (&recv_buf as *const _ as *const GetCapabilityResponse).as_ref().unwrap() };
  Ok(unsafe { recv_buf.capability_data.data.tpm_properties.tpm_property[0].value })
}

#[allow(dead_code)]
pub fn get_capability_manufacture_id(tis: &mut Tis) -> Result<u32, ()> {
  const TPM_CAP_TPM_PROPERTIES: u32 = 0x00000006;
  const TPM_PT_MANUFACTURER: u32 = 0x00000100 * 1 + 5;
  get_capability(tis, TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 1)
}