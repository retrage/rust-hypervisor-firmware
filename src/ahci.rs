// SPDX-License-Identifier: BSD-2-Clause-Patent
// Copyright (c) 2019, Intel Corporation. All rights reserved.

use core::cmp;
use core::convert::TryInto;

use crate::{
    delay,
    mem,
    pci,
};

#[derive(Debug)]
pub enum Error {
    NotAvailable,
    Timeout,
    DeviceError,
    Unsupported,
}

#[derive(Default)]
pub struct Hba {
    device: pci::PciDevice,
    reg: mem::MemoryRegion,
    ports: [Port; MAX_PORTS],
}

impl Hba {
    const CAP: u64 = 0x0000;
    const CAP_SAM: u32 = 1 << 18;
    const CAP_SSS: u32 = 1 << 27;

    const GHC: u64 = 0x0004;
    const GHC_RESET: u32 = 1 << 0;
    const GHC_ENABLE: u32 = 1 << 31;

    const IS: u64 = 0x0008;
    const PI: u64 = 0x000c;

    const RESET_TIMEOUT: u64 = 1000; // 1s

    pub fn new(device: pci::PciDevice) -> Self {
        Self {
            device,
            ..Default::default()
        }
    }

    pub fn init(&mut self) -> Result<(), Error> {
        self.device.init();

        let base = self.device.get_bar(5);
        if base == 0xffffffff {
            return Err(Error::NotAvailable);
        }
        self.reg = mem::MemoryRegion::new(base, 0x2c);

        self.reset(Self::RESET_TIMEOUT)?;

        let cap = self.read_reg(Self::CAP);

        if (self.read_reg(Self::GHC) & Self::GHC_ENABLE) == 0 {
            self.or_reg(Self::GHC, Self::GHC_ENABLE);
        }

        let mut max_port_num = ((cap & 0x1f) + 1) as u8;
        let port_impl_bit_map = self.read_reg(Self::PI);

        max_port_num = cmp::min(max_port_num, log2_u32(port_impl_bit_map) + 1);

        let hba = self as *const Hba;
        for idx in 0..=max_port_num {
            let idx = idx as usize;
            if port_impl_bit_map & (1 << idx) == 0 { continue; }
            let port_base = base as u64 + 0x100 + idx as u64 * 0x80;
            self.ports[idx] = Port::new(port_base, hba, idx);
            unsafe {
                let rfis_base: *const RxFIS = &CMD_TABLE.rfis[idx];
                let rfis = Data64::new(rfis_base as u64);
                let clb_base: *const CommandList = &CMD_TABLE.cmd_list;
                let clb = Data64::new(clb_base as u64);
                if self.ports[idx].init(&rfis, &clb).is_err() {
                    continue;
                }
            }
        }

        Ok(())
    }

    fn reset(&mut self, timeout: u64) -> Result<(), Error> {
        if self.read_reg(Self::CAP) & Self::CAP_SAM == 0 {
            self.or_reg(Self::GHC, Self::GHC_ENABLE);
        }
        self.or_reg(Self::GHC, Self::GHC_RESET);
        match delay::wait_until(timeout, ||{
            self.read_reg(Self::GHC) & Self::GHC_RESET == 0
        }) {
            true => Ok(()),
            false => Err(Error::Timeout),
        }
    }

    fn read_reg(&self, offset: u64) -> u32 {
        self.reg.io_read_u32(offset)
    }

    fn write_reg(&self, offset: u64, data: u32) {
        self.reg.io_write_u32(offset, data)
    }

    fn or_reg(&self, offset: u64, data: u32) {
        self.write_reg(offset, self.read_reg(offset) | data);
    }
}

pub struct Data64 {
    lo: u32,
    hi: u32,
}

impl Data64 {
    fn new(data: u64) -> Self {
        Self {
            lo: (data & 0xffffffff) as u32,
            hi: (data >> 32) as u32,
        }
    }
}

pub struct Port {
    reg: mem::MemoryRegion,
    hba: *const Hba,
    idx: usize,
}

impl Default for Port {
    fn default() -> Self {
        Self {
            reg: mem::MemoryRegion::default(),
            hba: core::ptr::null(),
            idx: 0,
        }
    }
}

impl Port {
    const REG_SIZE: u64 = 0x0080;
    const ATA_TIMEOUT: u64 = 3 * 1000; // 3s
    const BUS_PHY_DETECT_TIMEOUT: u64 = 15; // 15ms
    const PHY_READY_DETECT_TIMEOUT: u64 = 16 * 1000; // 16s

    const ATAPI_SIG_MASK: u32 = 0xffff0000;
    const ATA_DEVICE_SIG: u32 = 0x00000000;

    const CLB: u64 = 0x0000;
    const CLBU: u64 = 0x0004;
    const FB: u64 = 0x0008;
    const FBU: u64 = 0x000c;
    const IS: u64 = 0x0010;
    const IE: u64 = 0x0014;

    const CMD: u64 = 0x0018;
    const CMD_ST: u32 = 1 << 0;
    const CMD_SUD: u32 = 1 << 1;
    const CMD_POD: u32 = 1 << 2;
    const CMD_CLO: u32 = 1 << 3;
    const CMD_FRE: u32 = 1 << 4;
    const CMD_FR: u32 = 1 << 14;
    const CMD_CR: u32 = 1 << 15;
    const CMD_CPD: u32 = 1 << 20;
    const CMD_ATAPI: u32 = 1 << 24;
    const CMD_DLAE: u32 = 1 << 25;
    const CMD_ALPE: u32 = 1 << 26;
    const CMD_ACTIVE: u32 = 1 << 28;
    const CMD_ICC_MASK: u32 = (1 << 28) | (1 << 29) | (1 << 30) | (1 << 31);

    const TFD: u64 = 0x0020;
    const TFD_ERR: u32 = 1 << 0;
    const TFD_DRQ: u32 = 1 << 3;
    const TFD_BSY: u32 = 1 << 7;
    const TFD_MASK: u32 = Self::TFD_ERR | Self::TFD_DRQ | Self::TFD_BSY;

    const SIG: u64 = 0x0024;
    const SSTS: u64 = 0x0028;
    const SSTS_DET_MASK: u32 = 0x000f;
    const SSTS_DET: u32 = 0x0001;
    const SSTS_DET_PCE: u32 = 0x0003;

    const SCTL: u64 = 0x002c;
    const SCTL_IPM_INIT: u32 = 0x0300;

    const SERR: u64 = 0x0030;
    const CI: u64 = 0x0038;

    pub fn new(base: u64, hba: *const Hba, idx: usize) -> Port {
        Self {
            reg: mem::MemoryRegion::new(base, Self::REG_SIZE),
            hba,
            idx,
        }
    }

    pub fn init(&mut self, rfis: &Data64, clb: &Data64) -> Result<(), Error> {
        if !self.detect_phy() {
            return Err(Error::NotAvailable);
        }

        let cap = self.get_hba().read_reg(Hba::CAP);

        self.write_reg(Self::FB, rfis.lo);
        self.write_reg(Self::FBU, rfis.hi);

        self.write_reg(Self::CLB, clb.lo);
        self.write_reg(Self::CLBU, clb.hi);

        if self.read_reg(Self::CMD) & Self::CMD_CPD != 0 {
            self.or_reg(Self::CMD, Self::CMD_POD);
        }

        if cap & Hba::CAP_SSS != 0 {
            self.or_reg(Self::CMD, Self::CMD_SUD);
        }

        self.or_reg(Self::SCTL, Self::SCTL_IPM_INIT);

        self.and_reg(Self::IE, 0);

        self.enable_fis_rx();

        match delay::wait_until(Self::BUS_PHY_DETECT_TIMEOUT, ||{
            self.detect_phy()
        }) {
            true => {},
            false => {
                self.and_reg(Self::CMD, !Self::CMD_SUD);
                log!("No device detected");
                return Err(Error::NotAvailable);
            },
        }

        match delay::wait_until(Self::PHY_READY_DETECT_TIMEOUT, ||{
            if self.read_reg(Self::SERR) != 0 {
                self.write_reg(Self::SERR, self.read_reg(Self::SERR));
            }
            (self.read_reg(Self::TFD) & Self::TFD_MASK) == 0
        }) {
            true => {},
            false => {
                log!("Device presence detected but phy not ready");
                return Err(Error::Timeout);
            },
        }

        match delay::wait_until(16 * 1000, ||{
            (self.read_reg(Self::SIG) & 0x0000ffff) == 0x00000101
        }) {
            true => {},
            false => {
                log!("Timeout the first D2H register FIS wait");
                return Err(Error::Timeout);
            },
        }

        self.disable_fis_rx(Self::ATA_TIMEOUT)?;

        if (self.read_reg(Self::SIG) & Self::ATAPI_SIG_MASK) == Self::ATA_DEVICE_SIG {
            self.identify()?;
            log!("Found ATA hard disk");
        } else {
            return Err(Error::NotAvailable);
        }

        Ok(())
    }

    fn get_hba(&self) -> &Hba {
        assert!(self.hba != core::ptr::null());
        unsafe { self.hba.as_ref().unwrap() }
    }

    fn detect_phy(&self) -> bool {
        let data = self.read_reg(Self::SSTS) & Self::SSTS_DET_MASK;
        (data == Self::SSTS_DET_PCE) || (data == Self::SSTS_DET)
    }

    fn clear_status(&self) {
        self.write_reg(Self::SERR, self.read_reg(Self::SERR));
        self.write_reg(Self::IS, self.read_reg(Self::IS));
        self.get_hba().write_reg(Hba::IS, self.get_hba().read_reg(Hba::IS));
    }

    fn enable_fis_rx(&self) {
        self.or_reg(Self::CMD, Self::CMD_FRE);
    }

    fn disable_fis_rx(&self, timeout: u64) -> Result<(), Error> {
        let cmd = self.read_reg(Self::CMD);
        if (cmd & (Self::CMD_ST | Self::CMD_CR)) != 0 {
            return Err(Error::Unsupported);
        }
        if (cmd & Self::CMD_FR) != Self::CMD_FR {
            return Ok(());
        }
        self.and_reg(Self::CMD, !Self::CMD_FRE);

        self.wait_mmio_wait(Self::CMD, Self::CMD_FR, 0, timeout)
    }

    fn start_cmd(&self) -> Result<(), Error> {
        let cap = self.get_hba().read_reg(Hba::CAP);

        self.clear_status();
        //self.enable_fis_rx();

        let mut start_cmd: u32 =  0;
        if self.read_reg(Self::CMD) & Self::CMD_ALPE != 0 {
            start_cmd = self.read_reg(Self::CMD);
            start_cmd &= !Self::CMD_ICC_MASK;
            start_cmd |= Self::CMD_ACTIVE;
        }

        let tfd = self.read_reg(Self::TFD);
        if (tfd & (Self::TFD_BSY | Self::TFD_DRQ)) != 0 {
            if cap & (1 << 24) != 0 {
                self.or_reg(Self::CMD, Self::CMD_CLO);
                self.wait_mmio_wait(Self::CMD, Self::CMD_CLO, 0, Self::ATA_TIMEOUT)?;
            }
        }

        self.wait_mmio_wait(Self::CMD, Self::CMD_CR, 0, Self::ATA_TIMEOUT)?;
        self.or_reg(Self::CMD, Self::CMD_ST | start_cmd);

        let cmd_slot = 0; // XXX: We use cmd slot 0 only
        self.and_reg(Self::CI, 0);
        self.or_reg(Self::CI, 1 << cmd_slot);

        Ok(())
    }

    fn stop_cmd(&self, timeout: u64) -> Result<(), Error> {
        let cmd = self.read_reg(Self::CMD);
        if (cmd & (Self::CMD_ST | Self::CMD_CR)) != 0 {
            return Ok(());
        }
        if (cmd & Self::CMD_ST) != 0 {
            self.and_reg(Self::CMD, !Self::CMD_ST);
        }
        self.wait_mmio_wait(Self::CMD, Self::CMD_CR, 0, timeout)
    }

    fn do_pio(&self, buf: &mut [u8], cmd_fis: &mut CommandFIS, cmd_list: &mut CommandList, is_write: bool, timeout: u64)
        -> Result<(), Error> {
        if !self.detect_phy() {
            return Err(Error::NotAvailable);
        }

        let old_rfis_lo = self.read_reg(Self::FB);
        let old_rfis_hi = self.read_reg(Self::FBU);
        let rfis_base: *const RxFIS = unsafe { &CMD_TABLE.rfis[self.idx] };
        let rfis = Data64::new(rfis_base as u64);
        self.write_reg(Self::FB, rfis.lo);
        self.write_reg(Self::FBU, rfis.hi);

        let old_clb_lo = self.read_reg(Self::CLB);
        let old_clb_hi = self.read_reg(Self::CLBU);
        let clb_base: *const CommandList = unsafe { &CMD_TABLE.cmd_list };
        let clb = Data64::new(clb_base as u64);
        self.write_reg(Self::CLB, clb.lo);
        self.write_reg(Self::CLBU, clb.hi);

        unsafe {
            CMD_TABLE.build_cmd(self.idx, buf, cmd_fis, cmd_list, self);
        }

        self.enable_fis_rx();
        self.start_cmd()?; // TODO: Do exit

        match is_write {
            true => self.wait_write_completion(timeout)?,
            false => self.wait_read_completion(timeout, buf.len())?, // TODO: Do exit
        };

        self.stop_cmd(timeout)?;
        self.disable_fis_rx(timeout)?;

        self.write_reg(Self::FB, old_rfis_lo);
        self.write_reg(Self::FBU, old_rfis_hi);

        self.write_reg(Self::CLB, old_clb_lo);
        self.write_reg(Self::CLBU, old_clb_hi);

        Ok(())
    }

    fn wait_read_completion(&self, timeout: u64, count: usize) -> Result<(), Error> {
        const DELAY_UNIT: u64 = 100;
        let mut delay: i64 = timeout as i64;
        loop {
            let pio_fis = unsafe { CMD_TABLE.rfis[self.idx].check_pio_fis() };
            let d2h_fis = unsafe { CMD_TABLE.rfis[self.idx].check_d2h_fis() };

            if pio_fis || d2h_fis {
                if (self.read_reg(Self::TFD) & Self::TFD_ERR) != 0 {
                    return Err(Error::DeviceError);
                }
                if unsafe { CMD_TABLE.cmd_list.prdbc } == count as u32 {
                    return Ok(());
                }
            }
            unsafe { delay::mdelay(DELAY_UNIT) };
            delay -= DELAY_UNIT as i64;
            if delay <= 0 {
                break;
            }
        }
        Err(Error::Timeout)
    }

    fn wait_write_completion(&self, timeout: u64) -> Result<(), Error> {
        match unsafe { CMD_TABLE.rfis[self.idx].wait_d2h_fis_rx(timeout) } {
            true => {},
            false => return Err(Error::Timeout),
        };
        if (self.read_reg(Self::TFD) & Self::TFD_ERR) != 0 {
            return Err(Error::DeviceError);
        }
        Ok(())
    }

    fn identify(&self) -> Result<(), Error> {
        let mut cmd_fis = CommandFIS([0; CMD_FIS_SIZE]);
        cmd_fis.build_identify();

        let mut cmd_list = CommandList::new();
        cmd_list.set_cfl((CommandFIS::REGISTER_H2D_SIZE / 4) as u8);
        cmd_list.set_w(false);

        let mut id: [u8; 512] = [0; 512];

        self.do_pio(&mut id, &mut cmd_fis, &mut cmd_list, false, Self::ATA_TIMEOUT)
    }

    fn read_reg(&self, offset: u64) -> u32 {
        self.reg.io_read_u32(offset)
    }

    fn write_reg(&self, offset: u64, data: u32) {
        self.reg.io_write_u32(offset, data)
    }

    fn or_reg(&self, offset: u64, data: u32) {
        self.write_reg(offset, self.read_reg(offset) | data);
    }

    fn and_reg(&self, offset: u64, data: u32) {
        self.write_reg(offset, self.read_reg(offset) & data);
    }

    fn wait_mmio_wait(&self, offset: u64, mask: u32, test: u32, timeout: u64) -> Result<(), Error> {
        match delay::wait_until(timeout, ||{
            self.read_reg(offset) & mask == test
        }) {
            true => Ok(()),
            false => Err(Error::Timeout),
        }
    }
}

fn log2_u32(op: u32) -> u8 {
    assert!(op != 0);
    (u32::MAX.count_ones() - op.leading_zeros() - 1) as u8
}

// Command List must be 0x400 aligned
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct CommandList {
    opts: u32,
    prdbc: u32,     // Physical Region Descriptor Byte Count
    ctba: u32,      // Command Table Descriptor Base Address (low)
    ctbau: u32,     // Command Table Descriptor Base Address (high)
    _rsvd: [u32; 4],
}

impl CommandList {
    const fn new() -> Self {
        Self {
            opts: 0,
            prdbc: 0,
            ctba: 0,
            ctbau: 0,
            _rsvd: [0; 4],
        }
    }

    fn set_cfl(&mut self, cfl: u8) {
        assert!(cfl < (1 << 5));
        self.opts |= (cfl as u32) & ((1 << 5) - 1);
    }

    fn set_w(&mut self, w: bool) {
        self.opts |= (w as u32) << 7;
    }

    fn set_prdtl(&mut self, n_prdt: u16) {
        self.opts |= ((n_prdt as u32) << 16) & (((1 << 16) - 1) << 16);
    }
}

// Received FIS must be 0x100 aligned
const RX_FIS_SIZE: usize = 0x100;
#[derive(Debug)]
#[repr(C, packed)]
struct RxFIS([u8; RX_FIS_SIZE]);

impl RxFIS {
    const PIO: usize = 0x20;
    const D2H: usize = 0x40;
    const TYPE_MASK: u32 = 0x00ff;
    const REGISTER_D2H: u32 = 0x0034;
    const PIO_SETUP: u32 = 0x005f;

    fn wait_d2h_fis_rx(&self, timeout: u64) -> bool {
        delay::wait_until(timeout, ||{self.check_d2h_fis()})
    }

    fn check_pio_fis(&self) -> bool {
        self.check_mem_set(Self::PIO, Self::TYPE_MASK, Self::PIO_SETUP)
    }

    fn check_d2h_fis(&self) -> bool {
        self.check_mem_set(Self::D2H, Self::TYPE_MASK, Self::REGISTER_D2H)
    }

    fn check_mem_set(&self, offset: usize, mask: u32, test: u32) -> bool {
        (self.read_u32(offset) & mask) == test
    }

    fn read_u32(&self, offset: usize) -> u32 {
        assert!(offset < self.0.len() - 4);
        u32::from_le_bytes(self.0[offset..offset + 4].try_into().unwrap())
    }
}

// Command Table Descriptor must be 0x80 aligned
const CMD_FIS_SIZE: usize = 0x80;
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct CommandFIS([u8; CMD_FIS_SIZE]);

impl CommandFIS {
    const REGISTER_H2D: u8 = 0x27;
    const REGISTER_H2D_SIZE: usize = 20;

    const TYPE: usize = 0x00;
    const CMD_IND: usize = 0x01;
    const CMD: usize = 0x02;
    const DEV_HEAD: usize = 0x07;
    const SEC_COUNT: usize = 0x0c;

    fn build_identify(&mut self) {
        unsafe { self.0 = core::mem::zeroed() };
        self.0[Self::TYPE] = Self::REGISTER_H2D;
        self.0[Self::CMD_IND] = 1 << 7;
        self.0[Self::CMD] = 0xec;
        self.0[Self::SEC_COUNT] = 1;
        self.0[Self::DEV_HEAD] = 0xe0;
    }
}

#[derive(Debug)]
#[repr(C, packed)]
struct ATAPICommand([u8; 0x10]);

// PRDT Base Address must be word aligned

// Physical Region Descriptor Table
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct CommandPRDT {
    dba: u32,   // Data Base Address (low)
    dbau: u32,  // Data Base Address (high)
    _rsvd: u32,
    flags: u32, // [21:0]: Data Byte Count, [31]: Interrupt on Completion
}

impl CommandPRDT {
    const MAX_DATA: usize = 0x400000;
    const fn new() -> Self {
        Self {
            dba: 0,
            dbau: 0,
            _rsvd: 0,
            flags: 0,
        }
    }
    fn set_dbc(&mut self, val: u32) {
        self.flags |= (val - 1) & 0x3fffff;
    }
    fn set_ioc(&mut self, val: bool) {
        self.flags |= (val as u32) << 31;
    }
}

const MAX_PORTS: usize = 32;
const MAX_PRDT: usize = 8;

#[derive(Debug)]
#[repr(C, packed)]
struct CommandTable {
    cmd_list: CommandList,
    _rsvd: [u8; 0x1000 - 0x20],
    rfis: [RxFIS; MAX_PORTS],
    cmd_fis: CommandFIS,
    atapi_cmd: ATAPICommand,
    _rsvd1: [u8; 0x30],
    cmd_prdt: [CommandPRDT; MAX_PRDT],
}

impl CommandTable {
    const fn new() -> Self {
        Self {
            cmd_list: CommandList::new(),
            _rsvd: [0; 0x1000 - 0x20],
            rfis: [RxFIS([0; RX_FIS_SIZE]); MAX_PORTS],
            cmd_fis: CommandFIS([0; CMD_FIS_SIZE]),
            atapi_cmd: ATAPICommand([0; 0x10]),
            _rsvd1: [0; 0x30],
            cmd_prdt: [CommandPRDT::new(); MAX_PRDT],
        }
    }

    fn clear_rfis(&mut self, idx: usize) {
        unsafe { self.rfis[idx] = core::mem::zeroed() };
    }

    fn clear_cmd_fis(&mut self) {
        unsafe { self.cmd_fis = core::mem::zeroed() };
    }

    fn clear_prdt(&mut self) {
        for i in 0..MAX_PRDT {
            unsafe { self.cmd_prdt[i] = core::mem::zeroed()} ;
        }
    }

    fn build_cmd(&mut self, idx: usize, buf: &mut [u8],
                 cmd_fis: &mut CommandFIS, cmd_list: &mut CommandList, port: &Port) {
        let n_prdt = ((buf.len() - 1) / CommandPRDT::MAX_DATA) + 1;
        assert!(n_prdt <= MAX_PRDT);

        self.clear_rfis(idx);
        self.clear_cmd_fis();
        self.clear_prdt();

        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        self.cmd_fis = *cmd_fis;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

        // TODO: Set CFISPmNum
        port.and_reg(Port::CMD, !(Port::CMD_DLAE | Port::CMD_ATAPI));

        let mut remain = buf.len();
        for i in 0..n_prdt {
            let bytes = core::cmp::min(remain, CommandPRDT::MAX_DATA);
            self.cmd_prdt[idx].set_dbc(bytes as u32);

            let buf_ptr = &buf[i * CommandPRDT::MAX_DATA] as *const u8;
            let buf_addr = Data64::new(buf_ptr as u64);
            self.cmd_prdt[i].dba = buf_addr.lo;
            self.cmd_prdt[i].dbau = buf_addr.hi;

            if remain >= CommandPRDT::MAX_DATA {
                remain -= CommandPRDT::MAX_DATA;
            }
        }

        if n_prdt > 0 {
            self.cmd_prdt[n_prdt - 1].set_ioc(true);
        }

        //self.cmd_list.prdbc = n_prdt as u32;
        cmd_list.set_prdtl(n_prdt as u16);
        let cmd_fis_ptr = &self.cmd_fis as *const CommandFIS;
        let cmd_fis_addr = Data64::new(cmd_fis_ptr as u64);
        cmd_list.ctba = cmd_fis_addr.lo;
        cmd_list.ctbau = cmd_fis_addr.hi;

        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        self.cmd_list = *cmd_list;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

        // TODO: Pmp
    }
}

static mut CMD_TABLE: CommandTable = CommandTable::new();
