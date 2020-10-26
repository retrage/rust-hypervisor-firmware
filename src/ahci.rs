// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2020 Akira Moroo
// Copyright (C) 2006 Freescale Semiconductor, Inc

use crate::block::{Error as BlockError, SectorCapacity, SectorRead, SectorWrite};
use crate::{
    delay,
    mem,
};

const ATA_CMD_READ_SECTORS_EXT: u8 = 0x24;
const ATA_CMD_WRITE_SECTORS_EXT: u8 = 0x34;
const ATA_CMD_FLUSH_CACHE_EXT: u8 = 0xea;
const ATA_CMD_IDENTIFY_DEVICE: u8 = 0xec;

const AHCI_MAX_SG: usize = 56;

const PORT_LST_ADDR: u64 = 0x00;
const PORT_LST_ADDR_HI: u64 = 0x04;
const PORT_FIS_ADDR: u64 = 0x08;
const PORT_FIS_ADDR_HI: u64 = 0x0c;
const PORT_IRQ_STAT: u64 = 0x10;
const PORT_IRQ_MASK: u64 = 0x14;
const PORT_CMD: u64 = 0x18;
const PORT_TFDATA: u64 = 0x20;
const PORT_SCR_STAT: u64 = 0x28;
const PORT_SCR_ERR: u64 = 0x30;
const PORT_CMD_ISSUE: u64 = 0x38;

const PORT_CMD_LIST_ON: u32 = 1 << 15;
const PORT_CMD_FIS_ON: u32 = 1 << 14;
const PORT_CMD_FIS_RX: u32 = 1 << 4;
const PORT_CMD_POWER_ON: u32 = 1 << 2;
const PORT_CMD_SPIN_UP: u32 = 1 << 1;
const PORT_CMD_START: u32 = 1 << 0;

const PORT_CMD_ICC_ACTIVE: u32 = 0x01 << 28;

const ATA_STAT_BUSY: u32 = 0x80;
const ATA_STAT_DRQ: u32 = 0x08;

const ATA_MAJOR_ATA8: u16 = 1 << 8;

const PORT_IRQ_TF_ERR: u32 = 1 << 30;
const PORT_IRQ_HBUS_ERR: u32 = 1 << 29;
const PORT_IRQ_HBUS_DATA_ERR: u32 = 1 << 28;
const PORT_IRQ_IF_ERR: u32 = 1 << 27;

const PORT_IRQ_PHYRDY: u32 = 1 << 22;
const PORT_IRQ_CONNECT: u32 = 1 << 6;
const PORT_IRQ_SG_DONE: u32 = 1 << 5;
const PORT_IRQ_UNK_FIS: u32 = 1 << 4;
const PORT_IRQ_SDB_FIS: u32 = 1 << 3;
const PORT_IRQ_DMAS_FIS: u32 = 1 << 2;
const PORT_IRQ_PIOS_FIS: u32 = 1 << 1;
const PORT_IRQ_D2H_REG_FIS: u32 = 1 << 0;

const PORT_IRQ_FATAL: u32 = PORT_IRQ_TF_ERR | PORT_IRQ_HBUS_ERR
                            | PORT_IRQ_HBUS_DATA_ERR | PORT_IRQ_IF_ERR;
const DEF_PORT_IRQ: u32 = PORT_IRQ_FATAL | PORT_IRQ_PHYRDY
                          | PORT_IRQ_CONNECT | PORT_IRQ_SG_DONE
                          | PORT_IRQ_UNK_FIS | PORT_IRQ_SDB_FIS
                          | PORT_IRQ_DMAS_FIS | PORT_IRQ_PIOS_FIS
                          | PORT_IRQ_D2H_REG_FIS;

#[link_section = ".ahci.dma"]
static mut AHCI_PORT_DMA: AhciPortDma = AhciPortDma::new();

#[derive(Debug)]
pub enum Error {
    NotAvailable,
    NoLink,
    Timeout,
    TooMuchSg,
    IdentifyIntegrityFail,
}

#[derive(Default)]
struct AhciCommandHeader {
    opts: u32,
    status: u32,
    tbl_addr: u32,
    tbl_addr_hi: u32,
    _reserved: [u32; 4],
}

#[repr(packed)]
#[derive(Copy,Clone,Default)]
struct AhciSg {
    addr: u32,
    _addr_hi: u32,
    _reserved: u32,
    flags_size: u32,
}

#[repr(packed)]
struct AhciPortDma {
    cmd_slot: AhciCommandHeader,
    _reserved: [u8; 224], // Received-FIS is at 0x100 align.
    rx_fis: [u8; 0x100],
    cmd_tbl: [u8; 0x80],
    cmd_tbl_sg: [AhciSg; AHCI_MAX_SG],
}

impl AhciPortDma {
    const fn new() -> Self {
        Self {
            cmd_slot: AhciCommandHeader { opts: 0, status: 0, tbl_addr: 0, tbl_addr_hi: 0, _reserved: [0; 4] },
            _reserved: [0; 224],
            rx_fis: [0; 0x100],
            cmd_tbl: [0; 0x80],
            cmd_tbl_sg: [ AhciSg { addr: 0, _addr_hi: 0, _reserved: 0, flags_size: 0 }; AHCI_MAX_SG ],
        }
    }
}

#[derive(Default)]
pub struct AhciIoPort {
    port: mem::MemoryRegion,
    index: usize,
    link: bool,
}

impl AhciIoPort {
    pub fn new(base: u64, length: u64, index: usize) -> AhciIoPort {
        AhciIoPort {
            port: mem::MemoryRegion::new(base, length),
            index,
            link: false,
        }
    }
    pub fn init(&mut self) -> Result<(), Error> {
        let status = self.port.io_read_u32(PORT_SCR_STAT);
        if (status & 0x0f) != 0x03 {
            return Err(Error::NoLink);
        }
        let mut port_cmd = self.port.io_read_u32(PORT_CMD);
        let port_cmd_bits =
            PORT_CMD_LIST_ON | PORT_CMD_FIS_ON |
            PORT_CMD_FIS_RX | PORT_CMD_START;
        if port_cmd & port_cmd_bits != 0 {
            log!("Port {} is active. Deactivating.", self.index);
            port_cmd &= !port_cmd_bits;
            self.port.io_write_u32(PORT_CMD, port_cmd);
            self.port.io_read_u32(PORT_CMD);
            unsafe { delay::mdelay(500); }
        }
        port_cmd = PORT_CMD_SPIN_UP | PORT_CMD_FIS_RX;
        self.port.io_write_u32(PORT_CMD, port_cmd);
        if delay::wait_while(4, || {
            let ssts = self.port.io_read_u32(PORT_SCR_STAT);
            ssts & 0x0f != 0x03
        }) {
            return Err(Error::Timeout);
        }
        let scr_err = self.port.io_read_u32(PORT_SCR_ERR);
        if scr_err != 0 {
            self.port.io_write_u32(PORT_SCR_ERR, scr_err);
        }
        if delay::wait_while(10000, || {
            let tf_data = self.port.io_read_u32(PORT_TFDATA);
            tf_data & (ATA_STAT_BUSY | ATA_STAT_DRQ) != 0
        }) {
            return Err(Error::Timeout);
        }
        let scr_err = self.port.io_read_u32(PORT_SCR_ERR);
        if scr_err != 0 {
            self.port.io_write_u32(PORT_SCR_ERR, scr_err);
        }
        let irq_stat = self.port.io_read_u32(PORT_IRQ_STAT);
        if irq_stat != 0 {
            self.port.io_write_u32(PORT_IRQ_STAT, irq_stat);
        }
        self.port.io_write_u32(PORT_IRQ_MASK, DEF_PORT_IRQ);
        let status = self.port.io_read_u32(PORT_SCR_STAT);
        if (status & 0x0f) != 0x03 {
            return Err(Error::NoLink);
        }
        self.link = true;
        Ok(())
    }
    pub fn start(&self) -> Result<(), Error> {
        let status = self.port.io_read_u32(PORT_SCR_STAT);
        if (status & 0x0f) != 0x03 {
            return Err(Error::NoLink);
        }
        unsafe {
            let cmd_slot: *const AhciCommandHeader = &AHCI_PORT_DMA.cmd_slot;
            self.port.io_write_u32(PORT_LST_ADDR, cmd_slot as u32);
            self.port.io_write_u32(PORT_LST_ADDR_HI, 0);
            let rx_fis: *const [u8; 0x100] = &AHCI_PORT_DMA.rx_fis;
            self.port.io_write_u32(PORT_FIS_ADDR, rx_fis as u32);
            self.port.io_write_u32(PORT_FIS_ADDR_HI, 0);
        }
        self.port.io_write_u32(PORT_CMD,
                               PORT_CMD_ICC_ACTIVE | PORT_CMD_FIS_RX |
                               PORT_CMD_POWER_ON | PORT_CMD_SPIN_UP |
                               PORT_CMD_START);
        Ok(())
    }
    pub fn is_link(&self) -> bool {
        self.link
    }
    fn fill_sg(&self, buf: &mut [u8]) -> Result<usize, Error> {
        const MAX_DATA_BYTE_COUNT: usize = 4 * 1024 * 1024;
        let buf_size = core::mem::size_of::<u8>() * buf.len();
        let sg_count = ((buf_size - 1) / MAX_DATA_BYTE_COUNT) + 1;
        if sg_count > AHCI_MAX_SG {
            return Err(Error::TooMuchSg);
        }
        let mut len = buf.len();
        for i in 0..sg_count {
            let addr = &buf[i * MAX_DATA_BYTE_COUNT] as *const u8;
            let bytes = core::cmp::min(len, MAX_DATA_BYTE_COUNT) as u32;
            if len >= MAX_DATA_BYTE_COUNT {
                len -= MAX_DATA_BYTE_COUNT;
            }
            unsafe {
                AHCI_PORT_DMA.cmd_tbl_sg[i].addr = addr as u32;
                AHCI_PORT_DMA.cmd_tbl_sg[i].flags_size = (bytes - 1) & 0x3fffff;
            }
        }
        Ok(sg_count)
    }
    unsafe fn fill_cmd_slot(&self, opts: u32) {
        let addr = &AHCI_PORT_DMA.cmd_tbl as *const u8;
        AHCI_PORT_DMA.cmd_slot.opts = opts;
        AHCI_PORT_DMA.cmd_slot.status = 0;
        AHCI_PORT_DMA.cmd_slot.tbl_addr = addr as u32;
        AHCI_PORT_DMA.cmd_slot.tbl_addr_hi = 0;
    }
    fn identify_integrity(&self, id: &[u8]) -> Result<(), Error> {
        assert_eq!(512, id.len());
        let major: u16 = (id[160] as u16) | ((id[161] as u16) << 8);
        if major != 0xffff && (major & ATA_MAJOR_ATA8) != 0 {
            return Ok(());
        }
        let integrity: u16 = (id[510] as u16) | ((id[511] as u16) << 8);
        if integrity & 0xff != 0xa5 {
            return Ok(());
        }
        let mut sum: u8 = 0;
        for byte in id {
            sum += byte;
        }
        if sum == 0 {
            return Ok(());
        }
        Err(Error::IdentifyIntegrityFail)
    }
    fn device_data_io(&self, fis: &[u8], buf: &mut [u8], is_write: bool)
        -> Result<(), Error> {
        let status = self.port.io_read_u32(PORT_SCR_STAT);
        if (status & 0x0f) != 0x03 {
            return Err(Error::NoLink);
        }
        for (i, byte) in fis.iter().enumerate() {
            unsafe { AHCI_PORT_DMA.cmd_tbl[i] = *byte; }
        }
        let sg_count = self.fill_sg(buf)?;
        let fis_size = core::mem::size_of::<u8>() * fis.len();
        let opts: u32 = ((fis_size as u32) >> 2)
                      | ((sg_count as u32) << 16)
                      | ((is_write as u32) << 6);
        unsafe { self.fill_cmd_slot(opts); }
        self.port.io_write_u32(PORT_CMD_ISSUE, 1);
        const DATAIO_WAIT_US: u64 = 5000 * 1000;
        if delay::wait_while(DATAIO_WAIT_US, || {
            self.port.io_read_u32(PORT_CMD_ISSUE) & 0x1 != 0
        }) {
            return Err(Error::Timeout);
        }
        Ok(())
    }
    fn identify(&self, id: &mut [u8]) -> Result<(), Error> {
        let mut fis: [u8; 20] = [0; 20];
        fis[0] = 0x27;
        fis[1] = 1 << 7;
        fis[2] = ATA_CMD_IDENTIFY_DEVICE;
        self.device_data_io(&fis, id, false)?;
        self.identify_integrity(id)
    }
    fn read_write(&self, sector: u64, buf: &mut [u8], is_write: bool)
        -> Result<(), Error> {
        assert_eq!(512, buf.len());
        let mut fis: [u8; 20] = [0; 20];
        fis[0] = 0x27;
        fis[1] = 1 << 7;
        fis[2] = match is_write {
            true => ATA_CMD_WRITE_SECTORS_EXT,
            false => ATA_CMD_READ_SECTORS_EXT,
        };
        fis[3] = 0xe0;
        fis[4] = (sector & 0xff) as u8;
        fis[5] = ((sector >> 8) & 0xff) as u8;
        fis[6] = ((sector >> 16) & 0xff) as u8;
        fis[7] = 1 << 6;
        fis[8] = ((sector >> 24) & 0xff) as u8;
        fis[12] = (512 & 0xff) as u8;
        fis[13] = ((512 >> 8) & 0xff) as u8;

        self.device_data_io(&fis, buf, is_write)
    }
}

impl SectorCapacity for AhciIoPort {
    fn get_capacity(&self) -> Result<u64, BlockError> {
        let mut id: [u8; 512] = [0; 512];
        if self.identify(&mut id).is_err() {
            return Err(BlockError::BlockIOError);
        }
        let capacity: u32 = (id[120] as u32)
                          | ((id[121] as u32) << 8)
                          | ((id[122] as u32) << 16)
                          | ((id[123] as u32) << 24);
        Ok(u64::from(capacity))
    }
}

impl SectorRead for AhciIoPort {
    fn read(&self, sector: u64, data: &mut [u8]) -> Result<(), BlockError> {
        match self.read_write(sector, data, false) {
            Ok(()) => Ok(()),
            Err(_) => Err(BlockError::BlockIOError),
        }
    }
}

impl SectorWrite for AhciIoPort {
    fn write(&self, sector: u64, data: &mut [u8]) -> Result<(), BlockError> {
        match self.read_write(sector, data, true) {
            Ok(()) => Ok(()),
            Err(_) => Err(BlockError::BlockIOError),
        }
    }

    fn flush(&self) -> Result<(), BlockError> {
        let mut fis: [u8; 20] = [0; 20];
        fis[0] = 0x27;
        fis[1] = 1 << 7;
        fis[2] = ATA_CMD_FLUSH_CACHE_EXT;
        let mut buf: [u8; 0] = [0; 0];
        match self.device_data_io(&fis, &mut buf, true) {
            Ok(()) => Ok(()),
            Err(_) => Err(BlockError::BlockIOError),
        }
    }
}
