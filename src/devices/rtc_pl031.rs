// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

use atomic_refcell::AtomicRefCell;
use chrono::{DateTime, Datelike, NaiveDateTime, Timelike, Utc};

use crate::mem;

// TODO: Configure base address from FDT
static RTC: AtomicRefCell<Pl031> = AtomicRefCell::new(Pl031::new(0x9010000));

struct Pl031 {
    region: mem::MemoryRegion,
}

impl Pl031 {
    const RTCDR: u64 = 0x000;

    pub const fn new(base: u64) -> Self {
        Self {
            region: mem::MemoryRegion::new(base, 0x1000),
        }
    }

    fn read_timestamp(&self) -> u32 {
        self.region.io_read_u32(Self::RTCDR)
    }

    pub fn read_date(&self) -> Result<(u8, u8, u8), ()> {
        let timestamp = self.read_timestamp();
        let naive = NaiveDateTime::from_timestamp(timestamp as i64, 0);
        let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
        Ok((
            (datetime.year() - 2000) as u8,
            datetime.month() as u8,
            datetime.day() as u8,
        ))
    }

    pub fn read_time(&self) -> Result<(u8, u8, u8), ()> {
        let timestamp = self.read_timestamp();
        let naive = NaiveDateTime::from_timestamp(timestamp as i64, 0);
        let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
        Ok((
            datetime.hour() as u8,
            datetime.minute() as u8,
            datetime.second() as u8,
        ))
    }
}

pub fn read_date() -> Result<(u8, u8, u8), ()> {
    RTC.borrow_mut().read_date()
}

pub fn read_time() -> Result<(u8, u8, u8), ()> {
    RTC.borrow_mut().read_time()
}