// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

use crate::{
    mem,
    virtio::{Error as VirtioError, VirtioTransport},
};

#[derive(Default, Debug)]
pub struct VirtioMmioTransport {
    region: mem::MemoryRegion,
    // config_generation: u32,
}

impl VirtioMmioTransport {
    pub fn new(region: mem::MemoryRegion) -> Self {
        Self {
            region,
            ..Default::default()
        }
    }

    pub fn get_device_id(&self) -> u32 {
      // device_id: 0x008
      self.region.io_read_u32(0x008)
    }
}

impl VirtioTransport for VirtioMmioTransport {
    fn init(&mut self, device_type: u32) -> Result<(), VirtioError> {
      let magic = self.region.io_read_u32(0x000);
      if magic != 0x74726976 {
        return Err(VirtioError::UnsupportedDevice);
      }
      let version = self.region.io_read_u32(0x004);
      if version != 0x2 {
        return Err(VirtioError::LegacyOnly);
      }

      let device_id = self.get_device_id();
      if device_id != device_type {
        return Err(VirtioError::UnsupportedDevice);
      }

      let mut before = self.region.io_read_u32(0x0fc);
      dbg!(before);
      while before != self.region.io_read_u32(0x0fc) {
        before = self.region.io_read_u32(0x0fc);
        dbg!(before);
      }
      // self.config_generation = self.region.io_read_u32(0x0fc);

      Ok(())
    }

    fn get_status(&self) -> u32 {
      self.region.io_read_u32(0x070)
    }

    fn set_status(&self, status: u32) {
      self.region.io_write_u32(0x070, status);
      core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }

    fn add_status(&self, status: u32) {
        self.set_status(self.get_status() | status);
    }

    fn reset(&self) {
        self.set_status(0);
    }

    fn get_features(&self) -> u64 {
      // device_feature_select: 0x014
      self.region.io_write_u32(0x014, 0);
      // device_feature: 0x010
      let mut device_features: u64 = u64::from(self.region.io_read_u32(0x010));
      // device_feature_select: 0x014
      self.region.io_write_u32(0x014, 1);
      // device_feature: 0x010
      device_features |= u64::from(self.region.io_read_u32(0x010)) << 32;

      device_features
    }

    fn set_features(&self, features: u64) {
      // driver_feature_select: 0x024
      self.region.io_write_u32(0x024, 0);
      // driver_feature: 0x020
      self.region.io_write_u32(0x020, features as u32);
      // driver_feature_select: 0x024
      self.region.io_write_u32(0x024, 1);
      // driver_feature: 0x020
      self.region.io_write_u32(0x020, (features >> 32) as u32);
    }

    fn set_queue(&self, queue: u16) {
      // queue_select: 0x030
      self.region.io_write_u16(0x030, queue);
    }

    fn get_queue_max_size(&self) -> u16 {
      // queue_max_size: 0x034
      self.region.io_read_u16(0x034)
    }

    fn set_queue_size(&self, queue_size: u16) {
      // queue_size: 0x038
      self.region.io_write_u16(0x038, queue_size);
    }

    fn set_descriptors_address(&self, address: u64) {
      // queue_desc_low: 0x080
      self.region.io_write_u32(0x080, address as u32);
      // queue_desc_high: 0x084
      self.region.io_write_u32(0x084, (address >> 32) as u32);
    }

    fn set_avail_ring(&self, address: u64) {
      // queue_avail_low: 0x090
      self.region.io_write_u32(0x090, address as u32);
      // queue_avail_high: 0x094
      self.region.io_write_u32(0x094, (address >> 32) as u32);
    }

    fn set_used_ring(&self, address: u64) {
      // queue_used_low: 0x0a0
      self.region.io_write_u32(0x0a0, address as u32);
      // queue_used_high: 0x0a4
      self.region.io_write_u32(0x0a4, (address >> 32) as u32);
    }

    fn set_queue_enable(&self) {
      // queue_ready: 0x044
      self.region.io_write_u32(0x044, 0x1);
    }

    fn notify_queue(&self, queue: u16) {
      // queue_notify: 0x050
      self.region.io_write_u16(0x050, queue);
    }

    fn read_device_config(&self, offset: u64) -> u32 {
      // let config_generation = self.region.io_read_u32(0x0fc);
      // if config_generation != self.config_generation {
      //   self.config_generation = config_generation;
      // }
      // config: 0x100+
      self.region.io_read_u32(0x100 + offset)
    }
}