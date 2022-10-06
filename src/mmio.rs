// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022 Akira Moroo

use crate::fdt;
use crate::mem;

use super::virtio::{Error as VirtioError, VirtioTransport};

pub struct VirtioMmioTransport {
    device: MmioDevice,
}

impl VirtioMmioTransport {
    pub fn new(device: MmioDevice) -> Self {
        Self { device }
    }
}

impl VirtioTransport for VirtioMmioTransport {
    fn init(&mut self, _device_type: u32) -> Result<(), VirtioError> {
        let magic = self.device.read_u32(0x000);
        if magic != 0x74726976 {
            return Err(VirtioError::UnsupportedDevice);
        }
        let version = self.device.read_u32(0x004);
        if version != 0x2 {
            return Err(VirtioError::LegacyOnly);
        }

        Ok(())
    }

    fn get_status(&self) -> u32 {
        self.device.read_u32(0x070)
    }

    fn set_status(&self, status: u32) {
        self.device.write_u32(0x070, status);
    }

    fn add_status(&self, status: u32) {
        self.set_status(self.get_status() | status);
    }

    fn reset(&self) {
        self.set_status(0);
    }

    fn get_features(&self) -> u64 {
        // device_feature_select: 0x014
        self.device.write_u32(0x014, 0);
        // device_feature: 0x010
        let mut device_features: u64 = u64::from(self.device.read_u32(0x010));
        // device_feature_select: 0x014
        self.device.write_u32(0x014, 1);
        // device_feature: 0x010
        device_features |= u64::from(self.device.read_u32(0x010)) << 32;

        device_features
    }

    fn set_features(&self, features: u64) {
        // driver_feature_select: 0x024
        self.device.write_u32(0x024, 0);
        // driver_feature: 0x020
        self.device.write_u32(0x020, features as u32);
        // driver_feature_select: 0x024
        self.device.write_u32(0x024, 1);
        // driver_feature: 0x020
        self.device.write_u32(0x020, (features >> 32) as u32);
    }

    fn set_queue(&self, queue: u16) {
        // queue_select: 0x030
        self.device.write_u32(0x030, queue as u32);
    }

    fn get_queue_max_size(&self) -> u16 {
        // queue_max_size: 0x034
        (self.device.read_u32(0x034) & 0xffff) as u16
    }

    fn set_queue_size(&self, queue_size: u16) {
        // queue_size: 0x038
        self.device.write_u32(0x038, queue_size as u32);
    }

    fn set_descriptors_address(&self, address: u64) {
        // queue_desc_low: 0x080
        self.device.write_u32(0x080, address as u32);
        // queue_desc_high: 0x084
        self.device.write_u32(0x084, (address >> 32) as u32);
    }

    fn set_avail_ring(&self, address: u64) {
        // queue_avail_low: 0x090
        self.device.write_u32(0x090, address as u32);
        // queue_avail_high: 0x094
        self.device.write_u32(0x094, (address >> 32) as u32);
    }

    fn set_used_ring(&self, address: u64) {
        // queue_used_low: 0x0a0
        self.device.write_u32(0x0a0, address as u32);
        // queue_used_high: 0x0a4
        self.device.write_u32(0x0a4, (address >> 32) as u32);
    }

    fn set_queue_enable(&self) {
        // queue_ready: 0x044
        self.device.write_u32(0x044, 0x1);
    }

    fn notify_queue(&self, queue: u16) {
        // queue_notify: 0x050
        self.device.write_u32(0x050, queue as u32);
    }

    fn read_device_config(&self, offset: u64) -> u32 {
        // config: 0x100+
        self.device.read_u32(0x100 + offset)
    }
}

#[derive(Default)]
pub struct MmioDevice {
    region: mem::MemoryRegion,
    pub vendor_id: u32,
    pub device_id: u32,
}

impl MmioDevice {
    pub fn new(base: u64, size: u64) -> Self {
        Self {
            region: mem::MemoryRegion::new(base, size),
            ..Default::default()
        }
    }

    pub fn read_u32(&self, offset: u64) -> u32 {
        self.region.io_read_u32(offset)
    }

    pub fn write_u32(&self, offset: u64, value: u32) {
        self.region.io_write_u32(offset, value);
    }

    pub fn init(&mut self) {
        // vendor_id: 0x00c
        self.vendor_id = self.read_u32(0x00c);

        // device_id: 0x008
        self.device_id = self.read_u32(0x008);
    }
}

pub fn with_devices<F>(info: &fdt::StartInfo, vendor_id: u32, device_id: u32, per_device: F)
where
    F: Fn(MmioDevice) -> bool,
{
    for (base, size) in info.find_all_device_regions("/virtio_mmio") {
        let mut device = MmioDevice::new(base, size);
        device.init();
        if device.vendor_id == vendor_id && device.device_id == device_id && per_device(device) {
            break;
        }
    }
}
