// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 Akira Moroo

// protocol.rs implements an EFI protocol manager.
// It stores the installed protocols with associated handles.

use core::{
    borrow::Borrow,
    ffi::c_void,
    mem::size_of,
    ptr::{null_mut, NonNull},
};

use heapless::{FnvIndexMap, FnvIndexSet, Vec};
use r_efi::efi::{self};

use crate::efi::ALLOCATOR;

#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    OutOfResources,
    NotFound,
    InvalidParameter,
    BufferTooSmall,
    Unsupported,
    AccessDenied,
    EfiOther(efi::Status),
}

impl From<Error> for efi::Status {
    fn from(e: Error) -> Self {
        match e {
            Error::OutOfResources => efi::Status::OUT_OF_RESOURCES,
            Error::NotFound => efi::Status::NOT_FOUND,
            Error::InvalidParameter => efi::Status::INVALID_PARAMETER,
            Error::BufferTooSmall => efi::Status::BUFFER_TOO_SMALL,
            Error::Unsupported => efi::Status::UNSUPPORTED,
            Error::AccessDenied => efi::Status::ACCESS_DENIED,
            Error::EfiOther(status) => status,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct WrappedHandle(NonNull<c_void>);

impl Borrow<efi::Handle> for WrappedHandle {
    fn borrow(&self) -> &efi::Handle {
        unsafe { &*(self.0.as_ptr() as *const efi::Handle) }
    }
}

impl WrappedHandle {
    fn new(handle: efi::Handle) -> Option<Self> {
        NonNull::new(handle).map(|n| Self { 0: n })
    }

    fn as_ptr(&self) -> *const c_void {
        self.0.as_ptr()
    }

    #[allow(dead_code)]
    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.0.as_ptr()
    }
}

impl From<WrappedHandle> for efi::Handle {
    fn from(handle: WrappedHandle) -> Self {
        *handle.borrow()
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
struct Protocol {
    guid: efi::Guid,
    interface: NonNull<c_void>,
}

impl Default for Protocol {
    fn default() -> Self {
        Self {
            guid: efi::Guid::from_bytes(&[0u8; 16]),
            interface: NonNull::dangling(),
        }
    }
}

impl Protocol {
    pub fn new(guid: efi::Guid, interface: NonNull<c_void>) -> Self {
        Self { guid, interface }
    }
}

struct OpenProtocolData {
    agent_handle: Option<WrappedHandle>,
    controller_handle: Option<WrappedHandle>,
    attributes: u32,
    open_count: u32,
}

impl OpenProtocolData {
    fn matches(
        &self,
        agent_handle: efi::Handle,
        controller_handle: efi::Handle,
        attributes: Option<u32>,
    ) -> bool {
        log!("OpenProtocolData::matches: agent_handle: {:p}, controller_handle: {:p}, attributes: {:x}", agent_handle, controller_handle, attributes.unwrap_or(0));
        self.agent_handle == WrappedHandle::new(agent_handle)
            && self.controller_handle == WrappedHandle::new(controller_handle)
            && (attributes.is_none() || self.attributes == attributes.unwrap())
    }
}

const MAX_PROTOCOLS: usize = 16;
const MAX_HANDLES: usize = 16;
// const MAX_IMAGE_HANDLES: usize = 16;
const MAX_DEVICE_HANDLES: usize = 16;
const MAX_OPEN_DATA: usize = 16;

type DeviceHandle = WrappedHandle;
// type ImageHandle = WrappedHandle;

pub struct ProtocolManager {
    #[allow(dead_code)]
    handles: FnvIndexSet<WrappedHandle, MAX_HANDLES>,
    protocols: FnvIndexMap<DeviceHandle, Vec<Protocol, MAX_PROTOCOLS>, MAX_DEVICE_HANDLES>,
    open_lists: FnvIndexMap<Protocol, Vec<OpenProtocolData, MAX_OPEN_DATA>, MAX_PROTOCOLS>,
}

// TODO: Make ProtocolManager thread-safe
unsafe impl Send for ProtocolManager {}
unsafe impl Sync for ProtocolManager {}

impl ProtocolManager {
    pub const fn new() -> Self {
        Self {
            handles: FnvIndexSet::new(),
            protocols: FnvIndexMap::new(),
            open_lists: FnvIndexMap::new(),
        }
    }

    pub fn locate_device_handle(&self, guid: &efi::Guid) -> Option<usize> {
        for (handle, protocols) in self.protocols.iter() {
            for protocol in protocols.iter() {
                if protocol.guid == *guid {
                    log!("locate_device_handle: {:?}", handle.as_ptr().addr());
                    return Some(handle.as_ptr().addr());
                }
            }
        }
        None
    }

    fn dump_protocols(&self) {
        log!("dump_protocols");
        for (handle, protocols) in self.protocols.iter() {
            log!("Handle: {:p}", handle.as_ptr());
            for protocol in protocols.iter() {
                log!("  Protocol: {:?}", protocol.guid);
            }
        }
        for (protocol, open_list) in self.open_lists.iter() {
            if open_list.is_empty() {
                continue;
            }
            log!("Protocol: {:?}", protocol.guid);
            for open_data in open_list.iter() {
                log!(
                    "  Agent: {:?}, Controller: {:?}, Attributes: {:x}, OpenCount: {}",
                    open_data.agent_handle,
                    open_data.controller_handle,
                    open_data.attributes,
                    open_data.open_count
                );
            }
        }
    }

    pub fn install_protocol_interface(
        &mut self,
        handle: *mut efi::Handle,
        protocol_guid: *const efi::Guid,
        interface_type: efi::InterfaceType,
        interface: *mut c_void,
    ) -> Result<(), Error> {
        log!(
            "install_protocol_interface: handle: {:p}, protocol_guid: {:?}, interface_type: {:?}, interface: {:p}",
            handle,
            unsafe { &*protocol_guid },
            interface_type,
            interface
        );
        if handle.is_null() || protocol_guid.is_null() || interface_type != efi::NATIVE_INTERFACE {
            return Err(Error::InvalidParameter);
        }
        if unsafe { *handle } == null_mut() {
            // Create a new handle
            let (status, handle_addr) = ALLOCATOR
                .borrow_mut()
                .allocate_pool(efi::LOADER_DATA, size_of::<efi::Handle>());
            assert!(status == efi::Status::SUCCESS);
            unsafe { *handle = handle_addr as efi::Handle };
        }
        log!("handle: {:p}", unsafe { *handle });
        let handle = WrappedHandle::new(unsafe { *handle }).unwrap();
        let protocol_guid = unsafe { *protocol_guid };
        match self.protocols.get_mut(&handle) {
            Some(protocols) => {
                if protocols.len() == MAX_PROTOCOLS {
                    return Err(Error::OutOfResources);
                }
                for protocol in protocols.iter() {
                    if protocol.guid == protocol_guid {
                        log!(
                            "Protocol already installed: handle: {:?}, protocol: {:?}",
                            handle,
                            protocol.guid
                        );
                        // return Err(Error::InvalidParameter);
                        continue;
                    }
                }
                let protocol = Protocol::new(protocol_guid, NonNull::new(interface).unwrap());
                protocols
                    .push(protocol)
                    .map_err(|_| Error::OutOfResources)?;
                match self.open_lists.get_mut(&protocol) {
                    Some(open_list) => {
                        for open_data in open_list.iter_mut() {
                            if open_data.agent_handle == Some(handle) {
                                open_data.open_count += 1;
                            }
                        }
                    }
                    None => {
                        let open_list = Vec::new();
                        self.open_lists
                            .insert(protocol, open_list)
                            .map_err(|_| Error::OutOfResources)?;
                    }
                }
                Ok(())
            }
            None => {
                log!("no handle found for handle {:?}", handle);
                let mut protocols = Vec::new();
                let protocol = Protocol::new(protocol_guid, NonNull::new(interface).unwrap());
                protocols
                    .push(protocol)
                    .map_err(|_| Error::OutOfResources)?;
                self.protocols
                    .insert(handle, protocols)
                    .map_err(|_| Error::OutOfResources)?;
                match self.open_lists.get_mut(&protocol) {
                    Some(open_list) => {
                        for open_data in open_list.iter_mut() {
                            if open_data.agent_handle == Some(handle) {
                                open_data.open_count += 1;
                            }
                        }
                    }
                    None => {
                        let open_list = Vec::new();
                        self.open_lists
                            .insert(protocol, open_list)
                            .map_err(|_| Error::OutOfResources)?;
                    }
                }
                Ok(())
            }
        }
    }

    pub fn uninstall_protocol_interface(
        &mut self,
        handle: efi::Handle,
        protocol_guid: *const efi::Guid,
        interface: *mut c_void,
    ) -> Result<(), Error> {
        if handle.is_null() || protocol_guid.is_null() {
            return Err(Error::InvalidParameter);
        }
        let handle = WrappedHandle::new(handle).unwrap();
        let protocol_guid = unsafe { *protocol_guid };
        match self.protocols.get_mut(&handle) {
            Some(protocols) => {
                for (idx, protocol) in protocols.iter_mut().enumerate() {
                    if protocol.guid == protocol_guid && protocol.interface.as_ptr() == interface {
                        // TODO: Check if the protocol is opened
                        protocols.remove(idx);
                        return Ok(());
                    }
                }
                Err(Error::NotFound)
            }
            None => Err(Error::InvalidParameter),
        }
    }

    pub fn reinstall_protocol_interface(
        &mut self,
        handle: efi::Handle,
        protocol_guid: *const efi::Guid,
        old_interface: *mut c_void,
        new_interface: *mut c_void,
    ) -> Result<(), Error> {
        if handle.is_null() || protocol_guid.is_null() {
            return Err(Error::InvalidParameter);
        }
        let handle = WrappedHandle::new(handle).unwrap();
        let protocol_guid = unsafe { *protocol_guid };
        match self.protocols.get_mut(&handle) {
            Some(protocols) => {
                for protocol in protocols.iter_mut() {
                    if protocol.guid == protocol_guid
                        && protocol.interface.as_ptr() == old_interface
                    {
                        protocol.interface = NonNull::new(new_interface).unwrap();
                        return Ok(());
                    }
                }
                Err(Error::NotFound)
            }
            None => Err(Error::InvalidParameter),
        }
    }

    pub fn register_protocol_notify(
        &mut self,
        _protocol: *mut efi::Guid,
        _event: efi::Event,
        _registration: *mut efi::Handle,
    ) -> Result<(), Error> {
        log!("register_protocol_notify");
        Err(Error::Unsupported)
    }

    pub fn locate_handle(
        &mut self,
        search_type: efi::LocateSearchType,
        protocol_guid: *const efi::Guid,
        search_key: *const c_void,
        buffer_size: *mut usize,
        buffer: *mut efi::Handle,
    ) -> Result<(), Error> {
        log!("locate_handle: search_type: {:?}, protocol_guid: {:?}, search_key: {:p}, buffer_size: {:p}, buffer: {:p}", search_type, unsafe { &*protocol_guid}, search_key, buffer_size, buffer);
        if unsafe { *protocol_guid } == efi::protocols::device_path::PROTOCOL_GUID {
            log!("locate_handle: device_path");
        }
        let handles = match search_type {
            efi::ALL_HANDLES => self
                .protocols
                .iter()
                .filter(|(_, protocols)| protocols.iter().any(|_| true))
                .map(|(handle, _)| handle)
                .collect::<Vec<_, MAX_DEVICE_HANDLES>>(),
            efi::BY_REGISTER_NOTIFY if !search_key.is_null() => {
                todo!("locate_handle: BY_REGISTER_NOTIFY");
            }
            efi::BY_PROTOCOL if !protocol_guid.is_null() => {
                let protocol_guid = unsafe { *protocol_guid };
                self.protocols
                    .iter()
                    .filter(|(_, protocols)| {
                        protocols
                            .iter()
                            .any(|&protocol| protocol.guid == protocol_guid)
                    })
                    .map(|(handle, _)| handle)
                    .collect::<Vec<_, MAX_DEVICE_HANDLES>>()
            }
            _ => return Err(Error::InvalidParameter),
        };

        if handles.is_empty() {
            return Err(Error::NotFound);
        }
        if buffer_size.is_null() {
            return Err(Error::InvalidParameter);
        }
        let buffer_size = unsafe { buffer_size.as_mut().unwrap() };
        let needed_size = size_of::<efi::Handle>() * handles.len();
        log!("needed_size: {}, buffer_size: {}", needed_size, *buffer_size);
        if *buffer_size < needed_size {
            *buffer_size = needed_size;
            return Err(Error::BufferTooSmall);
        }
        if buffer.is_null() {
            return Err(Error::InvalidParameter);
        }
        let buffer = unsafe { core::slice::from_raw_parts_mut(buffer, handles.len()) };
        for (idx, handle) in handles.iter().enumerate() {
            buffer[idx] = handle.as_ptr() as *mut c_void;
            log!("locate_handle: buffer[{}]: {:p}", idx, buffer[idx]);
        }
        *buffer_size = needed_size;
        Ok(())
    }

    pub fn handle_protocol(
        &mut self,
        handle: efi::Handle,
        protocol_guid: *const efi::Guid,
        interface: *mut *mut c_void,
    ) -> Result<(), Error> {
        log!(
            "handle_protocol: handle: {:p}, protocol_guid: {:?}, interface: {:p}",
            handle,
            unsafe { *protocol_guid },
            interface
        );
        self.dump_protocols();
        self.open_protocol(
            handle,
            protocol_guid,
            interface,
            null_mut(), // TODO
            null_mut(),
            efi::OPEN_PROTOCOL_BY_HANDLE_PROTOCOL,
        )
    }

    // Locates the handle to a device on the device path that supports the specified protocol.
    pub fn locate_device_path(
        &mut self,
        _protocol: *mut efi::Guid,
        _device_path: *mut *mut efi::protocols::device_path::Protocol,
        _device: *mut efi::Handle,
    ) -> Result<(), Error> {
        Err(Error::NotFound)
    }

    // It does not support the following attributes:
    // - OPEN_PROTOCOL_BY_HANDLE_PROTOCOL
    // - OPEN_PROTOCOL_BY_CHILD_CONTROLLER
    // - OPEN_PROTOCOL_BY_DRIVER
    // - OPEN_PROTOCOL_EXCLUSIVE
    pub fn open_protocol(
        &mut self,
        user_handle: efi::Handle,
        protocol_guid: *const efi::Guid,
        interface: *mut *mut c_void,
        agent_handle: efi::Handle,
        controller_handle: efi::Handle,
        attributes: u32,
    ) -> Result<(), Error> {
        log!("open_protocol: user_handle: {:p}, protocol_guid: {:?}, interface: {:p}, agent_handle: {:p}, controller_handle: {:p}, attributes: {:x}", user_handle, unsafe { *protocol_guid }, interface, agent_handle, controller_handle, attributes);
        if user_handle.addr() == 0x2 {
            unsafe {
                core::arch::asm!("int3");
            }
        }
        if unsafe { *protocol_guid } == efi::protocols::device_path::PROTOCOL_GUID {
            log!("open_protocol: device_path");
        }
        if protocol_guid.is_null() {
            return Err(Error::InvalidParameter);
        }
        if attributes == efi::OPEN_PROTOCOL_TEST_PROTOCOL && interface.is_null() {
            return Err(Error::InvalidParameter);
        }
        let user_handle = WrappedHandle::new(user_handle).unwrap();
        let protocol_guid = unsafe { *protocol_guid };
        let prot = self
            .protocols
            .get(&user_handle)
            .ok_or(Error::Unsupported)?
            .iter()
            .find(|prot| prot.guid == protocol_guid)
            .ok_or(Error::Unsupported)?;

        let open_list = match self.open_lists.get_mut(prot) {
            Some(open_list) => {
                for open_data in open_list.iter_mut() {
                    if open_data.matches(agent_handle, controller_handle, Some(attributes)) {
                        open_data.open_count += 1;
                        if attributes != efi::OPEN_PROTOCOL_TEST_PROTOCOL {
                            log!("open_protocol: interface: {:p}", prot.interface.as_ptr());
                            unsafe { *interface = prot.interface.as_ptr() };
                        }
                        return Ok(());
                    }
                }
                open_list
            }
            None => {
                if attributes != efi::OPEN_PROTOCOL_TEST_PROTOCOL {
                    unsafe { *interface = null_mut() };
                }
                log!("open_list is None");
                return Err(Error::Unsupported);
            }
        };

        if agent_handle.is_null() {
            if attributes != efi::OPEN_PROTOCOL_TEST_PROTOCOL {
                unsafe { *interface = prot.interface.as_ptr() };
            }
            return Ok(());
        }

        log!(
            "open_protocol: agent_handle: {:p}, controller_handle: {:p}, attributes: {:x}",
            agent_handle,
            controller_handle,
            attributes
        );
        open_list
            .push(OpenProtocolData {
                agent_handle: WrappedHandle::new(agent_handle),
                controller_handle: WrappedHandle::new(controller_handle),
                attributes,
                open_count: 1,
            })
            .map_err(|_| Error::OutOfResources)?;
        log!("open_protocol: open_list.len(): {}", open_list.len());

        log!("open_protocol: interface: {:p}", prot.interface.as_ptr());
        if attributes != efi::OPEN_PROTOCOL_TEST_PROTOCOL {
            unsafe { *interface = prot.interface.as_ptr() };
        }
        Ok(())
    }

    pub fn close_protocol(
        &mut self,
        user_handle: efi::Handle,
        protocol: *mut efi::Guid,
        agent_handle: efi::Handle,
        controller_handle: efi::Handle,
    ) -> Result<(), Error> {
        if user_handle.is_null() || agent_handle.is_null() || protocol.is_null() {
            return Err(Error::InvalidParameter);
        }
        let user_handle = WrappedHandle::new(user_handle).unwrap();
        let prot = self
            .protocols
            .get(&user_handle)
            .ok_or(Error::NotFound)?
            .iter()
            .find(|prot| prot.guid == unsafe { *protocol })
            .ok_or(Error::NotFound)?;
        self.open_lists
            .get_mut(prot)
            .ok_or(Error::NotFound)?
            .iter_mut()
            .for_each(|open_data| {
                if open_data.matches(agent_handle, controller_handle, None) {
                    open_data.open_count -= 1;
                }
            });
        Ok(())
    }

    pub fn open_protocol_information(
        &mut self,
        handle: efi::Handle,
        protocol_guid: *const efi::Guid,
        entry_buffer: *mut *mut efi::OpenProtocolInformationEntry,
        entry_count: *mut usize,
    ) -> Result<(), Error> {
        if handle.is_null()
            || protocol_guid.is_null()
            || entry_buffer.is_null()
            || entry_count.is_null()
        {
            return Err(Error::InvalidParameter);
        }
        let _protocol_guid = unsafe { *protocol_guid };
        todo!()
    }

    pub fn connect_controller(
        &mut self,
        _controller_handle: efi::Handle,
        _driver_image_handle: *const efi::Handle,
        _remaining_device_path: *const efi::protocols::device_path::Protocol,
        _recursive: efi::Boolean,
    ) -> Result<(), Error> {
        log!("connect_controller");
        Err(Error::Unsupported)
    }

    pub fn disconnect_controller(
        &mut self,
        _controller_handle: efi::Handle,
        _driver_image_handle: efi::Handle,
        _child_handle: efi::Handle,
    ) -> Result<(), Error> {
        log!("disconnect_controller");
        Err(Error::Unsupported)
    }

    pub fn protocols_per_handle(
        &mut self,
        handle: efi::Handle,
        protocol_buffer: *mut *mut *mut efi::Guid,
        protocol_buffer_count: *mut usize,
    ) -> Result<(), Error> {
        if handle.is_null() || protocol_buffer.is_null() || protocol_buffer_count.is_null() {
            return Err(Error::InvalidParameter);
        }
        let handle = WrappedHandle::new(handle).unwrap();
        let protocol_buffer = unsafe { *protocol_buffer };
        let protocols = match self.protocols.get(&handle) {
            Some(protocols) => protocols,
            None => return Err(Error::NotFound),
        };
        let status = super::boot_services::allocate_pool(
            efi::LOADER_DATA,
            size_of::<efi::Guid>() * protocols.len(),
            protocol_buffer as *mut *mut c_void,
        );
        if status != efi::Status::SUCCESS {
            return Err(Error::EfiOther(status));
        }
        let protocol_buffer =
            unsafe { core::slice::from_raw_parts_mut(protocol_buffer, protocols.len()) };
        for (idx, protocol) in protocols.iter().enumerate() {
            protocol_buffer[idx] = &protocol.guid as *const efi::Guid as *mut efi::Guid;
        }
        unsafe { *protocol_buffer_count = protocols.len() };
        Ok(())
    }

    pub fn locate_handle_buffer(
        &mut self,
        _search_type: efi::LocateSearchType,
        _protocol: *const efi::Guid,
        _search_key: *const c_void,
        _no_handles: *mut usize,
        _buffer: *mut *mut efi::Handle,
    ) -> Result<(), Error> {
        log!("locate_handle_buffer");
        Err(Error::Unsupported)
    }

    pub fn locate_protocol(
        &mut self,
        protocol_guid: *const efi::Guid,
        _registration: *mut c_void,
        interface: *mut *mut c_void,
    ) -> Result<(), Error> {
        // TODO: Implement registration support
        if protocol_guid.is_null() || interface.is_null() {
            return Err(Error::InvalidParameter);
        }
        let protocol_guid = unsafe { *protocol_guid };
        for protocols in self.protocols.values() {
            for protocol in protocols.iter() {
                if protocol.guid == protocol_guid {
                    unsafe { *interface = protocol.interface.as_ptr() };
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::WrappedHandle;

    #[test]
    fn test_handle() {
        let handle1 = WrappedHandle::new(0x1234 as *mut core::ffi::c_void);
        let handle2 = WrappedHandle::new(0x1234 as *mut core::ffi::c_void);
        assert_eq!(handle1, handle2);

        let handle3 = WrappedHandle::new(0x5678 as *mut core::ffi::c_void);
        assert_ne!(handle1, handle3);
    }
}
