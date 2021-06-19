// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2021 Akira Moroo

use core::{
    mem::{align_of, size_of},
    slice::{from_raw_parts, from_raw_parts_mut},
};
use r_efi::efi;

use crate::common;

#[derive(PartialEq, Debug, Copy, Clone)]
struct Data {
    offset: usize,
    size: usize,
}

impl Data {
    const fn new() -> Self {
        Self { offset: 0, size: 0 }
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
struct Descriptor {
    name: Data,
    guid: efi::Guid,
    attr: u32,
    data: Data,
}

impl Descriptor {
    const fn new() -> Self {
        Self {
            name: Data::new(),
            guid: efi::Guid::from_fields(0, 0, 0, 0, 0, &[0; 6]),
            attr: 0,
            data: Data::new(),
        }
    }
    fn is_empty(&self) -> bool {
        *self == Descriptor::new()
    }
}

fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

const VAR_COUNT_MAX: usize = 64;

pub struct VariableAllocator {
    vars: [Descriptor; VAR_COUNT_MAX],
    addr: usize,
    size: usize,
    next: usize, // next allocation offset
}

impl VariableAllocator {
    pub const fn new() -> Self {
        Self {
            vars: [Descriptor::new(); VAR_COUNT_MAX],
            addr: 0,
            size: 0,
            next: 0,
        }
    }

    pub fn init(&mut self, addr: usize, size: usize) {
        self.addr = addr;
        self.size = size;
    }

    fn get_name(&self, desc: &Descriptor) -> &[u16] {
        unsafe {
            from_raw_parts(
                (self.addr as u64 + desc.name.offset as u64) as *const u16,
                desc.name.size / size_of::<u16>(),
            )
        }
    }

    fn get_data(&self, desc: &Descriptor) -> &[u8] {
        unsafe {
            from_raw_parts(
                (self.addr as u64 + desc.data.offset as u64) as *const u8,
                desc.data.size / size_of::<u8>(),
            )
        }
    }

    fn set_desc(&mut self, desc: &Descriptor) -> Option<usize> {
        for (i, v) in self.vars.iter_mut().enumerate() {
            if v.is_empty() {
                *v = *desc;
                return Some(i);
            }
        }
        None
    }

    fn set_name(&mut self, name: &[u16]) -> Option<Data> {
        let size = name.len() * size_of::<u16>();
        if self.size - self.next < size {
            return None;
        }
        // TODO: use Rust Layout
        self.next = align_up(self.next, align_of::<u16>());
        let n = unsafe {
            from_raw_parts_mut(
                (self.addr as u64 + self.next as u64) as *mut u16,
                name.len(),
            )
        };
        n.clone_from_slice(name);
        let data = Data {
            offset: self.next,
            size,
        };
        self.next += size;
        Some(data)
    }

    fn set_data(&mut self, data: &[u8]) -> Option<Data> {
        let size = data.len() * size_of::<u8>();
        if self.size - self.next < size {
            return None;
        }
        let d = unsafe {
            from_raw_parts_mut((self.addr as u64 + self.next as u64) as *mut u8, data.len())
        };
        d.clone_from_slice(data);
        let data = Data {
            offset: self.next,
            size,
        };
        self.next += size;
        Some(data)
    }

    fn append_data(&mut self, from: Data, data: &[u8]) -> Option<Data> {
        let size = from.size + data.len() * size_of::<u8>();
        if self.size - self.next < size {
            return None;
        }
        let d =
            unsafe { from_raw_parts_mut((self.addr as u64 + self.next as u64) as *mut u8, size) };
        let from = unsafe {
            from_raw_parts(
                (self.addr as u64 + from.offset as u64) as *const u8,
                from.size / size_of::<u8>(),
            )
        };
        d[0..from.len()].clone_from_slice(from);
        d[from.len()..].clone_from_slice(data);
        // TODO: clear from slice content
        let data = Data {
            offset: self.next,
            size,
        };
        self.next += size;
        Some(data)
    }

    fn replace_data(&mut self, _from: Data, data: &[u8]) -> Option<Data> {
        let size = data.len() * size_of::<u8>();
        if self.size - self.next < size {
            return None;
        }
        let d = unsafe {
            from_raw_parts_mut((self.addr as u64 + self.next as u64) as *mut u8, data.len())
        };
        d.clone_from_slice(data);
        // TODO: clear from slice content
        let data = Data {
            offset: self.next,
            size,
        };
        self.next += size;
        Some(data)
    }

    fn find(&self, name: *const u16, guid: *const efi::Guid) -> Option<usize> {
        if name.is_null() || guid.is_null() {
            return None;
        }
        let len = common::ucs2_as_ascii_length(name);
        if len == 0 {
            return None;
        }
        let name = unsafe { from_raw_parts(name, len + 1) };
        let guid = unsafe { &*guid };
        for (i, v) in self.vars.iter().enumerate() {
            if self.get_name(v) == name && v.guid == *guid {
                return Some(i);
            }
        }
        None
    }

    pub fn get(
        &mut self,
        name: *const efi::Char16,
        guid: *const efi::Guid,
        attr: *mut u32,
        size: *mut usize,
        data: *mut core::ffi::c_void,
    ) -> efi::Status {
        if name.is_null() || guid.is_null() || size.is_null() {
            return efi::Status::INVALID_PARAMETER;
        }
        let index = self.find(name, guid);
        if index == None {
            return efi::Status::NOT_FOUND;
        }
        let a = &self.vars[index.unwrap()];
        unsafe {
            if *size < a.data.size {
                *size = a.data.size;
                return efi::Status::BUFFER_TOO_SMALL;
            }
        }

        assert!(a.data.size > 0);
        unsafe {
            if !attr.is_null() {
                *attr = a.attr;
            }
            *size = a.data.size;
        }

        let data = unsafe { from_raw_parts_mut(data as *mut u8, *size) };
        data.clone_from_slice(self.get_data(a));

        efi::Status::SUCCESS
    }

    pub fn set(
        &mut self,
        name: *const efi::Char16,
        guid: *const efi::Guid,
        attr: u32,
        size: usize,
        data: *const core::ffi::c_void,
    ) -> efi::Status {
        if name.is_null() || guid.is_null() {
            return efi::Status::INVALID_PARAMETER;
        }
        let len = common::ucs2_as_ascii_length(name);
        if len == 0 {
            return efi::Status::INVALID_PARAMETER;
        }
        let index = self.find(name, guid);
        if index == None {
            // new variable
            if size == 0 {
                return efi::Status::NOT_FOUND;
            }
            if data.is_null() {
                return efi::Status::INVALID_PARAMETER;
            }
            let mut a = Descriptor::new();
            let name = unsafe { from_raw_parts(name as *const u16, len + 1) };
            a.name = self.set_name(name).unwrap();
            a.guid = unsafe { *guid };
            a.attr = attr & !efi::VARIABLE_APPEND_WRITE;
            let data = unsafe { from_raw_parts(data as *const u8, size) };
            a.data = self.set_data(data).unwrap();

            match self.set_desc(&a) {
                Some(_) => return efi::Status::SUCCESS,
                None => return efi::Status::BUFFER_TOO_SMALL, // TODO
            };
        }

        if attr & efi::VARIABLE_APPEND_WRITE != 0 {
            // append to existing variable
            if size == 0 {
                return efi::Status::SUCCESS;
            }
            if data.is_null() {
                return efi::Status::INVALID_PARAMETER;
            }
            let mut a = self.vars[index.unwrap()];
            let attr = attr & !efi::VARIABLE_APPEND_WRITE;
            if a.attr != attr {
                return efi::Status::INVALID_PARAMETER;
            }
            let data = unsafe { from_raw_parts(data as *const u8, size) };
            a.data = self.append_data(a.data, data).unwrap();

            self.vars[index.unwrap()] = a;
            return efi::Status::SUCCESS;
        }

        if attr == 0 || size == 0 {
            self.vars[index.unwrap()] = Descriptor::new();
            // TODO: clear name and data
            return efi::Status::SUCCESS;
        }

        let mut a = self.vars[index.unwrap()];
        if attr != a.attr {
            return efi::Status::INVALID_PARAMETER;
        }
        let data = unsafe { from_raw_parts(data as *const u8, size) };
        a.data = self.replace_data(a.data, data).unwrap();

        self.vars[index.unwrap()] = a;
        efi::Status::SUCCESS
    }

    pub fn update_address(&mut self, mem_descs: &[efi::MemoryDescriptor]) -> efi::Status {
        const PAGE_SIZE: usize = 4 * 1024;
        for d in mem_descs.iter() {
            if d.r#type == efi::MemoryType::RuntimeServicesData as u32
                && d.physical_start <= self.addr as u64
                && (self.addr + self.size) as u64
                    <= d.physical_start + d.number_of_pages * PAGE_SIZE as u64
            {
                let diff = (d.virtual_start - d.physical_start) as usize;
                self.addr += diff;
                return efi::Status::SUCCESS;
            }
        }
        efi::Status::NOT_FOUND
    }
}

/*
#[cfg(test)]
mod tests {
    use super::VariableAllocator;
    use r_efi::efi;

    const NAME: [efi::Char16; 5] = [116, 101, 115, 116, 0];
    const GUID: efi::Guid = efi::Guid::from_fields(1, 2, 3, 4, 5, &[6; 6]);
    const ATTR: u32 = efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS;

    fn set_initial_variable(allocator: &mut VariableAllocator, data: &[u8]) {
        let status = allocator.set(
            NAME.as_ptr(),
            &GUID,
            ATTR,
            data.len(),
            data.as_ptr() as *const core::ffi::c_void,
        );

        assert_eq!(status, efi::Status::SUCCESS);
        assert_eq!(allocator.allocations[0].name, NAME);
        assert_eq!(allocator.allocations[0].guid, GUID);
        assert_eq!(allocator.allocations[0].attr, ATTR);
        assert_eq!(allocator.allocations[0].data, data);
    }

    #[test]
    fn test_new() {
        let mut allocator = VariableAllocator::new();
        set_initial_variable(&mut allocator, &[1, 2, 3]);
    }

    #[test]
    fn test_overwrite() {
        let mut allocator = VariableAllocator::new();
        set_initial_variable(&mut allocator, &[1, 2, 3]);

        let data: [u8; 5] = [4, 5, 6, 7, 8];
        let attr = ATTR;
        let status = allocator.set(
            NAME.as_ptr(),
            &GUID,
            attr,
            data.len(),
            data.as_ptr() as *const core::ffi::c_void,
        );

        assert_eq!(status, efi::Status::SUCCESS);
        assert_eq!(allocator.allocations[0].name, NAME);
        assert_eq!(allocator.allocations[0].guid, GUID);
        assert_eq!(allocator.allocations[0].attr, attr);
        assert_eq!(allocator.allocations[0].data, data);
    }

    #[test]
    fn test_append() {
        let mut allocator = VariableAllocator::new();
        set_initial_variable(&mut allocator, &[1, 2, 3]);

        let size = 0;
        let attr = ATTR | efi::VARIABLE_APPEND_WRITE;
        let status = allocator.set(
            NAME.as_ptr(),
            &GUID,
            attr,
            size,
            core::ptr::null() as *const core::ffi::c_void,
        );

        assert_eq!(status, efi::Status::SUCCESS);
        assert_eq!(allocator.allocations[0].name, NAME);
        assert_eq!(allocator.allocations[0].guid, GUID);
        assert_eq!(allocator.allocations[0].attr, ATTR);
        assert_eq!(allocator.allocations[0].data, [1, 2, 3]);

        let data: [u8; 5] = [4, 5, 6, 7, 8];
        let attr = ATTR | efi::VARIABLE_APPEND_WRITE;
        let status = allocator.set(
            NAME.as_ptr(),
            &GUID,
            attr,
            data.len(),
            data.as_ptr() as *const core::ffi::c_void,
        );

        assert_eq!(status, efi::Status::SUCCESS);
        assert_eq!(allocator.allocations[0].name, NAME);
        assert_eq!(allocator.allocations[0].guid, GUID);
        assert_eq!(allocator.allocations[0].attr, ATTR);
        assert_eq!(allocator.allocations[0].data, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_erase() {
        let mut allocator = VariableAllocator::new();
        set_initial_variable(&mut allocator, &[1, 2, 3]);

        let size = 0;
        let attr = ATTR;
        let status = allocator.set(
            NAME.as_ptr(),
            &GUID,
            attr,
            size,
            core::ptr::null() as *const core::ffi::c_void,
        );

        assert_eq!(status, efi::Status::SUCCESS);
        assert!(allocator.allocations.is_empty());

        set_initial_variable(&mut allocator, &[1, 2, 3]);

        let data: [u8; 5] = [4, 5, 6, 7, 8];
        let attr = 0;
        let status = allocator.set(
            NAME.as_ptr(),
            &GUID,
            attr,
            data.len(),
            data.as_ptr() as *const core::ffi::c_void,
        );

        assert_eq!(status, efi::Status::SUCCESS);
        assert!(allocator.allocations.is_empty());
    }

    #[test]
    fn test_get() {
        let mut allocator = VariableAllocator::new();
        const DATA: [u8; 3] = [1, 2, 3];
        set_initial_variable(&mut allocator, &DATA);

        let mut data: [u8; 3] = [0; 3];
        let mut size = data.len();
        let mut attr = 0;
        let status = allocator.get(
            NAME.as_ptr(),
            &GUID,
            &mut attr,
            &mut size,
            data.as_mut_ptr() as *mut core::ffi::c_void,
        );
        assert_eq!(status, efi::Status::SUCCESS);
        assert_eq!(attr, ATTR);
        assert_eq!(size, DATA.len());
        assert_eq!(data, DATA);

        let mut data: [u8; 3] = [0; 3];
        let mut size = data.len();
        let status = allocator.get(
            NAME.as_ptr(),
            &GUID,
            core::ptr::null_mut() as *mut u32,
            &mut size,
            data.as_mut_ptr() as *mut core::ffi::c_void,
        );
        assert_eq!(status, efi::Status::SUCCESS);
        assert_eq!(size, DATA.len());
        assert_eq!(data, DATA);

        let mut data: [u8; 1] = [0; 1];
        let mut size = data.len();
        let mut attr = 0;
        let status = allocator.get(
            NAME.as_ptr(),
            &GUID,
            &mut attr,
            &mut size,
            data.as_mut_ptr() as *mut core::ffi::c_void,
        );
        assert_eq!(status, efi::Status::BUFFER_TOO_SMALL);
        assert_eq!(attr, 0);
        assert_eq!(size, DATA.len());
        assert_eq!(data, [0; 1]);
    }
}
*/
