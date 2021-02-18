// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2021 Akira Moroo

use r_efi::efi;

const MAX_NAME: usize = 32;

#[derive(Debug, Copy, Clone)]
struct Descriptor {
    in_use: bool,
    name: [u8; MAX_NAME],
    guid: efi::Guid,
    offset: usize,
    size: usize,
    attr: u32,
}

#[derive(Debug, Copy, Clone)]
struct Allocation {
    in_use: bool,
    next_allocation: Option<usize>,
    descriptor: Descriptor,
}

const MAX_VARIABLES: usize = 64;
const DATA_SIZE: usize = 4096;

#[derive(Copy, Clone)]
pub struct VariableAllocator {
    allocations: [Allocation; MAX_VARIABLES],
    first_allocation: Option<usize>,
    data: [u8; DATA_SIZE],
}

impl VariableAllocator {
    pub const fn new() -> Self {
        let allocation = Allocation {
            in_use: false,
            next_allocation: None,
            descriptor: Descriptor {
                in_use: false,
                name: [0; MAX_NAME],
                guid: efi::Guid::from_fields(0, 0, 0, 0, 0, &[0; 6]),
                offset: 0,
                size: 0,
                attr: 0,
            },
        };
        let mut allocations = [allocation; MAX_VARIABLES];
        let mut a = &mut allocations[0];
        a.in_use = true;
        a.next_allocation = None;
        a.descriptor.offset = 0;
        a.descriptor.size = DATA_SIZE;

        Self {
            allocations: allocations,
            first_allocation: Some(0),
            data: [0; DATA_SIZE],
        }
    }

    fn find_free_allocation(&self) -> usize {
        let mut free_allocation = MAX_VARIABLES;
        for i in 0..self.allocations.len() {
            if !self.allocations[i].in_use {
                free_allocation = i;
                break;
            }
        }
        free_allocation
    }

    fn find_free_memory(&self, size: usize) -> Option<usize> {
        let mut cur = self.first_allocation;
        while cur != None {
            let a = &self.allocations[cur.unwrap()];

            if a.descriptor.in_use {
                cur = a.next_allocation;
                continue;
            }

            if a.descriptor.size >= size {
                return cur;
            }

            cur = a.next_allocation;
        }

        None
    }

    fn split_allocation(&mut self, orig: usize, size: usize) -> Option<usize> {
        let new = self.find_free_allocation();
        if new == MAX_VARIABLES {
            return None;
        }

        self.allocations[new].in_use = true;
        self.allocations[new].next_allocation = self.allocations[orig].next_allocation;
        self.allocations[new].descriptor.size =
            self.allocations[orig].descriptor.size - size;

        self.allocations[orig].next_allocation = Some(new);
        self.allocations[orig].descriptor.size = size;

        self.allocations[new].descriptor.offset =
            self.allocations[orig].descriptor.offset + size;

        Some(new)
    }

    fn allocate(
        &mut self,
        size: usize,
        ) -> Option<usize> {
        let dest = match self.find_free_memory(size) {
            Some(dest) => dest,
            None => return None,
        };

        if self.allocations[dest].descriptor.size == size {
            return Some(dest);
        }

        self.split_allocation(dest, size);

        let mut a = &mut self.allocations[dest];
        a.descriptor.in_use = true;

        Some(dest)
    }

    fn merge_free_memory(&mut self) {
        let mut cur = self.first_allocation;

        while cur != None {
            let next_allocation = self.allocations[cur.unwrap()].next_allocation;

            if next_allocation == None {
                return;
            }

            let current = cur.unwrap();
            let next = next_allocation.unwrap();

            if !self.allocations[current].descriptor.in_use
                && !self.allocations[next].descriptor.in_use
                && self.allocations[next].descriptor.offset
                    == self.allocations[current].descriptor.offset
                        + self.allocations[current].descriptor.size
            {
                self.allocations[current].descriptor.size +=
                    self.allocations[next].descriptor.size;
                self.allocations[current].next_allocation = self.allocations[next].next_allocation;
                self.allocations[next].in_use = false;
            } else {
                cur = next_allocation;
            }
        }
    }

    fn free(&mut self, index: usize) {
        let a = &mut self.allocations[index];

        a.descriptor.in_use = false;
        let offset = a.descriptor.offset;
        let size = a.descriptor.size;
        self.data[offset..offset+size].fill(0);
        self.merge_free_memory();
    }

    fn find(&self, name: *const u16, guid: *const efi::Guid) -> Option<usize> {
        if name.is_null() || guid.is_null() {
            return None;
        }
        let len = crate::common::ucs2_as_ascii_length(name);
        if len < 1 || len > MAX_NAME {
            return None;
        }
        let mut name_bytes: [u8; MAX_NAME] = [0; MAX_NAME];
        crate::common::ucs2_to_ascii(name, &mut name_bytes);
        let guid = unsafe { &*guid };
        for i in 0..self.allocations.len() {
            if self.allocations[i].descriptor.in_use
                && name_bytes == self.allocations[i].descriptor.name
                && guid == &self.allocations[i].descriptor.guid
            {
                return Some(i);
            }
        }
        None
    }

    pub fn set(
        &mut self,
        name: *mut efi::Char16,
        guid: *mut efi::Guid,
        attr: u32,
        size: usize,
        data: *mut core::ffi::c_void,
        ) -> efi::Status {
        const BUF_SIZE: usize = 64;
        if name.is_null() || guid.is_null() {
            return efi::Status::INVALID_PARAMETER;
        }
        if crate::common::ucs2_as_ascii_length(name) == 0 {
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
            if crate::common::ucs2_as_ascii_length(name) > MAX_NAME {
                return efi::Status::OUT_OF_RESOURCES;
            }
            let index = self.allocate(size);
            if index == None {
                return efi::Status::OUT_OF_RESOURCES;
            }
            let a = &mut self.allocations[index.unwrap()];
            crate::common::ucs2_to_ascii(name, &mut a.descriptor.name);
            a.descriptor.guid = unsafe { *guid };
            a.descriptor.attr = attr & !efi::VARIABLE_APPEND_WRITE;
            let offset = a.descriptor.offset;
            let src = unsafe { core::slice::from_raw_parts_mut(data as *mut u8, size) };
            let dest = &mut self.data[offset..offset+size];
            dest.clone_from_slice(src);

            return efi::Status::SUCCESS;
        }

        if attr & efi::VARIABLE_APPEND_WRITE != 0 {
            // append to existing variable
            if size == 0 {
                return efi::Status::SUCCESS;
            }
            if data.is_null() {
                return efi::Status::INVALID_PARAMETER;
            }
            let src_desc = self.allocations[index.unwrap()].descriptor;
            let attr = attr & !efi::VARIABLE_APPEND_WRITE;
            if src_desc.attr != attr {
                return efi::Status::INVALID_PARAMETER;
            }
            let new_idx = self.allocate(src_desc.size+size);
            if new_idx == None {
                return efi::Status::OUT_OF_RESOURCES;
            }
            let b = &mut self.allocations[new_idx.unwrap()];
            crate::common::ucs2_to_ascii(name, &mut b.descriptor.name);
            b.descriptor.guid = unsafe { *guid };
            b.descriptor.attr = attr;
            let mut offset = src_desc.offset;
            let mut remaining = src_desc.size;
            let mut b_offset = b.descriptor.offset;
            let mut buf: [u8; BUF_SIZE] = [0; BUF_SIZE];
            while remaining > 0 {
                if remaining < BUF_SIZE {
                    buf[0..remaining].clone_from_slice(&self.data[offset..offset+remaining]);
                    self.data[b_offset..b_offset+remaining].clone_from_slice(&buf[0..remaining]);
                    b_offset += remaining;
                    break;
                } else {
                    buf.clone_from_slice(&self.data[offset..offset+64]);
                    self.data[b_offset..b_offset+64].clone_from_slice(&buf);
                    offset += 64;
                    b_offset += 64;
                    remaining -= 64;
                }
            }

            let src = unsafe { core::slice::from_raw_parts_mut(data as *mut u8, size) };
            let dest = &mut self.data[b_offset..b_offset+size];
            dest.clone_from_slice(src);
            self.free(index.unwrap());
            return efi::Status::SUCCESS;
        }

        let a = &mut self.allocations[index.unwrap()];

        if a.descriptor.size == size {
            if data.is_null() {
                return efi::Status::INVALID_PARAMETER;
            }
            let offset = a.descriptor.offset;
            let src = unsafe { core::slice::from_raw_parts_mut(data as *mut u8, size) };
            let dest = &mut self.data[offset..offset+size];
            dest.clone_from_slice(src);

            return efi::Status::SUCCESS;
        }

        if size == 0 {
            // erase variable
            self.free(index.unwrap());
            return efi::Status::SUCCESS;
        }

        let new_index = self.allocate(size);
        if new_index == None {
            return efi::Status::OUT_OF_RESOURCES;
        }
        self.free(index.unwrap());
        let a = &mut self.allocations[new_index.unwrap()];
        crate::common::ucs2_to_ascii(name, &mut a.descriptor.name);
        a.descriptor.guid = unsafe { *guid };
        a.descriptor.attr = attr;
        let offset = a.descriptor.offset;
        let src = unsafe { core::slice::from_raw_parts_mut(data as *mut u8, size) };
        let dest = &mut self.data[offset..offset+size];
        dest.clone_from_slice(src);

        efi::Status::SUCCESS
    }

    pub fn get(
        &mut self,
        name: *mut efi::Char16,
        guid: *mut efi::Guid,
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
        let a = self.allocations[index.unwrap()];
        unsafe {
            if *size < a.descriptor.size {
                *size = a.descriptor.size;
                return efi::Status::BUFFER_TOO_SMALL;
            }
        }

        assert!(a.descriptor.size > 0);
        unsafe {
            if !attr.is_null() {
                *attr = a.descriptor.attr;
            }
            *size = a.descriptor.size;

            let offset = a.descriptor.offset;
            let size = a.descriptor.size;
            let data = core::slice::from_raw_parts_mut(data as *mut u8, size);
            data.clone_from_slice(&self.data[offset..offset+size]);
        }

        efi::Status::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::VariableAllocator;
    use r_efi::efi;

    #[test]
    fn test_init() {
        let allocator = VariableAllocator::new();

        assert_eq!(allocator.first_allocation, Some(0));
        assert_eq!(allocator.allocations[0].in_use, true);
        assert_eq!(allocator.allocations[0].next_allocation, None);
        assert_eq!(allocator.allocations[0].descriptor.offset, 0);
        assert_eq!(allocator.allocations[0].descriptor.size, 1024);
    }

    #[test]
    fn test_set() {
        let mut allocator = VariableAllocator::new();

        let mut name: [efi::Char16; 5] = [116, 101, 115, 116, 0];
        let mut guid = efi::Guid::from_fields(1, 2, 3, 4, 5, &[6; 6]);
        let mut data: [u8; 3] = [1, 2, 3];
        let size = data.len();
        let attr = 0;
        let status = allocator.set(name.as_mut_ptr(), &mut guid, attr, size, data.as_mut_ptr() as *mut core::ffi::c_void);

        assert_eq!(status, efi::Status::SUCCESS);
        assert_eq!(allocator.allocations[0].in_use, true);
        assert_eq!(allocator.allocations[0].next_allocation, Some(1));
        assert_eq!(allocator.allocations[0].descriptor.offset, 0);
        assert_eq!(allocator.allocations[0].descriptor.size, 3);
        assert_eq!(&allocator.data[0..3], &data);

        let mut data: [u8; 1025] = [0xff; 1025];
        let size = data.len();
        let attr = 0;
        let status = allocator.set(name.as_mut_ptr(), &mut guid, attr, size, data.as_mut_ptr() as *mut core::ffi::c_void);

        assert_eq!(status, efi::Status::OUT_OF_RESOURCES);

        let size = 0;
        let attr = 0;
        let status = allocator.set(name.as_mut_ptr(), &mut guid, attr, size, core::ptr::null_mut() as *mut core::ffi::c_void);

        assert_eq!(status, efi::Status::SUCCESS);
        assert_eq!(allocator.allocations[0].in_use, true);
        assert_eq!(allocator.allocations[0].next_allocation, None);
        assert_eq!(allocator.data[0..3], [0, 0, 0]);
    }

    #[test]
    fn test_get() {
        let mut allocator = VariableAllocator::new();

        let mut name: [efi::Char16; 5] = [116, 101, 115, 116, 0];
        let mut guid = efi::Guid::from_fields(1, 2, 3, 4, 5, &[6; 6]);
        let mut data: [u8; 3] = [1, 2, 3];
        let size = data.len();
        let attr = 0;
        let status = allocator.set(name.as_mut_ptr(), &mut guid, attr, size, data.as_mut_ptr() as *mut core::ffi::c_void);

        assert_eq!(status, efi::Status::SUCCESS);

        let mut data: [u8; 3] = [0; 3];
        let mut size = data.len();
        let mut attr = 0;
        let status = allocator.get(name.as_mut_ptr(), &mut guid, &mut attr, &mut size, data.as_mut_ptr() as *mut core::ffi::c_void);

        assert_eq!(status, efi::Status::SUCCESS);
        assert_eq!(size, 3);
        assert_eq!(data, [1, 2, 3]);
        assert_eq!(attr, 0);
    }

    #[test]
    fn test_append() {
        let mut allocator = VariableAllocator::new();

        let mut name: [efi::Char16; 5] = [116, 101, 115, 116, 0];
        let mut guid = efi::Guid::from_fields(1, 2, 3, 4, 5, &[6; 6]);
        let mut data: [u8; 3] = [1, 2, 3];
        let size = data.len();
        let attr = 0;
        let status = allocator.set(name.as_mut_ptr(), &mut guid, attr, size, data.as_mut_ptr() as *mut core::ffi::c_void);

        assert_eq!(status, efi::Status::SUCCESS);

        let mut data: [u8; 4] = [4, 5, 6, 7];
        let size = data.len();
        let attr = efi::VARIABLE_APPEND_WRITE;
        let status = allocator.set(name.as_mut_ptr(), &mut guid, attr, size, data.as_mut_ptr() as *mut core::ffi::c_void);

        assert_eq!(status, efi::Status::SUCCESS);

        let mut data: [u8; 7] = [0; 7];
        let mut size = data.len();
        let mut attr = 0;
        let status = allocator.get(name.as_mut_ptr(), &mut guid, &mut attr, &mut size, data.as_mut_ptr() as *mut core::ffi::c_void);

        assert_eq!(status, efi::Status::SUCCESS);
        assert_eq!(size, 7);
        assert_eq!(data, [1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(attr, 0);

        let size = 0;
        let attr = 0;
        let status = allocator.set(name.as_mut_ptr(), &mut guid, attr, size, core::ptr::null_mut() as *mut core::ffi::c_void);

        assert_eq!(status, efi::Status::SUCCESS);

        let mut data: [u8; 7] = [0; 7];
        let mut size = data.len();
        let mut attr = 0;
        let status = allocator.get(name.as_mut_ptr(), &mut guid, &mut attr, &mut size, data.as_mut_ptr() as *mut core::ffi::c_void);

        assert_eq!(status, efi::Status::NOT_FOUND);
    }
}
