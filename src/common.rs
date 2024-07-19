// SPDX-License-Identifier: Apache-2.0
// Copyright © 2019 Intel Corporation

#[macro_export]
macro_rules! container_of {
    ($ptr:ident, $container:ty, $field:ident) => {{
        (($ptr as usize) - core::mem::offset_of!($container, $field)) as *const $container
    }};
}

#[macro_export]
macro_rules! container_of_mut {
    ($ptr:ident, $container:ty, $field:ident) => {{
        (($ptr as usize) - core::mem::offset_of!($container, $field)) as *mut $container
    }};
}

// SAFETY: Requires that addr point to a static, null-terminated C-string.
// The returned slice does not include the null-terminator.
#[allow(dead_code)]
pub unsafe fn from_cstring(addr: u64) -> &'static [u8] {
    if addr == 0 {
        return &[];
    }
    let start = addr as *const i8;
    let cstr = core::ffi::CStr::from_ptr(start);
    cstr.to_bytes()
}

pub fn ascii_strip(s: &[u8]) -> &str {
    core::str::from_utf8(s).unwrap().trim_matches(char::from(0))
}

pub fn ucs2_as_ascii_length(input: *const u16) -> usize {
    let mut len = 0;
    loop {
        let v = (unsafe { *input.add(len) } & 0xffu16) as u8;
        if v == b'\0' {
            break;
        }
        len += 1;
    }
    len
}

pub fn ascii_length(input: &str) -> usize {
    let mut len = 0;
    for c in input.chars() {
        if c == '\0' {
            break;
        }
        len += 1;
    }
    len
}

pub fn ucs2_to_ascii(input: *const u16, output: &mut [u8]) {
    let mut i = 0;
    assert!(output.len() >= ucs2_as_ascii_length(input));
    while i < output.len() {
        let v = (unsafe { *input.add(i) } & 0xffu16) as u8;
        output[i] = v;
        if v == b'\0' {
            break;
        }
        i += 1;
    }
}

pub fn ascii_to_ucs2(input: &str, output: &mut [u16]) {
    assert!(output.len() >= input.len() * 2);

    for (i, c) in input.bytes().enumerate() {
        output[i] = u16::from(c);
    }
}
