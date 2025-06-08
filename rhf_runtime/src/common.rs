// SPDX-License-Identifier: Apache-2.0
// Copyright © 2019 Intel Corporation

pub fn ucs2_as_ascii_length(input: *const u16) -> usize {
    let mut len = 0;
    loop {
        let v = (unsafe { *(((input as u64) + (2 * len as u64)) as *const u16) } & 0xffu16) as u8;

        if v == 0 {
            break;
        }
        len += 1;
    }
    len
}
