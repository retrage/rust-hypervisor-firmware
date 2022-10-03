use core::arch::global_asm;

#[cfg(target_arch = "x86_64")]
global_asm!(include_str!("ram32.s"), options(att_syntax, raw));
