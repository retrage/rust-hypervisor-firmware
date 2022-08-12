use core::arch::global_asm;

#[cfg(target_arch = "x86_64")]
global_asm!(include_str!("ram32.s"), options(att_syntax, raw));

#[cfg(target_arch = "aarch64")]
global_asm!(include_str!("aarch64start.s"));

#[cfg(target_arch = "aarch64")]
global_asm!(include_str!("aarch64asm.s"));