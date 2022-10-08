/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2022 Akira Moroo */
/* Copyright 2018 The Fuchsia Authors */

/* REF: https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/zircon/kernel/target/arm64/boot-shim/boot-shim.S */

.global aarch64_header
.section .text.boot, "ax"

aarch64_header:
  /* magic instruction that gives us UEFI "MZ" signature */
  add x13, x18, #0x16
  b aarch64_start

  .quad 0 /* image offset from start of ram (unused) */
  .quad 0 /* image size (unused) */
  .quad 0 /* flags */
  .quad 0 /* res2 */
  .quad 0 /* res3 */
  .quad 0 /* res4 */
  /* .long 0 */ /* magic */

  /* arm64 magic number */
  .byte 'A'
  .byte 'R'
  .byte 'M'
  .byte 0x64
  .long 0 /* res5 */
  .align 3

aarch64_start:
  /* x0 typically points to device tree at entry */

  /* setup stack */
  ldr x30, ={STACK_END}
  mov sp, x30

  /* x0: pointer to device tree */
  b rust64_start
