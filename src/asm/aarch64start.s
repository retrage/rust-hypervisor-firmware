/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2022 Akira Moroo */
/* Copyright 2018 The Fuchsia Authors */

/* REF: https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/zircon/kernel/target/arm64/boot-shim/boot-shim.S */

.global aarch64_header
.extern stack_start
.section .text.boot, "ax"

aarch64_header:
  /* magic instruction that gives us UEFI "MZ" signature */
  add x13, x18, #0x16
  b aarch64_start

  .quad 0 /* image offset from start of ram (unused) */
  .quad 0 /* image size (unused) */
  .quad 0
  .quad 0
  .quad 0
  .quad 0

  /* arm64 magic number */
  .byte 'A'
  .byte 'R'
  .byte 'M'
  .byte 0x64
  .align 3

aarch64_start:
  /* x0 typically points to device tree at entry */

  /* Set DTB pointer to x0 */
  ldr x0, =0x40000000

  /* setup stack */
  ldr x30, =0x40080000
  // ldr x30, =0x4009c000
  // ldr x30, =stack_start
  mov sp, x30

  /* x0: pointer to device tree */
  b rust64_start
