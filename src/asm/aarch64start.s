/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2022 Akira Moroo */
/* Copyright 2018 The Fuchsia Authors */

/* REF: https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/zircon/kernel/target/arm64/boot-shim/boot-shim.S */

.global aarch64_header
.global aarch64_start
.extern stack_start
.section .text.boot, "ax"

/* scratch register, not saved across function calls */
tmp .req x16

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

  /* what EL are we running at? */
  mrs tmp, CurrentEL
  cmp tmp, #(1 << 2)
  beq cache_disable_el1

  /* Disable caches and MMU (EL2 version) */
  mrs tmp, sctlr_el2
  bic tmp, tmp, #(1 << 12)  /* Instruction cache enable */
  bic tmp, tmp, #(1 << 2)   /* Cache enable */
  bic tmp, tmp, #(1 << 0)   /* MMU enable */
  msr sctlr_el2, tmp
  b cache_disable_done

cache_disable_el1:
  /* Disable caches and MMU (EL1 version) */
  mrs tmp, sctlr_el1
  bic tmp, tmp, #(1 << 12)  /* Instruction cache enable */
  bic tmp, tmp, #(1 << 2)   /* Cache enable */
  bic tmp, tmp, #(1 << 0)   /* MMU enable */
  msr sctlr_el1, tmp

cache_disable_done:
  dsb sy
  isb

  /* setup stack */
  ldr tmp, =stack_start
  mov sp, tmp

  /* x0: pointer to device tree */
  b rust64_start
