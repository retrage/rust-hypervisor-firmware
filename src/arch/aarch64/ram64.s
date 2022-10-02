/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2022 Akira Moroo */

.section .text.boot, "ax"
.global ram64_start

ram64_start:
  /* UEFI "MZ" signature magic instruction */
  add x13, x18, #0x16   /* code0 */
  b jump_to_rust        /* code1 */

  .quad 0               /* text_offset */
  .quad 0               /* image_size */
  .quad 0               /* flags */
  .quad 0               /* res2 */
  .quad 0               /* res3 */
  .quad 0               /* res4 */

  .long 0x644d5241      /* "ARM\x64" magic number */
  .long 0               /* res5 */
  .align 3

jump_to_rust:
  /* x0 typically points to device tree at entry */
  ldr x0, =0x40000000

  /* setup stack */
  ldr x30, =0xfc000000
  mov sp, x30

  /* x0: pointer to device tree */
  b rust64_start