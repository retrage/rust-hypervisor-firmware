.global aarch64_start
.extern stack_start
.section .text.boot, "ax"

aarch64_start:
  ldr x30, =stack_start
  mov sp, x30
  bl rust64_start
