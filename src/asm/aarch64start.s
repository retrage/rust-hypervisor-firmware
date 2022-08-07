.global aarch64_start
.section .text, "ax"

aarch64_start:
  ldr x30, stack_start
  mov sp, x30
  bl rust64_start