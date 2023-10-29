# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 Google LLC

.section .text, "ax"
.global ram64_start
.code64

ram64_start:
    # lgdtq GDT64_PTR
    movq $stack_end, %rsp
    # movw $0x10, %ax
    # movw %ax, %ds
    # movw %ax, %es
    # movw %ax, %gs
    # movw %ax, %fs
    # movw %ax, %ss
    # Linux/x86 64-bit boot protocol boot_params is in %rsi, the second paramter of the System V ABI.
    movq %rsi, %rdi
    movq $rust64_start, %rbx
    jmpq *%rbx
