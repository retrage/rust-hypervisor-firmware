.section .text32, "ax"
.global ram32_start
.code32

ram32_start:
    # Stash the PVH start_info struct in %rdi.
    movl %ebx, %edi

setup_page_tables:
    # First L2 entry identity maps [0, 1 GiB)
    push %edi
    movl $L2_TABLES, %ecx
    xor  %eax, %eax
    xor  %edx, %edx
    lea  0x0(%esi),%esi
    lea  0x0(%edi,%eiz,1),%edi
1:
    movl %eax, %ebx
    movl %edx, 0x4(%ecx)
    orb  $0b10000011, %bl # huge (bit 7), writable (bit 1), present (bit 0)
    addl $0x200000, %eax
    adc  $0x0, %edx
    movl %ebx, (%ecx)
    movl %eax, %ebx
    xor  $0x40000000, %ebx
    movl %edx, %esi
    addl $0x8, %ecx
    orl  %ebx, %esi
    jne  1b
    pop  %edi

    # First L3 entry points to L2 table
    movl $L2_TABLES, %eax
    orb  $0b00000011, %al # writable (bit 1), present (bit 0)
    movl %eax, (L3_TABLE)
    # First L4 entry points to L3 table
    movl $L3_TABLE, %eax
    orb  $0b00000011, %al # writable (bit 1), present (bit 0)
    movl %eax, (L4_TABLE)

enable_paging:
    # Load page table root into CR3
    movl $L4_TABLE, %eax
    movl %eax, %cr3

    # Set CR4.PAE (Physical Address Extension)
    movl %cr4, %eax
    orb  $0b00100000, %al # Set bit 5
    movl %eax, %cr4
    # Set EFER.LME (Long Mode Enable)
    movl $0xC0000080, %ecx
    rdmsr
    orb  $0b00000001, %ah # Set bit 8
    wrmsr
    # Set CRO.PG (Paging)
    movl %cr0, %eax
    orl  $(1 << 31), %eax
    movl %eax, %cr0

jump_to_64bit:
    # We are now in 32-bit compatibility mode. To enter 64-bit mode, we need to
    # load a 64-bit code segment into our GDT.
    lgdtl GDT64_PTR
    # Initialize the stack pointer (Rust code always uses the stack)
    movl $stack_start, %esp
    # Set segment registers to a 64-bit segment.
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %gs
    movw %ax, %fs
    movw %ax, %ss
    # Set CS to a 64-bit segment and jump to 64-bit Rust code.
    # PVH start_info is in %rdi, the first paramter of the System V ABI.
    ljmpl $0x08, $rust64_start
