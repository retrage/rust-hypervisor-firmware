ENTRY(aarch64_start)

/* For booting as a QEMU kernel image */
ram_min = 0x40080000;

SECTIONS
{
  /* Mapping the program headers and note into RAM makes the file smaller. */
  . = ram_min;

  /* These sections are mapped into RAM from the file. Omitting :ram from
     later sections avoids emitting empty sections in the final binary.       */
  text_start = .;
  .text.boot : { *(.text.boot) }
  .text   : { *(.text .text.*)     }
  text_end = .;
  .data   : { *(.data .data.*)     }
  .note : { *(.note) } :note :ram
  .rodata : { *(.rodata .rodata.*) } :ram

  /* The BSS section isn't mapped from file data. It is just zeroed in RAM. */
  .bss : {
    bss_start = .;
    *(.bss .bss.*)
    bss_size = . - bss_start;
  }

  /* Our stack grows down and is page-aligned. TODO: Add stack guard pages. */
  .stack (NOLOAD) : ALIGN(16) { . += 128K; }
  stack_start = .;

  /* Strip symbols from the output binary (comment out to get symbols) */
  /DISCARD/ : {
    *(.symtab)
    *(.strtab)
  }
}
