ENTRY(main)

SECTIONS
{
  start = .;
  . += SIZEOF_HEADERS;

  .rodata : { *(.rodata .rodata.*) }
  .text   : { *(.text .text.*)     }
  .data   : { *(.data .data.*) *(.bss .bss.*) }
  end = .;

  /* Strip symbols from the output binary (comment out to get symbols) */
  /DISCARD/ : {
    *(.symtab)
    *(.strtab)
  }
}
