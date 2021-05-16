ENTRY(main)

SECTIONS
{
  . += SIZEOF_HEADERS;

  .rodata : { *(.rodata .rodata.*) }
  .text   : { *(.text .text.*)     }
  .data   : { *(.data .data.*)     }
  .efi_rs : { *(.efi_rs*)          }
  .bss    : { *(.bss .bss.*)       }

  /* Strip symbols from the output binary (comment out to get symbols) */
  /*
  /DISCARD/ : {
    *(.symtab)
    *(.strtab)
  }
  */
}
