ENTRY(main) /* coreboot uses the ELF entrypoint */

PHDRS
{
  ram  PT_LOAD FILEHDR PHDRS ;
}

/* Loaders like to put stuff in low memory (< 1M), so we don't use it. */
ram_min = 4M;

SECTIONS
{
  /* Mapping the program headers and note into RAM makes the file smaller. */
  . = ram_min;
  . += SIZEOF_HEADERS;

  /* These sections are mapped into RAM from the file. Omitting :ram from
     later sections avoids emitting empty sections in the final binary.       */
  .rodata : { *(.rodata .rodata.*) } :ram
  .text   : { *(.text .text.*)     }
  .data   : { *(.data .data.*)     }
  .efi_rs : { *(.efi_rs*)          }
  .bss    : { *(.bss .bss.*)       }

  /* Strip symbols from the output binary (comment out to get symbols) */
  /DISCARD/ : {
    *(.symtab)
    *(.strtab)
  }
}
