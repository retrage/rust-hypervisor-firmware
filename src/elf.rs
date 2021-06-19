use core::{mem::size_of, slice::from_raw_parts};
use goblin::elf64::{dynamic::*, header::*, program_header::*, reloc::*};

pub fn get_entry(start: u64) -> u64 {
    let header = unsafe { &*(start as *const Header) };
    if header.e_machine != EM_X86_64 || header.e_type != ET_DYN {
        panic!("Unsupported ELF binary: {:?}", header);
    }
    start + header.e_entry
}

pub fn relocate(from: u64, to: u64) -> Result<(), ()> {
    let header = unsafe { &*(from as *const Header) };
    if header.e_machine != EM_X86_64 || header.e_type != ET_DYN {
        panic!("Unsupported ELF binary: {:?}", header);
    }
    let ph_addr = (from + header.e_phoff) as *const ProgramHeader;
    let ph_size = header.e_phnum as usize;
    let program_headers = unsafe { from_raw_parts(ph_addr, ph_size) };
    for ph in program_headers.iter() {
        if ph.p_type != PT_DYNAMIC {
            continue;
        }
        let dyn_addr = (from + ph.p_offset) as *const Dyn;
        let dyn_size = (ph.p_filesz as usize) / size_of::<Dyn>();
        let dyns = unsafe { from_raw_parts(dyn_addr, dyn_size) };
        let rela = dyns.iter().find(|&d| d.d_tag == DT_RELA).ok_or(())?;
        let relasz = dyns.iter().find(|&d| d.d_tag == DT_RELASZ).ok_or(())?;
        let rela_addr = (from + rela.d_val) as *const Rela;
        let rela_size = (relasz.d_val as usize) / size_of::<Rela>();
        let relas = unsafe { from_raw_parts(rela_addr, rela_size) };
        for r in relas.iter() {
            let addr = (from + r.r_offset) as *mut u64;
            let r_type = (r.r_info & 0xffffffff) as u32;
            match r_type {
                R_X86_64_RELATIVE => unsafe {
                    *addr = (to as i64 + r.r_addend) as u64;
                },
                _ => log!("Unknown relocation type: {}", r_type),
            }
        }
    }
    Ok(())
}
