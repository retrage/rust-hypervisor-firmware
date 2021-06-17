
use core::{
    mem::size_of,
    slice::from_raw_parts,
};
use goblin::elf64::{
    header::*,
    program_header::*,
    section_header::*,
    dynamic::*,
    reloc::*,
};

#[allow(dead_code)]
fn validate_header(header: &Header) -> bool {
    if header.e_machine != EM_X86_64 {
        return false;
    }
    match header.e_type {
        ET_EXEC | ET_DYN => true,
        _ => false,
    }
}

#[allow(dead_code)]
pub fn get_entry(start: u64, header: &Header) -> Option<u64> {
    if !validate_header(header) {
        return None;
    }

    match header.e_type {
        ET_EXEC => Some(header.e_entry),
        ET_DYN => Some(start + header.e_entry),
        _ => None,
    }
}

#[allow(dead_code)]
pub fn find_section(start: u64, header: &Header, section: &str) -> Option<u64> {
    let sh_addr = (start + header.e_shoff) as *const SectionHeader;
    let sh_size = header.e_shnum as usize;
    let section_headers = unsafe { from_raw_parts(sh_addr, sh_size) };

    let shstrndx = header.e_shstrndx as usize;
    let shstr_addr = start + section_headers[shstrndx].sh_offset;

    for sh in section_headers.iter() {
        let addr = shstr_addr + sh.sh_name as u64;
        let name = unsafe { crate::common::from_cstring(addr) };
        if crate::common::ascii_strip(name) == section {
            return Some(start + sh.sh_offset);
        }
    }

    None
}

pub fn relocate(header: &Header, from: u64, to: u64) -> Result<(), ()> {
    let ph_addr = (from + header.e_phoff) as *const ProgramHeader;
    let ph_size = header.e_phnum as usize;
    let program_headers = unsafe { from_raw_parts(ph_addr, ph_size)};
    for ph in program_headers.iter() {
        if ph.p_type != PT_DYNAMIC {
            continue;
        }
        let dyn_addr = (from + ph.p_offset) as *const Dyn;
        let dyn_size = (ph.p_filesz as usize) / size_of::<Dyn>();
        let dyns = unsafe { from_raw_parts(dyn_addr, dyn_size) };
        let rela = dyns.into_iter().find(|&d| d.d_tag == DT_RELA).ok_or(())?;
        let relasz = dyns.into_iter().find(|&d| d.d_tag == DT_RELASZ).ok_or(())?;
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
                _ => (),
            }
        }
    }
    Ok(())
}
