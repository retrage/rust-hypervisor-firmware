
use core::{
    mem::size_of,
    slice::from_raw_parts,
};
use goblin::elf64::{
    header::*,
    program_header::*,
    dynamic::*,
    reloc::*,
};

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
        let rela = dyns.iter().find(|&d| d.d_tag == DT_RELA).ok_or(())?;
        let relasz = dyns.iter().find(|&d| d.d_tag == DT_RELASZ).ok_or(())?;
        let rela_addr = (from + rela.d_val) as *const Rela;
        let rela_size = (relasz.d_val as usize) / size_of::<Rela>();
        let relas = unsafe { from_raw_parts(rela_addr, rela_size) };
        for r in relas.iter() {
            let addr = (from + r.r_offset) as *mut u64;
            let r_type = (r.r_info & 0xffffffff) as u32;
            if r_type == R_X86_64_RELATIVE {
                unsafe {
                    *addr = (to as i64 + r.r_addend) as u64;
                }
            }
        }
    }
    Ok(())
}
