// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2018-2022 Andre Richter <andre.o.richter@gmail.com>

use core::{arch::global_asm, cell::UnsafeCell, fmt};

use aarch64_cpu::{asm::barrier, registers::*};
use tock_registers::{
    interfaces::{Readable, Writeable},
    registers::InMemoryRegister,
};

#[repr(transparent)]
struct SpsrEL1(InMemoryRegister<u64, SPSR_EL1::Register>);
struct EsrEL1(InMemoryRegister<u64, ESR_EL1::Register>);

global_asm!(include_str!("exception.s"));

impl fmt::Display for SpsrEL1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "SPSR_EL1: {:#010x}", self.0.get())?;

        let to_flag_str = |x| -> _ {
            if x {
                "Set"
            } else {
                "Not set"
            }
        };

        writeln!(f, "  Flags:")?;
        writeln!(f, "    (N): {}", to_flag_str(self.0.is_set(SPSR_EL1::N)))?;
        writeln!(f, "    (Z): {}", to_flag_str(self.0.is_set(SPSR_EL1::Z)))?;
        writeln!(f, "    (C): {}", to_flag_str(self.0.is_set(SPSR_EL1::C)))?;
        writeln!(f, "    (V): {}", to_flag_str(self.0.is_set(SPSR_EL1::V)))?;

        let to_mask_str = |x| -> _ {
            if x {
                "Masked"
            } else {
                "Unmasked"
            }
        };

        writeln!(f, "  Exception handling state:")?;
        writeln!(f, "    (D): {}", to_mask_str(self.0.is_set(SPSR_EL1::D)))?;
        writeln!(f, "    (A): {}", to_mask_str(self.0.is_set(SPSR_EL1::A)))?;
        writeln!(f, "    (I): {}", to_mask_str(self.0.is_set(SPSR_EL1::I)))?;
        writeln!(f, "    (F): {}", to_mask_str(self.0.is_set(SPSR_EL1::F)))?;

        write!(
            f,
            "  Illegal Excetion State (IL): {}",
            to_flag_str(self.0.is_set(SPSR_EL1::IL))
        )
    }
}

impl EsrEL1 {
    #[inline(always)]
    fn exception_class(&self) -> Option<ESR_EL1::EC::Value> {
        self.0.read_as_enum(ESR_EL1::EC)
    }
}

impl fmt::Display for EsrEL1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ESR_EL1: {:#010x}", self.0.get())?;

        write!(f, "  Exception Class (EC): {:#x}", self.0.read(ESR_EL1::EC))?;

        let ec_translation = match self.exception_class() {
            Some(ESR_EL1::EC::Value::DataAbortCurrentEL) => "Data Abort, current EL",
            _ => "N/A",
        };
        writeln!(f, " - {}", ec_translation)?;

        write!(f, "  (ISS): {:#x}", self.0.read(ESR_EL1::ISS))
    }
}

#[repr(C)]
struct ExceptionContext {
    gpr: [u64; 30],
    lr: u64,
    elr_el1: u64,
    spsr_el1: SpsrEL1,
    esr_el1: EsrEL1,
}

impl ExceptionContext {
    #[inline(always)]
    fn exception_class(&self) -> Option<ESR_EL1::EC::Value> {
        self.esr_el1.exception_class()
    }

    #[inline(always)]
    fn fault_address_valid(&self) -> bool {
        use ESR_EL1::EC::Value::*;

        match self.exception_class() {
            None => false,
            Some(ec) => matches!(
                ec,
                InstrAbortLowerEL
                    | InstrAbortCurrentEL
                    | PCAlignmentFault
                    | DataAbortLowerEL
                    | DataAbortCurrentEL
                    | WatchpointLowerEL
                    | WatchpointCurrentEL
            ),
        }
    }
}

impl fmt::Display for ExceptionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.esr_el1)?;

        if self.fault_address_valid() {
            writeln!(f, "FAR_EL1: {:#018x}", FAR_EL1.get() as usize)?;
        }

        writeln!(f, "{}", self.spsr_el1)?;
        writeln!(f, "ELR_EL1: {:#018x}", self.elr_el1)?;
        writeln!(f)?;

        let alternating = |x| -> _ {
            if x % 2 == 0 {
                "  "
            } else {
                "\n"
            }
        };

        for (i, reg) in self.gpr.iter().enumerate() {
            write!(f, "x{: <2}: {: >#018x}{}", i, reg, alternating(i))?;
        }
        write!(f, "lr : {:#018x}", self.lr)
    }
}

fn default_exception_handler(exc: &ExceptionContext) {
    panic!(
        "CPU Exception!\n\n
        {}",
        exc
    );
}

#[no_mangle]
extern "C" fn current_sp0_sync(_e: &mut ExceptionContext) {
    panic!("Shoud not be here. Use of SP_EL0 in EL1 is not supported.");
}

#[no_mangle]
extern "C" fn current_sp0_irq(_e: &mut ExceptionContext) {
    panic!("Shoud not be here. Use of SP_EL0 in EL1 is not supported.");
}

#[no_mangle]
extern "C" fn current_sp0_serror(_e: &mut ExceptionContext) {
    panic!("Shoud not be here. Use of SP_EL0 in EL1 is not supported.");
}

#[no_mangle]
extern "C" fn current_spx_sync(e: &mut ExceptionContext) {
    default_exception_handler(e);
}
#[no_mangle]
extern "C" fn current_spx_irq(e: &mut ExceptionContext) {
    default_exception_handler(e);
}
#[no_mangle]
extern "C" fn current_spx_serror(e: &mut ExceptionContext) {
    default_exception_handler(e);
}

#[no_mangle]
extern "C" fn lower_aarch64_sync(e: &mut ExceptionContext) {
    default_exception_handler(e);
}

#[no_mangle]
extern "C" fn lower_aarch64_irq(e: &mut ExceptionContext) {
    default_exception_handler(e);
}

#[no_mangle]
extern "C" fn lower_aarch64_serror(e: &mut ExceptionContext) {
    default_exception_handler(e);
}

#[no_mangle]
extern "C" fn lower_aarch32_sync(e: &mut ExceptionContext) {
    default_exception_handler(e);
}

#[no_mangle]
extern "C" fn lower_aarch32_irq(e: &mut ExceptionContext) {
    default_exception_handler(e);
}

#[no_mangle]
extern "C" fn lower_aarch32_serror(e: &mut ExceptionContext) {
    default_exception_handler(e);
}

pub fn setup() {
    extern "Rust" {
        static __exception_vector_start: UnsafeCell<()>;
    }

    unsafe {
        VBAR_EL1.set(__exception_vector_start.get() as u64);

        barrier::isb(barrier::SY);
    }
}
