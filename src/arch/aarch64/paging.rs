use core::ops::RangeInclusive;

use cortex_a::{asm::barrier, registers::*};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

use super::{layout::KernelAddrSpace, translation_table::TranslationTable};

#[derive(Debug)]
pub enum MmuEnableError {
    AlreadyEnabled,
    Other(&'static str),
}

pub mod interface {
    use super::*;

    pub trait Mmu {
        unsafe fn enable_mmu_and_caching(&self) -> Result<(), MmuEnableError>;

        fn is_enabled(&self) -> bool;
    }
}

pub struct TranslationGranule<const GRANULE_SIZE: usize>;

pub struct AddressSpace<const AS_SIZE: usize>;

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum Translation {
    Identity,
    Offset(usize),
}

#[derive(Copy, Clone)]
pub enum MemAttributes {
    CacheableDRAM,
    Device,
}

#[derive(Copy, Clone)]
pub enum AccessPermissions {
    ReadOnly,
    ReadWrite,
}

#[derive(Copy, Clone)]
pub struct AttributeFields {
    pub mem_attributes: MemAttributes,
    pub acc_perms: AccessPermissions,
    pub execute_never: bool,
}

pub struct TranslationDescriptor {
    pub name: &'static str,
    pub virtual_range: RangeInclusive<usize>,
    pub physical_range_translation: Translation,
    pub attribute_fields: AttributeFields,
}

pub struct KernelVirtualLayout<const NUM_SPECIAL_RANGES: usize> {
    max_virt_addr_inclusive: usize,
    inner: [TranslationDescriptor; NUM_SPECIAL_RANGES],
}

impl<const GRANULE_SIZE: usize> TranslationGranule<GRANULE_SIZE> {
    pub const SIZE: usize = Self::size_checked();
    pub const SHIFT: usize = Self::SIZE.trailing_zeros() as usize;
    const fn size_checked() -> usize {
        assert!(GRANULE_SIZE.is_power_of_two());

        GRANULE_SIZE
    }
}

impl<const AS_SIZE: usize> AddressSpace<AS_SIZE> {
    pub const SIZE: usize = Self::size_checked();
    pub const SIZE_SHIFT: usize = Self::SIZE.trailing_zeros() as usize;

    const fn size_checked() -> usize {
        assert!(AS_SIZE.is_power_of_two());

        Self::arch_address_space_size_sanity_checks();

        AS_SIZE
    }
}

impl Default for AttributeFields {
    fn default() -> AttributeFields {
        AttributeFields {
            mem_attributes: MemAttributes::CacheableDRAM,
            acc_perms: AccessPermissions::ReadWrite,
            execute_never: true,
        }
    }
}

impl<const NUM_SPECIAL_RANGES: usize> KernelVirtualLayout<{ NUM_SPECIAL_RANGES }> {
    pub const fn new(max: usize, layout: [TranslationDescriptor; NUM_SPECIAL_RANGES]) -> Self {
        Self {
            max_virt_addr_inclusive: max,
            inner: layout,
        }
    }

    pub fn virt_addr_properties(
        &self,
        virt_addr: usize,
    ) -> Result<(usize, AttributeFields), &'static str> {
        if virt_addr > self.max_virt_addr_inclusive {
            return Err("Address out of range");
        }

        for i in self.inner.iter() {
            if i.virtual_range.contains(&virt_addr) {
                let output_addr = match i.physical_range_translation {
                    Translation::Identity => virt_addr,
                    Translation::Offset(a) => a + (virt_addr - (i.virtual_range).start()),
                };

                return Ok((output_addr, i.attribute_fields));
            }
        }

        Ok((virt_addr, AttributeFields::default()))
    }
}

struct MemoryManagementUnit;

pub type Granule512MiB = TranslationGranule<{ 512 * 1024 * 1024 }>;
pub type Granule64KiB = TranslationGranule<{ 64 * 1024 }>;

pub mod mair {
    pub const DEVICE: u64 = 0;
    pub const NORMAL: u64 = 1;
}

static mut KERNEL_TABLES: TranslationTable = TranslationTable::new();

static MMU: MemoryManagementUnit = MemoryManagementUnit;

impl<const AS_SIZE: usize> AddressSpace<AS_SIZE> {
    pub const fn arch_address_space_size_sanity_checks() {
        assert!((AS_SIZE % Granule512MiB::SIZE) == 0);

        assert!(AS_SIZE <= (1 << 48));
    }
}

impl MemoryManagementUnit {
    fn setup_mair(&self) {
        MAIR_EL1.write(
            MAIR_EL1::Attr1_Normal_Outer::WriteBack_NonTransient_ReadWriteAlloc
                + MAIR_EL1::Attr1_Normal_Inner::WriteBack_NonTransient_ReadWriteAlloc
                + MAIR_EL1::Attr0_Device::nonGathering_nonReordering_EarlyWriteAck,
        );
    }

    fn configure_translation_control(&self) {
        let t0sz = (64 - KernelAddrSpace::SIZE_SHIFT) as u64;

        TCR_EL1.write(
            TCR_EL1::TBI0::Used
                + TCR_EL1::IPS::Bits_40
                + TCR_EL1::TG0::KiB_64
                + TCR_EL1::SH0::Inner
                + TCR_EL1::ORGN0::WriteBack_ReadAlloc_WriteAlloc_Cacheable
                + TCR_EL1::IRGN0::WriteBack_ReadAlloc_WriteAlloc_Cacheable
                + TCR_EL1::EPD0::EnableTTBR0Walks
                + TCR_EL1::A1::TTBR0
                + TCR_EL1::T0SZ.val(t0sz)
                + TCR_EL1::EPD1::DisableTTBR1Walks,
        );
    }
}

pub fn mmu() -> &'static impl interface::Mmu {
    &MMU
}

impl interface::Mmu for MemoryManagementUnit {
    unsafe fn enable_mmu_and_caching(&self) -> Result<(), MmuEnableError> {
        if self.is_enabled() {
            return Err(MmuEnableError::AlreadyEnabled);
        }

        // Fail early if translation granule is not supported.
        if !ID_AA64MMFR0_EL1.matches_all(ID_AA64MMFR0_EL1::TGran64::Supported) {
            return Err(MmuEnableError::Other(
                "Translation granule not supported in HW",
            ));
        }

        // Prepare the memory attribute indirection register.
        self.setup_mair();

        // Populate translation tables.
        KERNEL_TABLES
            .populate_tt_entries()
            .map_err(MmuEnableError::Other)?;

        // Set the "Translation Table Base Register".
        TTBR0_EL1.set_baddr(KERNEL_TABLES.phys_base_address());

        self.configure_translation_control();

        // Switch the MMU on.
        //
        // First, force all previous changes to be seen before the MMU is enabled.
        barrier::isb(barrier::SY);

        // Enable the MMU and turn on data and instruction caching.
        SCTLR_EL1.modify(SCTLR_EL1::M::Enable + SCTLR_EL1::C::Cacheable + SCTLR_EL1::I::Cacheable);

        // Force MMU init to complete before next instruction.
        barrier::isb(barrier::SY);

        Ok(())
    }

    #[inline(always)]
    fn is_enabled(&self) -> bool {
        SCTLR_EL1.matches_all(SCTLR_EL1::M::Enable)
    }
}
