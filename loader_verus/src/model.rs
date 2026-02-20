use vstd::prelude::*;

verus! {

pub type LoaderResult<T> = Result<T, &'static str>;

pub const ELF64_HDR_SIZE: usize = 64;
pub const ELF64_PHDR_SIZE: usize = 56;
pub const ELF64_SHDR_SIZE: usize = 64;
pub const PT_LOAD: u32 = 1;
pub const ET_EXEC: u16 = 2;
pub const EM_X86_64: u16 = 62;
pub const PF_X: u32 = 0x1;
pub const SYSLIFT_SITE_SIZE: usize = 68;
pub const SYSLIFT_VALUE_COUNT: usize = 7;
pub const SYSLIFT_NR_BIT: u32 = 1;
pub const X86_SYSCALL_B0: u8 = 0x0f;
pub const X86_SYSCALL_B1: u8 = 0x05;
pub const X86_PATCH_SLOT_SIZE: usize = 8;

#[derive(Debug)]
pub struct Segment {
    pub vaddr: u64,
    pub mem_size: u64,
    pub file_off: u64,
    pub file_size: u64,
    pub flags: u32,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct SyscallSite {
    pub site_vaddr: u64,
    pub known_mask: u32,
    pub values: [u64; SYSLIFT_VALUE_COUNT],
}

#[derive(Debug)]
pub struct Program {
    pub entry: u64,
    pub segments: Vec<Segment>,
    pub syscall_sites: Vec<SyscallSite>,
}

#[derive(Debug)]
pub struct PatchDecision {
    pub site_vaddr: u64,
    pub sys_nr: u64,
    pub should_patch: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ElfHeaderInfo {
    pub(crate) entry: u64,
    pub(crate) phoff: usize,
    pub(crate) phentsize: usize,
    pub(crate) phnum: usize,
    pub(crate) shoff: usize,
    pub(crate) shentsize: usize,
    pub(crate) shnum: usize,
    pub(crate) shstrndx: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SectionInfo {
    pub(crate) off: usize,
    pub(crate) size: usize,
}

} // verus!
