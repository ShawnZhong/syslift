mod model;
mod parse;
mod policy;
mod process;
mod spec;

use std::env;
use std::ffi::c_void;
use std::ptr;

use vstd::prelude::*;

use crate::model::*;

const PROT_NONE: i32 = 0;
const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const PROT_EXEC: i32 = 4;

const MAP_PRIVATE: i32 = 0x02;
const MAP_FIXED: i32 = 0x10;
const MAP_ANONYMOUS: i32 = 0x20;
const MAP_STACK: i32 = 0x20000;
const MAP_FIXED_NOREPLACE: i32 = 0x100000;

const _SC_PAGESIZE: i32 = 30;

const STACK_SIZE: usize = 1 << 20;
const ARG0_BYTES: &[u8; 7] = b"loaded\0";

unsafe extern "C" {
    fn mmap(addr: *mut c_void, length: usize, prot: i32, flags: i32, fd: i32, offset: isize) -> *mut c_void;
    fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    fn sysconf(name: i32) -> isize;
}

fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

fn align_up(value: usize, align: usize) -> usize {
    let add = align.checked_sub(1).unwrap_or_else(|| panic!("invalid alignment"));
    let v = value.checked_add(add).unwrap_or_else(|| panic!("alignment overflow"));
    align_down(v, align)
}

fn u64_to_usize(value: u64, name: &str) -> usize {
    usize::try_from(value).unwrap_or_else(|_| panic!("{} does not fit usize", name))
}

fn map_failed(ptr: *mut c_void) -> bool {
    (ptr as isize) == -1
}

fn segment_page_range(seg: &Segment, page_size: usize) -> (usize, usize) {
    let seg_start = u64_to_usize(seg.vaddr, "segment vaddr");
    let seg_size = u64_to_usize(seg.mem_size, "segment mem_size");
    let seg_end = seg_start.checked_add(seg_size).unwrap_or_else(|| panic!("segment range overflow"));
    let map_start = align_down(seg_start, page_size);
    let map_end = align_up(seg_end, page_size);
    (map_start, map_end)
}

fn flags_to_prot(flags: u32) -> i32 {
    let mut prot: i32 = 0;
    if (flags & 0x4) != 0 {
        prot |= PROT_READ;
    }
    if (flags & 0x2) != 0 {
        prot |= PROT_WRITE;
    }
    if (flags & PF_X) != 0 {
        prot |= PROT_EXEC;
    }
    prot
}

unsafe fn reserve_image_span(program: &Program, page_size: usize) -> (usize, usize) {
    if program.segments.is_empty() {
        panic!("runtime: no PT_LOAD segments");
    }

    let mut min_page: usize = usize::MAX;
    let mut max_page: usize = 0;
    for seg in &program.segments {
        let (start, end) = segment_page_range(seg, page_size);
        if start < min_page {
            min_page = start;
        }
        if end > max_page {
            max_page = end;
        }
    }
    if min_page >= max_page {
        panic!("runtime: invalid image span");
    }

    let span = max_page - min_page;
    let base = unsafe {
        mmap(
            min_page as *mut c_void,
            span,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if !map_failed(base) {
        return (min_page, span);
    }

    let base_fixed = unsafe {
        mmap(
            min_page as *mut c_void,
            span,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1,
            0,
        )
    };
    if map_failed(base_fixed) {
        panic!("runtime: mmap image reservation failed");
    }

    (min_page, span)
}

unsafe fn map_program_image(program: &Program, page_size: usize) {
    let (image_start, image_span) = unsafe { reserve_image_span(program, page_size) };

    for seg in &program.segments {
        let seg_start = u64_to_usize(seg.vaddr, "segment vaddr");
        let seg_size = u64_to_usize(seg.mem_size, "segment mem_size");
        if seg.data.len() > seg_size {
            panic!("runtime: memsz smaller than filesz");
        }

        let dst = seg_start as *mut u8;
        if !seg.data.is_empty() {
            unsafe { ptr::copy_nonoverlapping(seg.data.as_ptr(), dst, seg.data.len()) };
        }
        if seg_size > seg.data.len() {
            unsafe { ptr::write_bytes(dst.add(seg.data.len()), 0, seg_size - seg.data.len()) };
        }
    }

    let rc_none = unsafe { mprotect(image_start as *mut c_void, image_span, PROT_NONE) };
    if rc_none != 0 {
        panic!("runtime: mprotect(PROT_NONE) failed");
    }

    for seg in &program.segments {
        let (map_start, map_end) = segment_page_range(seg, page_size);
        let prot = flags_to_prot(seg.flags);
        let rc = unsafe { mprotect(map_start as *mut c_void, map_end - map_start, prot) };
        if rc != 0 {
            panic!("runtime: segment mprotect failed");
        }
    }
}

unsafe fn push_u64(sp: &mut usize, value: u64) {
    *sp = sp.checked_sub(8).unwrap_or_else(|| panic!("runtime stack overflow"));
    unsafe { *(*sp as *mut u64) = value };
}

unsafe fn setup_runtime_stack() -> usize {
    let mem = unsafe {
        mmap(
            ptr::null_mut(),
            STACK_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
            -1,
            0,
        )
    };
    if map_failed(mem) {
        panic!("runtime: failed to allocate runtime stack");
    }

    let mut sp = (mem as usize).checked_add(STACK_SIZE).unwrap_or_else(|| panic!("runtime stack overflow"));
    sp &= !0x0fusize;

    let argc: usize = 1;
    if (argc % 2) == 0 {
        sp = sp.checked_sub(8).unwrap_or_else(|| panic!("runtime stack overflow"));
    }

    unsafe { push_u64(&mut sp, 0) }; // auxv value
    unsafe { push_u64(&mut sp, 0) }; // auxv type (AT_NULL)
    unsafe { push_u64(&mut sp, 0) }; // envp terminator
    unsafe { push_u64(&mut sp, 0) }; // argv terminator
    unsafe { push_u64(&mut sp, ARG0_BYTES.as_ptr() as u64) };
    unsafe { push_u64(&mut sp, argc as u64) };
    sp
}

#[cfg(target_arch = "x86_64")]
unsafe fn jump_to_entry(entry_pc: usize, entry_sp: usize) -> ! {
    unsafe {
        core::arch::asm!(
            "mov rsp, {sp}",
            "xor rbp, rbp",
            "jmp {entry}",
            sp = in(reg) entry_sp,
            entry = in(reg) entry_pc,
            options(noreturn)
        );
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn jump_to_entry(_entry_pc: usize, _entry_sp: usize) -> ! {
    panic!("runtime: unsupported host arch");
}

unsafe fn runtime_exec_impl(program: &Program, _plan: &Vec<PatchDecision>) -> ! {
    let page_size_raw = unsafe { sysconf(_SC_PAGESIZE) };
    if page_size_raw <= 0 {
        panic!("runtime: failed to query page size");
    }
    let page_size = page_size_raw as usize;
    if page_size == 0 || (page_size & (page_size - 1)) != 0 {
        panic!("runtime: invalid page size");
    }

    unsafe { map_program_image(program, page_size) };
    let entry_sp = unsafe { setup_runtime_stack() };
    let entry_pc = u64_to_usize(program.entry, "entry");

    println!("trusted runtime: jump entry=0x{:x} sp=0x{:x}", entry_pc, entry_sp);
    unsafe { jump_to_entry(entry_pc, entry_sp) }
}

verus! {

// Trusted boundary: host filesystem read.
#[verifier::external_body]
pub fn trusted_read_file(path: &String) -> (r: LoaderResult<Vec<u8>>) {
    match std::fs::read(path) {
        Ok(v) => Ok(v),
        Err(_) => Err("failed to read ELF file"),
    }
}

// Trusted boundary: host mapping + jump to entry.
#[verifier::external_body]
pub fn trusted_runtime_exec(program: &Program, plan: &Vec<PatchDecision>) {
    unsafe { runtime_exec_impl(program, plan) };
}

} // verus!


fn parse_allow_csv(arg: &str) -> Vec<u64> {
    if arg.is_empty() {
        panic!("allow list cannot be empty");
    }

    let mut allow: Vec<u64> = Vec::new();
    for token in arg.split(',') {
        if token.is_empty() {
            panic!("invalid allow list: empty token");
        }
        match token.parse::<u64>() {
            Ok(v) => allow.push(v),
            Err(_) => panic!("invalid syscall number in allow list: {}", token),
        }
    }
    allow
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        panic!("usage: loader_verus <elf-file> <allow-csv>; example: loader_verus build/getpid 60,39");
    }

    let elf_path = args[1].clone();
    let allow = parse_allow_csv(&args[2]);

    let bytes = match trusted_read_file(&elf_path) {
        Ok(v) => v,
        Err(e) => panic!("{}: {}", e, elf_path),
    };

    let program = match parse::parse_program(&bytes) {
        Ok(v) => v,
        Err(e) => panic!("parse failed: {}", e),
    };

    let (patched_program, plan) = match process::build_to_be_mapped_program(program, &allow) {
        Ok(v) => v,
        Err(e) => panic!("processing failed: {}", e),
    };

    let mut patched_sites: usize = 0;
    let mut i: usize = 0;
    while i < plan.len() {
        if plan[i].should_patch {
            patched_sites += 1;
        }
        i += 1;
    }

    println!(
        "loader_verus ok: entry=0x{:x} segments={} sites={} patched={}",
        patched_program.entry,
        patched_program.segments.len(),
        patched_program.syscall_sites.len(),
        patched_sites
    );

    trusted_runtime_exec(&patched_program, &plan);
}
