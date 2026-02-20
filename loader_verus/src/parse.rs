use vstd::prelude::*;

use crate::model::*;
use crate::spec::{exec_pair_non_overlapping, exec_segments_non_overlapping_segments, phase_parsed_ok};

verus! {

fn checked_add(a: usize, b: usize) -> (r: LoaderResult<usize>) {
    match a.checked_add(b) {
        Some(v) => Ok(v),
        None => Err("integer overflow"),
    }
}

fn checked_mul(a: usize, b: usize) -> (r: LoaderResult<usize>) {
    match a.checked_mul(b) {
        Some(v) => Ok(v),
        None => Err("integer overflow"),
    }
}

fn ensure_range(len: usize, off: usize, size: usize) -> (r: LoaderResult<()>) {
    if off > len {
        return Err("offset out of bounds");
    }
    if size > len - off {
        return Err("truncated input");
    }
    Ok(())
}

fn read_u8(bytes: &Vec<u8>, off: usize) -> (r: LoaderResult<u8>) {
    match bytes.get(off) {
        Some(v) => Ok(*v),
        None => Err("truncated input"),
    }
}

fn copy_range(bytes: &Vec<u8>, off: usize, size: usize) -> (r: LoaderResult<Vec<u8>>) {
    if let Err(e) = ensure_range(bytes.len(), off, size) {
        return Err(e);
    }

    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < size
        invariant
            i <= size,
            out.len() == i,
        decreases size - i,
    {
        let at = match checked_add(off, i) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let b = match read_u8(bytes, at) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        out.push(b);
        i = i + 1;
    }

    Ok(out)
}

fn u64_to_usize(value: u64) -> (r: LoaderResult<usize>) {
    if value > usize::MAX as u64 {
        return Err("value does not fit usize");
    }
    Ok(value as usize)
}

fn parse_u16_le(bytes: &Vec<u8>, off: usize) -> (r: LoaderResult<u16>) {
    let off1 = match checked_add(off, 1) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let b0 = match read_u8(bytes, off) {
        Ok(v) => v as u16,
        Err(e) => return Err(e),
    };
    let b1 = match read_u8(bytes, off1) {
        Ok(v) => v as u16,
        Err(e) => return Err(e),
    };
    Ok(b0 | (b1 << 8))
}

fn parse_u32_le(bytes: &Vec<u8>, off: usize) -> (r: LoaderResult<u32>) {
    let off1 = match checked_add(off, 1) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let off2 = match checked_add(off, 2) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let off3 = match checked_add(off, 3) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let b0 = match read_u8(bytes, off) {
        Ok(v) => v as u32,
        Err(e) => return Err(e),
    };
    let b1 = match read_u8(bytes, off1) {
        Ok(v) => v as u32,
        Err(e) => return Err(e),
    };
    let b2 = match read_u8(bytes, off2) {
        Ok(v) => v as u32,
        Err(e) => return Err(e),
    };
    let b3 = match read_u8(bytes, off3) {
        Ok(v) => v as u32,
        Err(e) => return Err(e),
    };
    Ok(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
}

fn parse_u64_le(bytes: &Vec<u8>, off: usize) -> (r: LoaderResult<u64>) {
    let off1 = match checked_add(off, 1) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let off2 = match checked_add(off, 2) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let off3 = match checked_add(off, 3) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let off4 = match checked_add(off, 4) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let off5 = match checked_add(off, 5) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let off6 = match checked_add(off, 6) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let off7 = match checked_add(off, 7) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let b0 = match read_u8(bytes, off) {
        Ok(v) => v as u64,
        Err(e) => return Err(e),
    };
    let b1 = match read_u8(bytes, off1) {
        Ok(v) => v as u64,
        Err(e) => return Err(e),
    };
    let b2 = match read_u8(bytes, off2) {
        Ok(v) => v as u64,
        Err(e) => return Err(e),
    };
    let b3 = match read_u8(bytes, off3) {
        Ok(v) => v as u64,
        Err(e) => return Err(e),
    };
    let b4 = match read_u8(bytes, off4) {
        Ok(v) => v as u64,
        Err(e) => return Err(e),
    };
    let b5 = match read_u8(bytes, off5) {
        Ok(v) => v as u64,
        Err(e) => return Err(e),
    };
    let b6 = match read_u8(bytes, off6) {
        Ok(v) => v as u64,
        Err(e) => return Err(e),
    };
    let b7 = match read_u8(bytes, off7) {
        Ok(v) => v as u64,
        Err(e) => return Err(e),
    };
    Ok(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56))
}

fn parse_elf_header(bytes: &Vec<u8>) -> (r: LoaderResult<ElfHeaderInfo>) {
    if let Err(e) = ensure_range(bytes.len(), 0, ELF64_HDR_SIZE) {
        return Err(e);
    }

    // ELF magic + ELF64 + little-endian
    let ident0 = match read_u8(bytes, 0) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let ident1 = match read_u8(bytes, 1) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let ident2 = match read_u8(bytes, 2) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let ident3 = match read_u8(bytes, 3) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    if ident0 != 0x7f || ident1 != 0x45 || ident2 != 0x4c || ident3 != 0x46 {
        return Err("unsupported ELF magic");
    }
    let ident4 = match read_u8(bytes, 4) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    if ident4 != 2 {
        return Err("unsupported ELF class (need ELF64)");
    }
    let ident5 = match read_u8(bytes, 5) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    if ident5 != 1 {
        return Err("unsupported ELF encoding (need little-endian)");
    }

    let e_type = match parse_u16_le(bytes, 16) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    if e_type != ET_EXEC {
        return Err("unsupported ELF type (need ET_EXEC)");
    }

    let e_machine = match parse_u16_le(bytes, 18) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    if e_machine != EM_X86_64 {
        return Err("unsupported ELF machine (need x86_64)");
    }

    let entry = match parse_u64_le(bytes, 24) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    let phoff_u64 = match parse_u64_le(bytes, 32) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let shoff_u64 = match parse_u64_le(bytes, 40) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    let phentsize = match parse_u16_le(bytes, 54) {
        Ok(v) => v as usize,
        Err(e) => return Err(e),
    };
    let phnum = match parse_u16_le(bytes, 56) {
        Ok(v) => v as usize,
        Err(e) => return Err(e),
    };
    let shentsize = match parse_u16_le(bytes, 58) {
        Ok(v) => v as usize,
        Err(e) => return Err(e),
    };
    let shnum = match parse_u16_le(bytes, 60) {
        Ok(v) => v as usize,
        Err(e) => return Err(e),
    };
    let shstrndx = match parse_u16_le(bytes, 62) {
        Ok(v) => v as usize,
        Err(e) => return Err(e),
    };

    if phnum == 0 {
        return Err("invalid program header table");
    }
    if shnum == 0 {
        return Err("invalid section header table");
    }
    if shstrndx >= shnum {
        return Err("invalid shstrndx");
    }
    if phentsize < ELF64_PHDR_SIZE {
        return Err("unsupported program header size");
    }
    if shentsize < ELF64_SHDR_SIZE {
        return Err("unsupported section header size");
    }

    let phoff = match u64_to_usize(phoff_u64) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let shoff = match u64_to_usize(shoff_u64) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    let ph_table_bytes = match checked_mul(phnum, phentsize) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let sh_table_bytes = match checked_mul(shnum, shentsize) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    if let Err(e) = ensure_range(bytes.len(), phoff, ph_table_bytes) {
        return Err(e);
    }
    if let Err(e) = ensure_range(bytes.len(), shoff, sh_table_bytes) {
        return Err(e);
    }

    Ok(ElfHeaderInfo { entry, phoff, phentsize, phnum, shoff, shentsize, shnum, shstrndx })
}

fn section_name_is_syslift(bytes: &Vec<u8>, strtab: SectionInfo, name_off: usize) -> (r: bool) {
    let target: [u8; 8] = [0x2e, 0x73, 0x79, 0x73, 0x6c, 0x69, 0x66, 0x74];

    if name_off >= strtab.size {
        return false;
    }

    let need = match checked_add(target.len(), 1) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if strtab.size - name_off < need {
        return false;
    }

    let mut i: usize = 0;
    while i < target.len()
        invariant
            i <= target.len(),
        decreases target.len() - i,
    {
        let rel = match checked_add(name_off, i) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let file_off = match checked_add(strtab.off, rel) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let b = match read_u8(bytes, file_off) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if b != target[i] {
            return false;
        }
        i = i + 1;
    }

    let nul_rel = match checked_add(name_off, target.len()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let nul_off = match checked_add(strtab.off, nul_rel) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let b = match read_u8(bytes, nul_off) {
        Ok(v) => v,
        Err(_) => return false,
    };
    b == 0
}

fn parse_segments(bytes: &Vec<u8>, hdr: &ElfHeaderInfo) -> (r: LoaderResult<Vec<Segment>>) {
    let mut segments: Vec<Segment> = Vec::new();

    let mut i: usize = 0;
    while i < hdr.phnum
        invariant
            i <= hdr.phnum,
        decreases hdr.phnum - i,
    {
        let row = match checked_mul(i, hdr.phentsize) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let phoff = match checked_add(hdr.phoff, row) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        let p_type_off = phoff;
        let p_type = match parse_u32_le(bytes, p_type_off) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if p_type != PT_LOAD {
            i = i + 1;
            continue;
        }

        let p_flags_off = match checked_add(phoff, 4) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let p_flags = match parse_u32_le(bytes, p_flags_off) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let p_offset_off = match checked_add(phoff, 8) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let p_offset = match parse_u64_le(bytes, p_offset_off) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let p_vaddr_off = match checked_add(phoff, 16) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let p_vaddr = match parse_u64_le(bytes, p_vaddr_off) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let p_filesz_off = match checked_add(phoff, 32) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let p_filesz = match parse_u64_le(bytes, p_filesz_off) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let p_memsz_off = match checked_add(phoff, 40) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let p_memsz = match parse_u64_le(bytes, p_memsz_off) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        if p_memsz == 0 {
            i = i + 1;
            continue;
        }
        if p_filesz > p_memsz {
            return Err("PT_LOAD memsz smaller than filesz");
        }

        let file_off = match u64_to_usize(p_offset) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let file_size = match u64_to_usize(p_filesz) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if let Err(e) = ensure_range(bytes.len(), file_off, file_size) {
            return Err(e);
        }
        let seg_data = match copy_range(bytes, file_off, file_size) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        segments.push(Segment {
            vaddr: p_vaddr,
            mem_size: p_memsz,
            file_off: p_offset,
            file_size: p_filesz,
            flags: p_flags,
            data: seg_data,
        });

        i = i + 1;
    }

    if segments.len() == 0 {
        return Err("no PT_LOAD segments");
    }
    Ok(segments)
}

fn reject_if_exec_segments_overlap(segments: &Vec<Segment>) -> (r: LoaderResult<()>)
    ensures
        r.is_ok() ==> exec_segments_non_overlapping_segments(segments@),
{
    let mut i: usize = 0;
    while i < segments.len()
        invariant
            i <= segments.len(),
            forall|a: int, b: int| 0 <= a < b < segments@.len() && a < i ==> exec_pair_non_overlapping(segments@, a, b),
        decreases segments.len() - i,
    {
        let mut j: usize = i + 1;
        while j < segments.len()
            invariant
                i + 1 <= j <= segments.len(),
                forall|a0: int, b0: int| 0 <= a0 < b0 < segments@.len() && a0 < i ==> exec_pair_non_overlapping(segments@, a0, b0),
                forall|b0: int| i < b0 < j ==> exec_pair_non_overlapping(segments@, i as int, b0),
            decreases segments.len() - j,
        {
            if (segments[i].flags & PF_X) != 0 && (segments[j].flags & PF_X) != 0 {
                let a_start = segments[i].vaddr as u128;
                let b_start = segments[j].vaddr as u128;
                let a_end = a_start + segments[i].data.len() as u128;
                let b_end = b_start + segments[j].data.len() as u128;
                let overlap = a_start < b_end && b_start < a_end;
                if overlap {
                    return Err("executable segments overlap in data range");
                }
                assert(exec_pair_non_overlapping(segments@, i as int, j as int));
            } else {
                assert(exec_pair_non_overlapping(segments@, i as int, j as int));
            }

            j = j + 1;
        }

        i = i + 1;
    }

    assert(exec_segments_non_overlapping_segments(segments@));
    Ok(())
}

fn parse_syslift_section_info(bytes: &Vec<u8>, hdr: &ElfHeaderInfo) -> (r: LoaderResult<SectionInfo>) {
    let shstr_row = match checked_mul(hdr.shstrndx, hdr.shentsize) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let shstr_off = match checked_add(hdr.shoff, shstr_row) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    let shstr_data_off_field = match checked_add(shstr_off, 24) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let shstr_data_off_u64 = match parse_u64_le(bytes, shstr_data_off_field) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let shstr_data_size_field = match checked_add(shstr_off, 32) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let shstr_data_size_u64 = match parse_u64_le(bytes, shstr_data_size_field) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let shstr_data_off = match u64_to_usize(shstr_data_off_u64) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let shstr_data_size = match u64_to_usize(shstr_data_size_u64) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    if let Err(e) = ensure_range(bytes.len(), shstr_data_off, shstr_data_size) {
        return Err(e);
    }
    let shstr = SectionInfo { off: shstr_data_off, size: shstr_data_size };

    let mut found: bool = false;
    let mut found_info = SectionInfo { off: 0, size: 0 };

    let mut i: usize = 0;
    while i < hdr.shnum
        invariant
            i <= hdr.shnum,
        decreases hdr.shnum - i,
    {
        let row = match checked_mul(i, hdr.shentsize) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let shoff = match checked_add(hdr.shoff, row) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        let name_off = match parse_u32_le(bytes, shoff) {
            Ok(v) => v as usize,
            Err(e) => return Err(e),
        };
        if !section_name_is_syslift(bytes, shstr, name_off) {
            i = i + 1;
            continue;
        }

        if found {
            return Err("duplicate .syslift section");
        }

        let sec_off_field = match checked_add(shoff, 24) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let sec_off_u64 = match parse_u64_le(bytes, sec_off_field) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let sec_size_field = match checked_add(shoff, 32) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let sec_size_u64 = match parse_u64_le(bytes, sec_size_field) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let sec_off = match u64_to_usize(sec_off_u64) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let sec_size = match u64_to_usize(sec_size_u64) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        if let Err(e) = ensure_range(bytes.len(), sec_off, sec_size) {
            return Err(e);
        }

        found = true;
        found_info = SectionInfo { off: sec_off, size: sec_size };
        i = i + 1;
    }

    if !found {
        return Err("missing .syslift section");
    }
    Ok(found_info)
}

fn parse_syscall_sites(bytes: &Vec<u8>, sec: SectionInfo) -> (r: LoaderResult<Vec<SyscallSite>>)
    ensures
        r.is_ok() ==> sec.size % SYSLIFT_SITE_SIZE == 0,
{
    proof {
        assert(12usize + 8usize * SYSLIFT_VALUE_COUNT == SYSLIFT_SITE_SIZE);
    }

    if sec.size % SYSLIFT_SITE_SIZE != 0 {
        return Err("invalid .syslift section size");
    }

    let count = sec.size / SYSLIFT_SITE_SIZE;
    let mut sites: Vec<SyscallSite> = Vec::new();

    let mut i: usize = 0;
    while i < count
        invariant
            i <= count,
            sites.len() == i,
        decreases count - i,
    {
        let row = match checked_mul(i, SYSLIFT_SITE_SIZE) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let off = match checked_add(sec.off, row) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        let site_vaddr = match parse_u64_le(bytes, off) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let known_mask_off = match checked_add(off, 8) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let known_mask = match parse_u32_le(bytes, known_mask_off) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        let mut values: [u64; SYSLIFT_VALUE_COUNT] = [0u64; SYSLIFT_VALUE_COUNT];
        let mut j: usize = 0;
        while j < SYSLIFT_VALUE_COUNT
            invariant
                j <= SYSLIFT_VALUE_COUNT,
            decreases SYSLIFT_VALUE_COUNT - j,
        {
            let value_base = match checked_add(off, 12) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            let value_row = match checked_mul(j, 8) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            let value_off = match checked_add(value_base, value_row) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            let value = match parse_u64_le(bytes, value_off) {
                Ok(v) => v,
                Err(e) => return Err(e),
            };
            values[j] = value;
            j = j + 1;
        }

        sites.push(SyscallSite { site_vaddr, known_mask, values });
        i = i + 1;
    }

    Ok(sites)
}

pub fn parse_program(bytes: &Vec<u8>) -> (r: LoaderResult<Program>)
    ensures
        match r {
            Ok(ref program) => phase_parsed_ok(program),
            Err(_) => true,
        },
{
    let hdr = match parse_elf_header(bytes) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    let segments = match parse_segments(bytes, &hdr) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    let syslift_sec = match parse_syslift_section_info(bytes, &hdr) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    let syscall_sites = match parse_syscall_sites(bytes, syslift_sec) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    if let Err(e) = reject_if_exec_segments_overlap(&segments) {
        return Err(e);
    }

    let program = Program {
        entry: hdr.entry,
        segments,
        syscall_sites,
    };
    assert(phase_parsed_ok(&program));
    Ok(program)
}

} // verus!
