use vstd::prelude::*;

use crate::model::*;
use crate::policy::build_allow_patch_plan;
use crate::spec::{
    allow_plan_spec, build_to_be_mapped_contract, output_contains_only_allowed_syscalls,
    output_syscalls_come_from_plan, phase_parsed_ok, phase_patched_ok, phase_planned_ok, phase_rejected_ok,
    plan_matches_program, plan_respects_allow, program_has_exec_raw_syscall, raw_syscall_at, reject_raw_syscall_spec,
    site_is_patched_by_plan,
};

verus! {

fn plan_has_patched_site(plan: &Vec<PatchDecision>, site: u64) -> (r: bool)
    ensures
        r ==> site_is_patched_by_plan(plan@, site as int),
{
    let mut i: usize = 0;
    while i < plan.len()
        invariant
            i <= plan.len(),
            forall|k: int|
                0 <= k < i &&
                (#[trigger] plan@[k]).should_patch &&
                plan@[k].site_vaddr == site ==>
                    site_is_patched_by_plan(plan@, site as int),
        decreases plan.len() - i,
    {
        let d = &plan[i];
        if d.should_patch && d.site_vaddr == site {
            assert(site_is_patched_by_plan(plan@, site as int));
            return true;
        }
        i = i + 1;
    }
    false
}

fn checked_add_usize(a: usize, b: usize) -> (r: LoaderResult<usize>) {
    if a > usize::MAX - b {
        Err("integer overflow")
    } else {
        Ok(a + b)
    }
}

fn checked_add_u64(a: u64, b: u64) -> (r: LoaderResult<u64>) {
    if a > u64::MAX - b {
        Err("integer overflow")
    } else {
        Ok(a + b)
    }
}

fn u64_to_usize(value: u64) -> (r: LoaderResult<usize>) {
    if value > usize::MAX as u64 {
        Err("value does not fit usize")
    } else {
        Ok(value as usize)
    }
}

fn patch_sites_overlap(a: u64, b: u64) -> (r: bool) {
    if a <= b {
        b - a < X86_PATCH_SLOT_SIZE as u64
    } else {
        a - b < X86_PATCH_SLOT_SIZE as u64
    }
}

fn overlaps_existing_patch_site(patch_sites: &Vec<u64>, site: u64) -> (r: bool) {
    let mut i: usize = 0;
    while i < patch_sites.len()
        invariant
            i <= patch_sites.len(),
        decreases patch_sites.len() - i,
    {
        if patch_sites_overlap(patch_sites[i], site) {
            return true;
        }
        i = i + 1;
    }
    false
}

fn x86_patch_slot_byte(offset: usize) -> (r: u8)
    requires
        offset < X86_PATCH_SLOT_SIZE,
{
    if offset == 0 {
        X86_SYSCALL_B0
    } else if offset == 1 {
        X86_SYSCALL_B1
    } else {
        0x90
    }
}

fn has_raw_syscall(data: &Vec<u8>) -> (r: bool)
    ensures
        r ==> exists|pos: int| raw_syscall_at(data@, pos),
        !r ==> forall|pos: int| !raw_syscall_at(data@, pos),
{
    if data.len() < 2 {
        assert(forall|pos: int| !raw_syscall_at(data@, pos));
        return false;
    }

    let mut i: usize = 0;
    while i + 1 < data.len()
        invariant
            i < data.len(),
            forall|pos: int| 0 <= pos < i ==> !raw_syscall_at(data@, pos),
        decreases data.len() - i,
    {
        if data[i] == X86_SYSCALL_B0 && data[i + 1] == X86_SYSCALL_B1 {
            assert(raw_syscall_at(data@, i as int));
            assert(exists|pos: int| raw_syscall_at(data@, pos));
            return true;
        }
        i = i + 1;
    }

    assert(i + 1 >= data.len());
    assert(forall|pos: int| !raw_syscall_at(data@, pos));

    false
}

pub fn reject_program_with_existing_syscall(program: &Program) -> (r: LoaderResult<()>)
    ensures
        reject_raw_syscall_spec(program, r),
{
    let mut i: usize = 0;
    while i < program.segments.len()
        invariant
            i <= program.segments.len(),
            forall|j: int, pos: int|
                0 <= j < i &&
                (program.segments@[j].flags & PF_X) != 0 ==>
                    !(#[trigger] raw_syscall_at(program.segments@[j].data@, pos)),
        decreases program.segments.len() - i,
    {
        let seg = &program.segments[i];
        if (seg.flags & PF_X) != 0 {
            let seg_has_raw = has_raw_syscall(&seg.data);
            if seg_has_raw {
                return Err("untrusted input: syscall instruction found in executable segment");
            }
            assert(forall|pos: int| !raw_syscall_at(seg.data@, pos));
        }
        i = i + 1;
    }

    assert(!program_has_exec_raw_syscall(program));
    Ok(())
}

fn exec_segment_range(seg: &Segment) -> (r: LoaderResult<(u64, u64)>) {
    let len_u64 = seg.data.len() as u64;
    let end = match checked_add_u64(seg.vaddr, len_u64) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    Ok((seg.vaddr, end))
}

fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> (r: bool) {
    a_start < b_end && b_start < a_end
}

pub fn reject_if_exec_segments_overlap(program: &Program) -> (r: LoaderResult<()>) {
    let mut i: usize = 0;
    while i < program.segments.len()
        invariant
            i <= program.segments.len(),
        decreases program.segments.len() - i,
    {
        let a = &program.segments[i];
        if (a.flags & PF_X) == 0 {
            i = i + 1;
            continue;
        }
        let (a_start, a_end) = match exec_segment_range(a) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        let mut j: usize = i + 1;
        while j < program.segments.len()
            invariant
                i + 1 <= j <= program.segments.len(),
            decreases program.segments.len() - j,
        {
            let b = &program.segments[j];
            if (b.flags & PF_X) != 0 {
                let (b_start, b_end) = match exec_segment_range(b) {
                    Ok(v) => v,
                    Err(e) => return Err(e),
                };
                if ranges_overlap(a_start, a_end, b_start, b_end) {
                    return Err("executable segments overlap in data range");
                }
            }
            j = j + 1;
        }

        i = i + 1;
    }

    Ok(())
}

fn segment_has_unplanned_raw_syscall(seg: &Segment, plan: &Vec<PatchDecision>) -> (r: bool)
    ensures
        !r ==> forall|pos: int|
            raw_syscall_at(seg.data@, pos) ==> site_is_patched_by_plan(plan@, seg.vaddr as int + pos),
{
    if seg.data.len() < 2 {
        return false;
    }

    let mut i: usize = 0;
    while i + 1 < seg.data.len()
        invariant
            i < seg.data.len(),
            forall|pos: int|
                0 <= pos < i && raw_syscall_at(seg.data@, pos) ==>
                    site_is_patched_by_plan(plan@, seg.vaddr as int + pos),
        decreases seg.data.len() - i,
    {
        if seg.data[i] == X86_SYSCALL_B0 && seg.data[i + 1] == X86_SYSCALL_B1 {
            if seg.vaddr > u64::MAX - i as u64 {
                return true;
            }
            let site = seg.vaddr + i as u64;
            if !plan_has_patched_site(plan, site) {
                return true;
            }
            assert(site as int == seg.vaddr as int + i as int);
            assert(site_is_patched_by_plan(plan@, seg.vaddr as int + i as int));
        }
        i = i + 1;
    }

    assert(i + 1 >= seg.data.len());
    assert(forall|pos: int|
        raw_syscall_at(seg.data@, pos) ==> site_is_patched_by_plan(plan@, seg.vaddr as int + pos));
    false
}

fn reject_output_syscalls_not_in_plan(program: &Program, plan: &Vec<PatchDecision>) -> (r: LoaderResult<()>)
    ensures
        r.is_ok() ==> output_syscalls_come_from_plan(program, plan@),
{
    let mut i: usize = 0;
    while i < program.segments.len()
        invariant
            i <= program.segments.len(),
            forall|si: int, pos: int|
                0 <= si < i &&
                (program.segments@[si].flags & PF_X) != 0 &&
                (#[trigger] raw_syscall_at(program.segments@[si].data@, pos)) ==>
                    site_is_patched_by_plan(plan@, program.segments@[si].vaddr as int + pos),
        decreases program.segments.len() - i,
    {
        let seg = &program.segments[i];
        if (seg.flags & PF_X) != 0 {
            if segment_has_unplanned_raw_syscall(seg, plan) {
                return Err("patched image contains syscall outside allow-driven plan");
            }
            assert(forall|pos: int|
                raw_syscall_at(seg.data@, pos) ==> site_is_patched_by_plan(plan@, seg.vaddr as int + pos));
        }
        i = i + 1;
    }

    assert(output_syscalls_come_from_plan(program, plan@));
    Ok(())
}

fn site_in_exec_segment_data(program: &Program, site_vaddr: u64) -> (r: bool) {
    let mut i: usize = 0;
    while i < program.segments.len()
        invariant
            i <= program.segments.len(),
        decreases program.segments.len() - i,
    {
        let seg = &program.segments[i];
        if (seg.flags & PF_X) == 0 || site_vaddr < seg.vaddr {
            i = i + 1;
            continue;
        }

        let rel_u64 = site_vaddr - seg.vaddr;
        let rel = match u64_to_usize(rel_u64) {
            Ok(v) => v,
            Err(_) => {
                i = i + 1;
                continue;
            }
        };
        let rel_end = match checked_add_usize(rel, X86_PATCH_SLOT_SIZE) {
            Ok(v) => v,
            Err(_) => {
                i = i + 1;
                continue;
            }
        };
        if rel_end <= seg.data.len() {
            return true;
        }

        i = i + 1;
    }

    false
}

fn validate_plan_and_collect_sites(program: &Program, plan: &Vec<PatchDecision>) -> (r: LoaderResult<Vec<u64>>) {
    if plan.len() != program.syscall_sites.len() {
        return Err("invalid patch plan length");
    }

    let mut patch_sites: Vec<u64> = Vec::new();

    let mut i: usize = 0;
    while i < plan.len()
        invariant
            i <= plan.len(),
            patch_sites.len() <= i,
            plan.len() == program.syscall_sites.len(),
        decreases plan.len() - i,
    {
        let d = &plan[i];
        let s = &program.syscall_sites[i];

        if d.site_vaddr != s.site_vaddr {
            return Err("invalid patch plan site address");
        }
        if d.sys_nr != s.values[0] {
            return Err("invalid patch plan syscall number");
        }

        if d.should_patch {
            if !site_in_exec_segment_data(program, d.site_vaddr) {
                return Err("syscall site outside executable segment data");
            }
            if overlaps_existing_patch_site(&patch_sites, d.site_vaddr) {
                return Err("overlapping syscall patch sites");
            }

            patch_sites.push(d.site_vaddr);
        }

        i = i + 1;
    }

    Ok(patch_sites)
}

fn make_zero_marks(len: usize) -> (r: Vec<u8>)
    ensures
        r@.len() == len,
{
    let mut marks: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < len
        invariant
            i <= len,
            marks@.len() == i,
        decreases len - i,
    {
        marks.push(0u8);
        i = i + 1;
    }
    marks
}

fn build_patch_marks_for_segment(seg: &Segment, patch_sites: &Vec<u64>) -> (r: LoaderResult<Vec<u8>>)
    ensures
        match r {
            Ok(ref marks) => marks@.len() == seg.data@.len(),
            Err(_) => true,
        },
{
    let mut marks = make_zero_marks(seg.data.len());
    if (seg.flags & PF_X) == 0 {
        return Ok(marks);
    }

    let mut i: usize = 0;
    while i < patch_sites.len()
        invariant
            i <= patch_sites.len(),
            marks@.len() == seg.data@.len(),
        decreases patch_sites.len() - i,
    {
        let site = patch_sites[i];
        if site >= seg.vaddr {
            let rel_u64 = site - seg.vaddr;
            let rel = match u64_to_usize(rel_u64) {
                Ok(v) => v,
                Err(_) => {
                    i = i + 1;
                    continue;
                }
            };
            let rel_end = match checked_add_usize(rel, X86_PATCH_SLOT_SIZE) {
                Ok(v) => v,
                Err(_) => {
                    i = i + 1;
                    continue;
                }
            };
            if rel_end <= seg.data.len() {
                if rel < marks.len() {
                    marks[rel] = 1u8;
                }
            }
        }

        i = i + 1;
    }

    Ok(marks)
}

fn patch_segment_one_pass(seg: &Segment, patch_marks: &Vec<u8>) -> (r: LoaderResult<Segment>) {
    if patch_marks.len() != seg.data.len() {
        return Err("invalid patch marks length");
    }

    let mut out_data: Vec<u8> = Vec::new();

    let mut i: usize = 0;
    while i < seg.data.len()
        invariant
            i <= seg.data.len(),
            out_data.len() == i,
            patch_marks@.len() == seg.data@.len(),
        decreases seg.data.len() - i,
    {
        let mut b = seg.data[i];
        if (seg.flags & PF_X) != 0 {
            if patch_marks[i] != 0 {
                b = x86_patch_slot_byte(0);
            } else if i >= 1 && patch_marks[i - 1] != 0 {
                b = x86_patch_slot_byte(1);
            } else if i >= 2 && patch_marks[i - 2] != 0 {
                b = x86_patch_slot_byte(2);
            } else if i >= 3 && patch_marks[i - 3] != 0 {
                b = x86_patch_slot_byte(3);
            } else if i >= 4 && patch_marks[i - 4] != 0 {
                b = x86_patch_slot_byte(4);
            } else if i >= 5 && patch_marks[i - 5] != 0 {
                b = x86_patch_slot_byte(5);
            } else if i >= 6 && patch_marks[i - 6] != 0 {
                b = x86_patch_slot_byte(6);
            } else if i >= 7 && patch_marks[i - 7] != 0 {
                b = x86_patch_slot_byte(7);
            }
        }

        out_data.push(b);
        i = i + 1;
    }

    Ok(Segment {
        vaddr: seg.vaddr,
        mem_size: seg.mem_size,
        file_off: seg.file_off,
        file_size: seg.file_size,
        flags: seg.flags,
        data: out_data,
    })
}

fn apply_patch_sites_one_pass(program: &mut Program, patch_sites: &Vec<u64>) -> (r: LoaderResult<()>) {
    let mut new_segments: Vec<Segment> = Vec::new();

    let mut i: usize = 0;
    while i < program.segments.len()
        invariant
            i <= program.segments.len(),
            new_segments.len() == i,
        decreases program.segments.len() - i,
    {
        let seg = &program.segments[i];
        let patch_marks = match build_patch_marks_for_segment(seg, patch_sites) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let new_seg = match patch_segment_one_pass(seg, &patch_marks) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        new_segments.push(new_seg);
        i = i + 1;
    }

    program.segments = new_segments;
    Ok(())
}

fn apply_patch_plan(program: &mut Program, plan: &Vec<PatchDecision>) -> (r: LoaderResult<()>) {
    let patch_sites = match validate_plan_and_collect_sites(program, plan) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    apply_patch_sites_one_pass(program, &patch_sites)
}

pub fn phase_reject_raw_syscalls(program: Program) -> (r: LoaderResult<Program>)
    requires
        phase_parsed_ok(&program),
    ensures
        match r {
            Ok(ref rejected) => phase_rejected_ok(rejected),
            Err(_) => true,
        },
{
    if let Err(e) = reject_if_exec_segments_overlap(&program) {
        return Err(e);
    }

    if let Err(e) = reject_program_with_existing_syscall(&program) {
        return Err(e);
    }

    assert(phase_rejected_ok(&program));
    Ok(program)
}

pub fn phase_build_allow_plan(program: Program, allow: &Vec<u64>) -> (r: LoaderResult<(Program, Vec<PatchDecision>)>)
    requires
        phase_rejected_ok(&program),
    ensures
        match r {
            Ok((ref planned_program, ref plan)) => phase_planned_ok(planned_program, allow, plan@),
            Err(_) => true,
        },
{
    let plan = match build_allow_patch_plan(&program, allow) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    assert(phase_planned_ok(&program, allow, plan@));
    Ok((program, plan))
}

pub fn phase_apply_patches(program: Program, plan: Vec<PatchDecision>, allow: &Vec<u64>) -> (r: LoaderResult<(Program, Vec<PatchDecision>)>)
    requires
        phase_planned_ok(&program, allow, plan@),
    ensures
        match r {
            Ok((ref patched_program, ref out_plan)) => phase_patched_ok(patched_program, allow, out_plan@),
            Err(_) => true,
        },
{
    let mut out_program = program;
    if let Err(e) = apply_patch_plan(&mut out_program, &plan) {
        return Err(e);
    }

    if let Err(e) = reject_output_syscalls_not_in_plan(&out_program, &plan) {
        return Err(e);
    }

    assert(phase_patched_ok(&out_program, allow, plan@));
    Ok((out_program, plan))
}

pub fn build_to_be_mapped_program_phased(program: Program, allow: &Vec<u64>) -> (r: LoaderResult<(Program, Vec<PatchDecision>)>)
    requires
        phase_parsed_ok(&program),
    ensures
        match r {
            Ok((ref patched_program, ref plan)) => phase_patched_ok(patched_program, allow, plan@),
            Err(_) => true,
        },
{
    let rejected_program = match phase_reject_raw_syscalls(program) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let (planned_program, plan) = match phase_build_allow_plan(rejected_program, allow) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    phase_apply_patches(planned_program, plan, allow)
}

pub fn build_to_be_mapped_program(program: Program, allow: &Vec<u64>) -> (r: LoaderResult<(Program, Vec<PatchDecision>)>)
    ensures
        match r {
            Ok((ref out_program, ref plan)) => build_to_be_mapped_contract(&program, allow, out_program, plan@),
            Err(_) => true,
        },
{
    if let Err(e) = reject_if_exec_segments_overlap(&program) {
        return Err(e);
    }

    if let Err(e) = reject_program_with_existing_syscall(&program) {
        return Err(e);
    }

    let plan = match build_allow_patch_plan(&program, allow) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    let mut out_program = program;
    if let Err(e) = apply_patch_plan(&mut out_program, &plan) {
        return Err(e);
    }

    if let Err(e) = reject_output_syscalls_not_in_plan(&out_program, &plan) {
        return Err(e);
    }

    assert(allow_plan_spec(&program, allow, plan@));
    assert(plan_matches_program(&program, plan@));
    assert(plan_respects_allow(allow, plan@));
    assert(!program_has_exec_raw_syscall(&program));
    assert(output_syscalls_come_from_plan(&out_program, plan@));
    assert(output_contains_only_allowed_syscalls(&out_program, allow, plan@));
    assert(build_to_be_mapped_contract(&program, allow, &out_program, plan@));
    Ok((out_program, plan))
}

} // verus!
