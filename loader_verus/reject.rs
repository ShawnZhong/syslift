use vstd::prelude::*;

use crate::model::*;
use crate::spec::{
    output_syscalls_come_from_plan, program_has_exec_raw_syscall, raw_syscall_at,
    reject_raw_syscall_spec, site_is_patched_by_plan,
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
fn checked_add_u64(a: u64, b: u64) -> (r: LoaderResult<u64>) {
    if a > u64::MAX - b {
        Err("integer overflow")
    } else {
        Ok(a + b)
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

pub fn reject_output_syscalls_not_in_plan(program: &Program, plan: &Vec<PatchDecision>) -> (r: LoaderResult<()>)
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

} // verus!
