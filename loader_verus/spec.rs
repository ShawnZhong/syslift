use vstd::prelude::*;

use crate::model::{LoaderResult, PatchDecision, Program, Segment, PF_X, X86_SYSCALL_B0, X86_SYSCALL_B1};

verus! {

// Raw-syscall shape on executable bytes.
pub open spec fn raw_syscall_at(data: Seq<u8>, pos: int) -> bool {
    0 <= pos && pos + 1 < data.len() && data[pos] == X86_SYSCALL_B0 && data[pos + 1] == X86_SYSCALL_B1
}

// Program contains at least one executable raw syscall.
pub open spec fn program_has_exec_raw_syscall(program: &Program) -> bool {
    exists|si: int, pos: int|
        0 <= si < program.segments@.len() &&
        (program.segments@[si].flags & PF_X) != 0 &&
        (#[trigger] raw_syscall_at(program.segments@[si].data@, pos))
}

// Executable segment overlap predicate.
pub open spec fn exec_pair_non_overlapping(segments: Seq<Segment>, i: int, j: int) -> bool {
    (segments[i].flags & PF_X) == 0 ||
    (segments[j].flags & PF_X) == 0 ||
    (segments[i].vaddr as int + segments[i].data@.len() as int) <= segments[j].vaddr as int ||
    (segments[j].vaddr as int + segments[j].data@.len() as int) <= segments[i].vaddr as int
}

pub open spec fn exec_segments_non_overlapping(segments: Seq<Segment>) -> bool {
    forall|i: int, j: int| 0 <= i < j < segments.len() ==> exec_pair_non_overlapping(segments, i, j)
}

// Kept for call-site compatibility in parser/proofs.
pub open spec fn exec_segments_non_overlapping_segments(segments: Seq<Segment>) -> bool {
    exec_segments_non_overlapping(segments)
}

// Parsed phase: structure-only properties.
pub open spec fn phase_parsed_ok(program: &Program) -> bool {
    exec_segments_non_overlapping(program.segments@)
}

// Rejected phase: parsed + no executable raw syscall.
pub open spec fn phase_rejected_ok(program: &Program) -> bool {
    phase_parsed_ok(program) && !program_has_exec_raw_syscall(program)
}

// Plan rows align 1:1 with parsed syscall-site rows.
pub open spec fn plan_matches_program(program: &Program, plan: Seq<PatchDecision>) -> bool {
    plan.len() == program.syscall_sites@.len() &&
    forall|k: int|
        0 <= k < plan.len() ==>
            (#[trigger] plan[k]).site_vaddr == (#[trigger] program.syscall_sites@[k]).site_vaddr &&
            plan[k].sys_nr == program.syscall_sites@[k].values[0]
}

// Any patch decision must come from allow.
pub open spec fn plan_respects_allow(allow: &Vec<u64>, plan: Seq<PatchDecision>) -> bool {
    forall|k: int|
        0 <= k < plan.len() ==> (#[trigger] plan[k]).should_patch ==> allow@.contains((#[trigger] plan[k]).sys_nr)
}

// Plan correctness for a given input program.
pub open spec fn allow_plan_spec(program: &Program, allow: &Vec<u64>, plan: Seq<PatchDecision>) -> bool {
    plan_matches_program(program, plan) && plan_respects_allow(allow, plan)
}

// Planned phase: rejected + valid allow plan.
pub open spec fn phase_planned_ok(program: &Program, allow: &Vec<u64>, plan: Seq<PatchDecision>) -> bool {
    phase_rejected_ok(program) && allow_plan_spec(program, allow, plan)
}

// A vaddr site appears in the explicit patch plan.
pub open spec fn site_is_patched_by_plan(plan: Seq<PatchDecision>, site: int) -> bool {
    exists|k: int|
        0 <= k < plan.len() &&
        (#[trigger] plan[k]).should_patch &&
        site == plan[k].site_vaddr as int
}

// Output executable bytes contain raw syscall at vaddr site.
pub open spec fn program_exec_syscall_at_site(program: &Program, site: int) -> bool {
    exists|si: int, pos: int|
        0 <= si < program.segments@.len() &&
        (program.segments@[si].flags & PF_X) != 0 &&
        (#[trigger] raw_syscall_at(program.segments@[si].data@, pos)) &&
        site == program.segments@[si].vaddr as int + pos
}

pub open spec fn output_syscalls_come_from_plan(output: &Program, plan: Seq<PatchDecision>) -> bool {
    forall|site: int| program_exec_syscall_at_site(output, site) ==> site_is_patched_by_plan(plan, site)
}

// Top-level output goal: any syscall reachable in the to-be-mapped image is allowed.
pub open spec fn output_contains_only_allowed_syscalls(
    program: &Program,
    allow: &Vec<u64>,
    plan: Seq<PatchDecision>,
) -> bool {
    plan_respects_allow(allow, plan) && output_syscalls_come_from_plan(program, plan)
}

// Patched phase property.
pub open spec fn phase_patched_ok(program: &Program, allow: &Vec<u64>, plan: Seq<PatchDecision>) -> bool {
    output_contains_only_allowed_syscalls(program, allow, plan)
}

// Top-level loader security contract.
pub open spec fn build_to_be_mapped_contract(
    input: &Program,
    allow: &Vec<u64>,
    output: &Program,
    plan: Seq<PatchDecision>,
) -> bool {
    plan_matches_program(input, plan)
    && !program_has_exec_raw_syscall(input)
    && output_contains_only_allowed_syscalls(output, allow, plan)
}

// Helper contract for reject function.
pub open spec fn reject_raw_syscall_spec(program: &Program, result: LoaderResult<()>) -> bool {
    result.is_ok() ==> !program_has_exec_raw_syscall(program)
}

} // verus!
