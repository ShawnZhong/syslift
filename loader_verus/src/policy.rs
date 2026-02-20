use vstd::prelude::*;

use crate::model::*;
use crate::spec::{plan_matches_program, plan_respects_allow};

verus! {

fn contains_u64(values: &Vec<u64>, target: u64) -> (r: bool)
    ensures
        r ==> values@.contains(target),
{
    let mut i: usize = 0;
    while i < values.len()
        invariant
            i <= values.len(),
        decreases values.len() - i,
    {
        if values[i] == target {
            return true;
        }
        i = i + 1;
    }
    false
}

pub fn build_allow_patch_plan(program: &Program, allow: &Vec<u64>) -> (r: LoaderResult<Vec<PatchDecision>>)
    ensures
        match r {
            Ok(ref plan) => plan_matches_program(program, plan@) && plan_respects_allow(allow, plan@),
            Err(_) => true,
        },
{
    proof {
        assert(SYSLIFT_NR_BIT == 1u32);
    }

    let mut plan: Vec<PatchDecision> = Vec::new();

    let mut i: usize = 0;
    while i < program.syscall_sites.len()
        invariant
            i <= program.syscall_sites.len(),
            plan.len() == i,
            forall|k: int| 0 <= k < i ==> (#[trigger] plan@[k]).site_vaddr == program.syscall_sites@[k].site_vaddr,
            forall|k: int| 0 <= k < i ==> (#[trigger] plan@[k]).sys_nr == program.syscall_sites@[k].values[0],
            forall|k: int| 0 <= k < plan@.len() ==> (#[trigger] plan@[k]).should_patch ==> allow@.contains((#[trigger] plan@[k]).sys_nr),
        decreases program.syscall_sites.len() - i,
    {
        let site = &program.syscall_sites[i];
        if (site.known_mask & SYSLIFT_NR_BIT) == 0 {
            return Err("unable to prove constant syscall number in .syslift");
        }

        let sys_nr = site.values[0];
        let should_patch = contains_u64(allow, sys_nr);
        if should_patch {
            assert(allow@.contains(sys_nr));
        }

        plan.push(PatchDecision {
            site_vaddr: site.site_vaddr,
            sys_nr,
            should_patch,
        });

        i = i + 1;
    }

    Ok(plan)
}

} // verus!
