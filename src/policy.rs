//! Policy after blame (SPEC §10.3).
//!
//! An instance that aborts with blame is restarted without the blamed
//! parties — but only while the remaining committee still satisfies the
//! honest-majority bound `n' >= 2t - 1`. Below that bound the correct move
//! is committee re-sharing (SPEC §13.4), which is NOT implemented here;
//! `t` is never silently lowered.

use crate::{Error, PartyId, Result};

/// §10.3(1): the committee for restarting an instance after blame.
///
/// Returns the `current` ids minus the `blamed` (sorted; original ids
/// preserved — the survivors' long-term shares live at those evaluation
/// points). If the remainder would drop below `2t - 1`, returns
/// [`Error::InvalidParams`] pointing at §13.4 committee re-sharing instead
/// of silently lowering `t`.
pub fn restart_committee(
    current: &[PartyId],
    blamed: &[PartyId],
    t: usize,
) -> Result<Vec<PartyId>> {
    if t < 1 {
        return Err(Error::InvalidParams("threshold must be >= 1"));
    }
    let mut survivors: Vec<PartyId> = current
        .iter()
        .copied()
        .filter(|p| !blamed.contains(p))
        .collect();
    survivors.sort_unstable();
    if survivors.len() < 2 * t - 1 {
        return Err(Error::InvalidParams(
            "expulsion leaves n' < 2t-1: committee re-sharing required (SPEC 13.4, not implemented)",
        ));
    }
    Ok(survivors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_committee_with_and_without_slack() {
        // 3-of-6 has one slack: one expulsion leaves 5 >= 2t-1 — restart
        // over the surviving ORIGINAL ids.
        assert_eq!(
            restart_committee(&[1, 2, 3, 4, 5, 6], &[2], 3).unwrap(),
            vec![1, 3, 4, 5, 6]
        );
        // A second expulsion exhausts the slack: 4 < 5 — refused.
        let err = restart_committee(&[1, 3, 4, 5, 6], &[4], 3).unwrap_err();
        match err {
            Error::InvalidParams(msg) => assert!(msg.contains("13.4")),
            other => panic!("expected InvalidParams, got {other:?}"),
        }
        // 2-of-3 (n = 2t-1, zero slack): ANY expulsion is refused — t is
        // never silently lowered.
        assert!(restart_committee(&[1, 2, 3], &[2], 2).is_err());
        // No blame: the committee is returned unchanged (sorted).
        assert_eq!(
            restart_committee(&[3, 1, 2], &[], 2).unwrap(),
            vec![1, 2, 3]
        );
        // t = 0 is rejected, not underflowed.
        assert!(restart_committee(&[1, 2, 3], &[], 0).is_err());
    }
}
