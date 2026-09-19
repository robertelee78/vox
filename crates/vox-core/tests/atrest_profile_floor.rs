//! ADR-010 §"Post-quantum strength of the at-rest factors": the passphrase
//! factor is Argon2id at **≥ 256 MiB, ≥ 3 passes**. This is an *integration*
//! test on purpose — it links `vox-core` as a normal (non-`cfg(test)`)
//! dependency, so it observes exactly what a production build resolves. The
//! reduced test-only profile must not exist here, and no stored profile id may
//! resolve to parameters below the floor.
//!
//! No KDF is executed: the assertions are on the resolved parameters only.

use vox_core::atrest::sek::Argon2Profile;

/// ADR-010 floor, restated here independently of the crate's own constants so
/// the test cannot drift with them.
const ADR_MIN_M_COST_KIB: u32 = 256 * 1024;
const ADR_MIN_T_COST: u32 = 3;

#[test]
fn production_build_resolves_only_profiles_at_or_above_the_adr_floor() {
    // Every id a production build is willing to resolve must meet the floor.
    let mut resolved = 0;
    for id in 0..=u8::MAX {
        if let Ok(p) = Argon2Profile::from_id(id) {
            resolved += 1;
            assert!(
                p.m_cost_kib() >= ADR_MIN_M_COST_KIB,
                "profile id {id} resolves to {} KiB, below the ADR-010 256 MiB floor",
                p.m_cost_kib()
            );
            assert!(
                p.t_cost() >= ADR_MIN_T_COST,
                "profile id {id} resolves to {} passes, below the ADR-010 3-pass floor",
                p.t_cost()
            );
        }
    }
    assert!(resolved >= 1, "the production profile must resolve");
}

#[test]
fn reduced_test_profile_id_is_unknown_in_a_production_build() {
    // Id 2 is the test-only reduced profile (8 KiB / 1 pass). A wrap naming it
    // must be un-openable outside the crate's own unit tests.
    assert!(Argon2Profile::from_id(2).is_err());
}

#[test]
fn default_profile_is_production_and_meets_the_floor() {
    let p = Argon2Profile::default();
    assert_eq!(p.id(), Argon2Profile::PRODUCTION_ID);
    assert!(p.m_cost_kib() >= ADR_MIN_M_COST_KIB);
    assert!(p.t_cost() >= ADR_MIN_T_COST);
}
