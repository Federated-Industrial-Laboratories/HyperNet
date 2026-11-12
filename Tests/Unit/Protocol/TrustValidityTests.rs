// SPDX-License-Identifier: MIT
use super::*;
use crate::trust_wire as wire;
#[test]
fn finite_encoding_is_unchanged_and_persistent_encoding_is_explicit() {
    let finite = Validity(10, End::At(20));
    assert_eq!(serde_json::to_string(&finite).unwrap(), "[10,20]");
    assert_eq!(wire::encode(&finite.value()).unwrap(), vec![0x82, 10, 20]);
    let persistent = Validity(10, End::UntilWithdrawn);
    assert_eq!(
        serde_json::to_string(&persistent).unwrap(),
        r#"[10,{"untilWithdrawn":1}]"#
    );
    assert_eq!(Validity::parse(&persistent.value()).unwrap(), persistent);
    assert!(persistent.value().array(2).unwrap()[1].uint().is_err());
    assert_eq!(
        serde_json::from_str::<Validity>(r#"[10,{"untilWithdrawn":1}]"#).unwrap(),
        persistent
    );
    assert_eq!(
        End::parse(&Value::Uint(u64::MAX)).unwrap(),
        End::At(u64::MAX)
    );
}
#[test]
fn unknown_or_ambiguous_lifetimes_fail_closed() {
    for value in [
        Value::Null,
        Value::Bool(true),
        Value::Array(vec![]),
        Value::Array(vec![Value::Uint(2)]),
        Value::Array(vec![Value::Uint(1), Value::Uint(1)]),
    ] {
        assert!(End::parse(&value).is_err());
    }
    for json in [
        r#"{"untilWithdrawn":2}"#,
        r#"{"untilWithdrawn":1,"expires":20}"#,
        "null",
        "true",
        r#""until-withdrawn""#,
    ] {
        assert!(serde_json::from_str::<End>(json).is_err());
    }
}
#[test]
fn unbounded_entitlements_still_check_start_clock_and_finite_proofs() {
    let persistent = Validity(100, End::UntilWithdrawn);
    assert!(!persistent.current(99, 0));
    assert!(!persistent.current(100, 1));
    assert!(persistent.current(10_000_000_000, 1250));
    assert!(!persistent.current(u64::MAX, 1250));
    assert_eq!(persistent.1.bound(5000), 5000);
    assert!(persistent.1.finite().is_err());
    assert_eq!(persistent.1.remaining(10_000_000_000).unwrap(), None);
    assert_eq!(End::At(200).remaining(100).unwrap(), Some(100));
    assert!(End::At(200).remaining(200).is_err());
    assert!(End::UntilWithdrawn > End::At(u64::MAX));
    assert!(!Validity(1, End::At(604800002)).bounded_duration(604800000));
}

#[test]
fn persistent_cli_options_have_unambiguous_exclusive_arguments() {
    use clap::CommandFactory;
    crate::Arguments::command().debug_assert();
    assert_eq!(End::selected(None, true).unwrap(), End::UntilWithdrawn);
    assert_eq!(End::selected(Some(200), false).unwrap(), End::At(200));
    assert!(End::selected(Some(200), true).is_err());
    assert!(End::selected(None, false).is_err());
}
