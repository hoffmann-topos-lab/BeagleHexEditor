use super::*;

fn f(name: &str, address: u64, hash: u64) -> Function {
    Function { name: name.into(), address, insns: 10, hash }
}

#[test]
fn identical_binaries_report_no_differences() {
    let a = vec![f("main", 0x1000, 1), f("helper", 0x1100, 2)];
    let b = a.clone();
    let r = match_functions(a, b);
    assert_eq!(r.identical.len(), 2);
    assert!(!r.differs());
    assert!(r.changed.is_empty() && r.added.is_empty() && r.removed.is_empty());
}

#[test]
fn a_changed_function_is_matched_by_name_but_flagged() {
    let a = vec![f("main", 0x1000, 1)];
    let b = vec![f("main", 0x1000, 999)]; // same name, different fingerprint
    let r = match_functions(a, b);
    assert_eq!(r.changed.len(), 1);
    assert_eq!(r.changed[0].name, "main");
    assert!(r.identical.is_empty());
    assert!(r.differs());
}

#[test]
fn added_and_removed_functions_are_reported() {
    let a = vec![f("main", 0x1000, 1), f("gone", 0x1100, 2)];
    let b = vec![f("main", 0x1000, 1), f("new", 0x1200, 3)];
    let r = match_functions(a, b);
    assert_eq!(r.identical.len(), 1, "main matches");
    assert_eq!(r.removed.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), ["gone"]);
    assert_eq!(r.added.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), ["new"]);
}

#[test]
fn a_rename_is_matched_by_fingerprint() {
    // Same code (hash 42), different name, and the old name is gone in B.
    let a = vec![f("old_name", 0x1000, 42)];
    let b = vec![f("new_name", 0x2000, 42)];
    let r = match_functions(a, b);
    assert_eq!(r.renamed.len(), 1);
    assert_eq!(r.renamed[0].name_a, "old_name");
    assert_eq!(r.renamed[0].name_b, "new_name");
    assert!(r.added.is_empty() && r.removed.is_empty());
    assert!(r.differs());
}

#[test]
fn name_match_wins_over_fingerprint_match() {
    // Both have "f" (hash 1) and a fingerprint-twin with a different name.
    let a = vec![f("f", 0x1000, 1), f("only_a", 0x1100, 7)];
    let b = vec![f("f", 0x1000, 1), f("only_b", 0x1200, 7)];
    let r = match_functions(a, b);
    assert_eq!(r.identical.len(), 1, "f matches by name");
    assert_eq!(r.renamed.len(), 1, "the hash-7 twins pair as a rename");
    assert!(r.added.is_empty() && r.removed.is_empty());
}

#[test]
fn duplicate_names_pair_one_to_one_not_as_renames() {
    // Two functions share the name "thunk" (common: outlined code, except
    // tables). They must pair by name, never be mislabelled as renamed.
    let a = vec![f("thunk", 0x1000, 5), f("thunk", 0x2000, 6), f("main", 0x3000, 1)];
    let b = a.clone();
    let r = match_functions(a, b);
    assert_eq!(r.identical.len(), 3);
    assert!(r.renamed.is_empty(), "identical names must not become renames");
    assert!(!r.differs());
}

#[test]
fn totals_reflect_the_inputs() {
    let a = vec![f("a", 0x10, 1), f("b", 0x20, 2)];
    let b = vec![f("a", 0x10, 1)];
    let r = match_functions(a, b);
    assert_eq!((r.total_a, r.total_b), (2, 1));
}
