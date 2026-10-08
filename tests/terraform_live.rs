//! End-to-end tests against a real `terraform` (or `tofu`) binary.
//!
//! These are the only tests that need Terraform installed. When it is
//! absent they skip -- but a skip is never silent and never invisible:
//! set `STRICTTF_REQUIRE_TERRAFORM=1` and a skip becomes a failure
//! instead. CI sets it, so the suite cannot quietly stop testing the
//! layer that matters most.
//!
//! Every `live-*` module uses only `terraform_data`, which is built into
//! Terraform, so no test needs the network.

mod support;

use std::collections::BTreeMap;
use std::path::Path;
use stricttf::{tfcli, Depth};

/// Returns true when the body should run. Fails the test rather than
/// skipping when Terraform is declared to be required.
fn terraform_ready(test: &str) -> bool {
    if tfcli::binary().is_some() {
        return true;
    }
    assert!(
        std::env::var_os("STRICTTF_REQUIRE_TERRAFORM").is_none(),
        "{test} requires terraform or tofu on PATH and STRICTTF_REQUIRE_TERRAFORM is set"
    );
    eprintln!("SKIPPING {test}: neither terraform nor tofu is on PATH");
    false
}

/// Every file and directory below `root`, with file contents, so any
/// write a check makes -- including a new `.terraform` -- is visible.
fn snapshot(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    walkdir::WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .map(|entry| {
            let entry = entry.expect("module should be walkable");
            let relative = entry
                .path()
                .strip_prefix(root)
                .expect("entry is below the root")
                .to_string_lossy()
                .into_owned();
            let contents = entry
                .file_type()
                .is_file()
                .then(|| std::fs::read(entry.path()).expect("file should be readable"));
            (relative, contents)
        })
        .collect()
}

#[test]
fn a_clean_module_passes_a_full_check_with_no_diagnostics() {
    if !terraform_ready("a_clean_module_passes_a_full_check_with_no_diagnostics") {
        return;
    }
    let fixture = support::module_fixture("live-clean");

    let report =
        stricttf::run_check_with_depth(fixture.path(), Depth::Full).expect("check should run");

    assert!(report.ok, "{report:#?}");
    // Without trivy the security-scan layer is skipped with exactly one
    // warning; with it, a `terraform_data`-only module has no findings.
    if stricttf::trivy::binary().is_some() {
        assert!(report.diagnostics.is_empty(), "{report:#?}");
    } else {
        assert_eq!(
            support::codes(&report),
            vec!["trivy::unavailable".to_owned()],
            "{report:#?}"
        );
    }
}

#[test]
fn a_misformatted_module_gets_an_fmt_fix_that_the_fix_loop_applies() {
    if !terraform_ready("a_misformatted_module_gets_an_fmt_fix_that_the_fix_loop_applies") {
        return;
    }
    let fixture = support::module_fixture("live-misformatted");

    let report =
        stricttf::run_check_with_depth(fixture.path(), Depth::Full).expect("check should run");
    let fmt = support::with_code(&report, "terraform::fmt");
    assert_eq!(fmt.len(), 1, "{report:#?}");
    assert_eq!((fmt[0].at.file.as_str(), fmt[0].at.line), ("main.tf", 6));
    assert_eq!(fmt[0].fixes.len(), 1);

    let fixed =
        stricttf::run_fix_with_limit(fixture.path(), Depth::Full, 10).expect("fix loop should run");

    assert!(fixed.ok, "{fixed:#?}");
    assert!(!support::has_code(&fixed, "terraform::fmt"), "{fixed:#?}");
    assert_eq!(
        fixture.read("main.tf"),
        support::fixture_text("live-clean/main.tf"),
        "the fixed file is exactly what terraform fmt writes"
    );
}

#[test]
fn an_invalid_reference_is_a_located_validate_error() {
    if !terraform_ready("an_invalid_reference_is_a_located_validate_error") {
        return;
    }
    let fixture = support::module_fixture("live-invalid");

    let report =
        stricttf::run_check_with_depth(fixture.path(), Depth::Full).expect("check should run");
    let validate = support::with_code(&report, "terraform::validate");

    assert!(!report.ok);
    assert_eq!(validate.len(), 1, "{report:#?}");
    let at = &validate[0].at;
    assert_eq!(validate[0].level, "error");
    assert_eq!(validate[0].source, "terraform");
    assert_eq!((at.file.as_str(), at.line, at.col), ("main.tf", 13, 13));
    assert_eq!(at.snippet, "    owner = local.nope");
    assert!(
        validate[0].message.contains("undeclared local value"),
        "{}",
        validate[0].message
    );
}

#[test]
fn a_check_leaves_a_locked_module_byte_identical() {
    if !terraform_ready("a_check_leaves_a_locked_module_byte_identical") {
        return;
    }
    let fixture = support::module_fixture("live-clean");
    let before = snapshot(fixture.path());

    stricttf::run_check_with_depth(fixture.path(), Depth::Full).expect("check should run");

    assert_eq!(snapshot(fixture.path()), before);
}

#[test]
fn a_check_of_a_module_without_a_lock_file_leaves_none_behind() {
    if !terraform_ready("a_check_of_a_module_without_a_lock_file_leaves_none_behind") {
        return;
    }
    let fixture = support::module_fixture("live-unlocked");
    let before = snapshot(fixture.path());

    for run in 0..2 {
        stricttf::run_check_with_depth(fixture.path(), Depth::Full).expect("check should run");
        assert!(
            !fixture.path().join(stricttf::LOCK_FILE).exists(),
            "run {run} left a lock file"
        );
        assert!(!fixture.path().join(".terraform").exists());
        assert_eq!(snapshot(fixture.path()), before);
    }
}

#[test]
fn a_failed_init_is_reported_and_leaves_the_module_untouched() {
    if !terraform_ready("a_failed_init_is_reported_and_leaves_the_module_untouched") {
        return;
    }
    let fixture = support::module_fixture("live-unlocked");
    fixture.write(
        "modules.tf",
        "module \"network\" {\n  source = \"./modules/network\"\n}\n",
    );
    let before = snapshot(fixture.path());

    let report =
        stricttf::run_check_with_depth(fixture.path(), Depth::Full).expect("check should run");

    assert!(support::has_code(&report, "terraform::init"), "{report:#?}");
    assert!(
        !support::has_code(&report, "terraform::validate"),
        "validate is skipped when init fails: {report:#?}"
    );
    assert_eq!(snapshot(fixture.path()), before);
}
