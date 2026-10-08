//! Terraform output normalisation. These parsers are pure, so the whole
//! contract between Terraform's output and the JSON report is testable
//! without a Terraform binary.
//!
//! Every capture under `fixtures/terraform/` was produced by Terraform
//! 1.16.5 (darwin_arm64) from the module directory of the same name, with
//! `TF_IN_AUTOMATION=1 TF_INPUT=0 CHECKPOINT_DISABLE=1` and `TF_DATA_DIR`
//! pointed outside the module:
//!
//! - `validate.json`: `terraform init -backend=false -input=false
//!   -no-color`, then `terraform validate -json -no-color > validate.json`
//!   in `validate/` (one warning, two errors, a multi-byte character
//!   before one error).
//! - `validate-uninitialised.json`: `terraform validate -json -no-color`
//!   in `validate-uninitialised/` without running `init` first, which
//!   yields a diagnostic with no source range.
//! - `init-*.stderr`: `terraform init -backend=false -input=false
//!   -no-color 2> <case>.stderr` in `<case>/`; `init-lockfile-readonly`
//!   adds `-lockfile=readonly` against a lock file pinning a version the
//!   configuration no longer allows; `init-wrapped-summary` is a quoted
//!   type constraint, whose stderr wraps a long `Error:` summary.
//! - `fmt.stdout`: `terraform fmt -no-color - < fmt/main.tf`.

mod support;

use stricttf::hcl::SourceFile;
use stricttf::report::{Diagnostic, Report};
use stricttf::{tfcli, ModuleSources};

fn sources(case: &str) -> ModuleSources {
    stricttf::read_module(&support::fixture_root().join("terraform").join(case))
        .expect("fixture module should be readable")
}

fn assert_golden(diagnostics: Vec<Diagnostic>, expected: &str) {
    let report = Report::build(diagnostics);
    let actual = serde_json::to_string_pretty(&report).expect("report should serialize");
    assert_eq!(
        actual.trim_end(),
        support::fixture_text(&format!("terraform/{expected}")).trim_end()
    );
}

fn validate(case: &str) -> Vec<Diagnostic> {
    tfcli::parse_validate_json(
        &support::fixture_text(&format!("terraform/{case}.json")),
        &sources(case),
    )
    .expect("a captured validate report should parse")
}

fn init(case: &str) -> Vec<Diagnostic> {
    tfcli::parse_init_errors(
        &support::fixture_text(&format!("terraform/{case}.stderr")),
        &sources(case),
    )
}

fn summary(diagnostic: &Diagnostic) -> (&str, &str, &str, u64, u64) {
    (
        diagnostic.level.as_str(),
        diagnostic.code.as_str(),
        diagnostic.at.file.as_str(),
        diagnostic.at.line,
        diagnostic.at.col,
    )
}

#[test]
fn validate_output_matches_its_golden_contract() {
    assert_golden(validate("validate"), "validate.expected.json");
}

#[test]
fn validate_severities_and_ranges_map_onto_the_report_contract() {
    let diagnostics = validate("validate");
    let found: Vec<_> = diagnostics.iter().map(summary).collect();

    assert!(found.contains(&("warning", "terraform::validate", "main.tf", 15, 17)));
    assert!(found.contains(&("error", "terraform::validate", "outputs.tf", 3, 17)));
    assert!(diagnostics
        .iter()
        .all(|diagnostic| diagnostic.source == "terraform" && diagnostic.fixes.is_empty()));
}

#[test]
fn validate_columns_count_characters_not_bytes() {
    let diagnostics = validate("validate");
    let local = diagnostics
        .iter()
        .find(|diagnostic| diagnostic.message.contains("undeclared local value"))
        .expect("the undeclared local is reported");

    // `café` precedes the reference, so its byte column is one greater.
    assert_eq!((local.at.line, local.at.col), (11, 35));
    assert_eq!((local.at.end_line, local.at.end_col), (11, 45));
    assert_eq!(
        local.at.snippet,
        "  input = { label = \"café\", ref = local.nope }"
    );
}

#[test]
fn a_validate_message_is_the_summary_and_detail_on_one_line() {
    let diagnostics = validate("validate");

    assert!(diagnostics.iter().any(|diagnostic| diagnostic.message
        == "Reference to undeclared local value: A local value with the name \"nope\" has not been declared."));
    assert!(diagnostics
        .iter()
        .all(|diagnostic| !diagnostic.message.contains('\n')));
}

#[test]
fn a_range_in_a_file_outside_the_module_keeps_terraforms_coordinates() {
    let diagnostics = tfcli::parse_validate_json(
        &support::fixture_text("terraform/validate.json"),
        &ModuleSources::default(),
    )
    .expect("a captured validate report should parse");
    let local = diagnostics
        .iter()
        .find(|diagnostic| diagnostic.message.contains("undeclared local value"))
        .expect("the undeclared local is reported");

    assert_eq!(
        summary(local),
        ("error", "terraform::validate", "main.tf", 11, 35)
    );
    assert_eq!(local.at.end_col, 45);
    assert_eq!(
        local.at.snippet, "  input = { label = \"café\", ref = local.nope }",
        "the snippet comes from the code Terraform quoted"
    );
}

#[test]
fn a_validate_diagnostic_without_a_range_addresses_the_module() {
    let diagnostics = validate("validate-uninitialised");

    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        summary(&diagnostics[0]),
        ("error", "terraform::validate", ".", 1, 1)
    );
    assert!(diagnostics[0]
        .message
        .starts_with("Missing required provider: This configuration requires provider"));
    assert_golden(diagnostics, "validate-uninitialised.expected.json");
}

#[test]
fn a_clean_validate_report_yields_no_diagnostics() {
    let clean = r#"{"format_version":"1.0","valid":true,"error_count":0,"warning_count":0,"diagnostics":[]}"#;
    assert_eq!(
        tfcli::parse_validate_json(clean, &ModuleSources::default()),
        Ok(Vec::new())
    );
}

#[test]
fn text_that_is_not_a_validate_report_is_an_operational_failure() {
    let empty = ModuleSources::default();

    assert!(tfcli::parse_validate_json("", &empty).is_err());
    assert!(tfcli::parse_validate_json("Error: Missing expression\n", &empty).is_err());
    assert!(tfcli::parse_validate_json(r#"{"valid":true}"#, &empty).is_err());
    assert!(tfcli::parse_validate_json(
        r#"{"diagnostics":[{"severity":"note","summary":"x","detail":""}]}"#,
        &empty
    )
    .is_err());
}

#[test]
fn init_errors_match_their_golden_contracts() {
    for case in [
        "init-core-version",
        "init-lockfile-readonly",
        "init-module-missing",
        "init-provider-unsatisfiable",
        "init-wrapped-summary",
    ] {
        assert_golden(init(case), &format!("{case}.expected.json"));
    }
}

#[test]
fn an_init_error_with_a_source_reference_is_located_on_that_line() {
    let diagnostics = init("init-core-version");

    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        summary(&diagnostics[0]),
        ("error", "terraform::init", "main.tf", 2, 1)
    );
    assert_eq!(
        diagnostics[0].at.snippet,
        "  required_version = \">= 99.0.0\""
    );
    assert!(
        !diagnostics[0].message.contains("2:"),
        "the quoted source excerpt is location, not message"
    );
}

#[test]
fn an_init_error_naming_a_module_file_inline_is_located_there() {
    let diagnostics = init("init-module-missing");
    let found: Vec<_> = diagnostics.iter().map(summary).collect();

    assert_eq!(
        found,
        vec![
            ("error", "terraform::init", ".", 1, 1),
            ("error", "terraform::init", "main.tf", 5, 1),
        ]
    );
    assert_eq!(diagnostics[1].at.snippet, "module \"network\" {");
}

#[test]
fn an_init_error_without_a_location_addresses_the_module_and_unwraps_its_text() {
    let diagnostics = init("init-provider-unsatisfiable");

    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        summary(&diagnostics[0]),
        ("error", "terraform::init", ".", 1, 1)
    );
    assert!(
        diagnostics[0]
            .message
            .contains("for provider hashicorp/null: no available releases"),
        "lines Terraform wrapped are joined: {}",
        diagnostics[0].message
    );
}

#[test]
fn a_wrapped_init_summary_stays_in_the_summary() {
    let diagnostics = init("init-wrapped-summary");
    let found: Vec<_> = diagnostics.iter().map(summary).collect();

    assert_eq!(
        found,
        vec![
            ("error", "terraform::init", ".", 1, 1),
            ("error", "terraform::init", "main.tf", 7, 1),
        ]
    );
    assert!(
        diagnostics[0].message.starts_with(
            "Terraform encountered problems during initialisation, including problems with the configuration, described below.: The Terraform configuration must be valid"
        ),
        "{}",
        diagnostics[0].message
    );
    assert!(diagnostics[1]
        .message
        .starts_with("Invalid quoted type constraints: Terraform 0.11 and earlier"));
}

#[test]
fn init_warnings_and_unrecognised_text_yield_no_errors() {
    let empty = ModuleSources::default();

    assert!(tfcli::parse_init_errors("", &empty).is_empty());
    assert!(tfcli::parse_init_errors("Initializing provider plugins...\n", &empty).is_empty());
    let diagnostics = tfcli::parse_init_errors(
        "\nWarning: Incomplete lock file information\n\nSome detail.\n\nError: Real failure\n\nWhy it failed.\n",
        &empty,
    );
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].message, "Real failure: Why it failed.");
}

fn fmt_case() -> (SourceFile, String) {
    let sources = sources("fmt");
    let file = sources
        .configuration
        .first()
        .expect("the fmt fixture has a file")
        .clone();
    (file, support::fixture_text("terraform/fmt.stdout"))
}

fn apply(file: &SourceFile, diagnostic: &Diagnostic) -> String {
    assert_eq!(diagnostic.fixes.len(), 1, "one fix per misformatted file");
    let fix = &diagnostic.fixes[0];
    let edit = fix.edit.as_ref().expect("an fmt fix is span-exact");
    assert_eq!(edit.file, file.path);
    format!(
        "{}{}{}",
        &file.text[..edit.byte_start],
        fix.replace_with,
        &file.text[edit.byte_end..]
    )
}

#[test]
fn fmt_output_matches_its_golden_contract() {
    let (file, formatted) = fmt_case();
    let diagnostic = tfcli::fmt_diagnostic(&file, &formatted).expect("the fixture is misformatted");

    assert_golden(vec![diagnostic], "fmt.expected.json");
}

#[test]
fn an_fmt_fix_spans_only_the_differing_region_and_reproduces_fmt_exactly() {
    let (file, formatted) = fmt_case();
    let diagnostic = tfcli::fmt_diagnostic(&file, &formatted).expect("the fixture is misformatted");

    assert_eq!(
        summary(&diagnostic),
        ("error", "terraform::fmt", "main.tf", 6, 8)
    );
    assert_eq!(diagnostic.at.end_line, 12);
    assert_eq!(apply(&file, &diagnostic), formatted);

    let fixed = SourceFile {
        path: file.path.clone(),
        text: formatted.clone(),
    };
    assert_eq!(
        tfcli::fmt_diagnostic(&fixed, &formatted),
        None,
        "a formatted file yields nothing, so the fix is idempotent"
    );
}

proptest::proptest! {
    #[test]
    fn an_fmt_fix_always_turns_the_text_into_the_formatted_text(
        old in "[a-c é😀\n]{0,12}",
        new in "[a-c é😀\n]{0,12}",
    ) {
        let file = SourceFile { path: "main.tf".to_owned(), text: old.clone() };
        match tfcli::fmt_diagnostic(&file, &new) {
            None => proptest::prop_assert_eq!(&old, &new),
            Some(diagnostic) => proptest::prop_assert_eq!(apply(&file, &diagnostic), new),
        }
    }
}
