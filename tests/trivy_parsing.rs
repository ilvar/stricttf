//! Trivy report normalisation. The parser is pure, so the whole contract
//! between trivy's JSON and the report is testable without a trivy
//! binary.
//!
//! Every capture under `fixtures/trivy/` was produced by trivy 0.75.0
//! (darwin_arm64) from the module directory of the same name, run inside
//! that directory with exactly the command `stricttf` runs:
//!
//! ```sh
//! env TMPDIR=<cache>/tmp \
//!   HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 \
//!   ALL_PROXY=http://127.0.0.1:9 http_proxy=http://127.0.0.1:9 \
//!   https_proxy=http://127.0.0.1:9 all_proxy=http://127.0.0.1:9 \
//!   NO_PROXY= no_proxy= GIT_ALLOW_PROTOCOL=none GIT_TERMINAL_PROMPT=0 \
//!   trivy config --quiet --format json --exit-code 0 \
//!   --skip-check-update --skip-version-check --disable-telemetry \
//!   --misconfig-scanners terraform \
//!   --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
//!   --cache-dir <cache> --module-dir <cache>/modules \
//!   --config "" --ignorefile "" . > ../<case>.json
//! ```
//!
//! - `insecure`: the `.tf` and `.tfvars` files of `fixtures/insecure`.
//! - `nested`: a root module with one finding and an uncalled `child/`
//!   directory with another; trivy reports both, the parser keeps only
//!   the root's.
//! - `ignored`: a `.trivyignore` listing the module's only finding and a
//!   `trivy.yaml` restricting the scan to Dockerfiles. With trivy's
//!   defaults the finding disappears; with `--ignorefile ""` and
//!   `--config ""` it is still reported.
//! - `inline`: the same finding suppressed by an inline
//!   `#trivy:ignore:AWS-0107` comment, which trivy always honours: its
//!   result for `main.tf` carries no misconfigurations at all.
//!
//! Each report's `ReportID` and `CreatedAt` differ on every run; the
//! parser reads neither.

mod support;

use stricttf::hcl::SourceFile;
use stricttf::report::{Diagnostic, Report};
use stricttf::{trivy, ModuleSources};

fn sources(case: &str) -> ModuleSources {
    stricttf::read_module(&support::fixture_root().join("trivy").join(case))
        .expect("fixture module should be readable")
}

fn parse(case: &str) -> Vec<Diagnostic> {
    trivy::parse_report(
        &support::fixture_text(&format!("trivy/{case}.json")),
        &sources(case),
    )
    .expect("a captured trivy report should parse")
}

fn assert_golden(case: &str) {
    let report = Report::build(parse(case));
    let actual = serde_json::to_string_pretty(&report).expect("report should serialize");
    assert_eq!(
        actual.trim_end(),
        support::fixture_text(&format!("trivy/{case}.expected.json")).trim_end()
    );
}

fn summary(diagnostic: &Diagnostic) -> (&str, &str, &str, u64, u64, u64, u64) {
    (
        diagnostic.level.as_str(),
        diagnostic.code.as_str(),
        diagnostic.at.file.as_str(),
        diagnostic.at.line,
        diagnostic.at.col,
        diagnostic.at.end_line,
        diagnostic.at.end_col,
    )
}

fn one_file(path: &str, text: &str) -> ModuleSources {
    ModuleSources {
        configuration: vec![SourceFile {
            path: path.to_owned(),
            text: text.to_owned(),
        }],
        ..ModuleSources::default()
    }
}

const MAIN: &str = "resource \"aws_s3_bucket\" \"site\" {\n  bucket = \"site\"\n}\n";

/// A schema-2 report with one result for `target` holding one
/// misconfiguration built from the given JSON members.
fn report_with(target: &str, misconfiguration: &str) -> String {
    format!(
        r#"{{"SchemaVersion":2,"Results":[{{"Target":"{target}","Misconfigurations":[{{{misconfiguration}}}]}}]}}"#
    )
}

fn finding(severity: &str, status: &str, lines: &str) -> String {
    format!(
        r#""ID":"AWS-0001","Title":"Title","Message":"Message","Resolution":"Resolve","Severity":"{severity}","PrimaryURL":"https://example.com/aws-0001","Status":"{status}","CauseMetadata":{{{lines}}}"#
    )
}

// --- goldens ------------------------------------------------------------

#[test]
fn the_insecure_module_matches_its_golden_contract() {
    assert_golden("insecure");
}

#[test]
fn a_finding_in_a_nested_directory_is_left_to_that_module() {
    assert_golden("nested");
    let diagnostics = parse("nested");
    let found: Vec<_> = diagnostics.iter().map(summary).collect();
    assert_eq!(
        found,
        vec![("error", "trivy::AWS-0107", "main.tf", 14, 1, 14, 32)]
    );
}

#[test]
fn a_trivyignore_in_the_module_does_not_suppress_a_finding() {
    assert!(
        support::fixture_text("trivy/ignored/.trivyignore").contains("AWS-0107"),
        "the fixture must list the finding it would suppress"
    );
    assert_golden("ignored");
    assert!(parse("ignored")
        .iter()
        .any(|diagnostic| diagnostic.code == "trivy::AWS-0107"));
}

#[test]
fn an_inline_trivy_ignore_comment_is_honoured_by_trivy() {
    assert_golden("inline");
    assert!(parse("inline").is_empty());
}

// --- mapping onto the report contract -----------------------------------

#[test]
fn findings_carry_trivys_id_level_and_cause_span() {
    let diagnostics = parse("insecure");
    let found: Vec<_> = diagnostics.iter().map(summary).collect();

    assert_eq!(diagnostics.len(), 23);
    assert!(found.contains(&("error", "trivy::AWS-0107", "main.tf", 12, 1, 12, 32)));
    assert!(found.contains(&("error", "trivy::AWS-0180", "main.tf", 49, 1, 49, 29)));
    assert!(found.contains(&("warning", "trivy::AWS-0066", "main.tf", 52, 1, 66, 2)));
    assert!(found.contains(&("warning", "trivy::AWS-0077", "main.tf", 42, 1, 50, 2)));
    assert!(diagnostics
        .iter()
        .all(|diagnostic| diagnostic.source == "trivy" && diagnostic.fixes.is_empty()));
}

#[test]
fn the_message_joins_title_message_resolution_and_url() {
    let diagnostics = parse("insecure");
    let public = diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "trivy::AWS-0180")
        .expect("AWS-0180 should be reported");
    assert_eq!(
        public.message,
        "RDS Publicly Accessible: Instance has Public Access enabled. Remove the public endpoint from the RDS instance. (https://avd.aquasec.com/misconfig/aws-0180)"
    );
    assert_eq!(public.at.snippet, "  publicly_accessible = true");
}

#[test]
fn severities_map_onto_two_levels() {
    for (severity, level) in [
        ("CRITICAL", "error"),
        ("HIGH", "error"),
        ("MEDIUM", "warning"),
        ("LOW", "warning"),
        ("UNKNOWN", "warning"),
    ] {
        let json = report_with(
            "main.tf",
            &finding(severity, "FAIL", r#""StartLine":2,"EndLine":2"#),
        );
        let diagnostics =
            trivy::parse_report(&json, &one_file("main.tf", MAIN)).expect("report should parse");
        assert_eq!(diagnostics.len(), 1, "{severity}");
        assert_eq!(diagnostics[0].level, level, "{severity}");
        assert_eq!(diagnostics[0].code, "trivy::AWS-0001");
    }
}

#[test]
fn an_unknown_severity_is_an_operational_failure() {
    let json = report_with(
        "main.tf",
        &finding("SEVERE", "FAIL", r#""StartLine":2,"EndLine":2"#),
    );
    assert!(trivy::parse_report(&json, &one_file("main.tf", MAIN)).is_err());
}

#[test]
fn only_failed_checks_are_findings() {
    for status in ["PASS", "EXCEPTION"] {
        let json = report_with(
            "main.tf",
            &finding("HIGH", status, r#""StartLine":2,"EndLine":2"#),
        );
        assert_eq!(
            trivy::parse_report(&json, &one_file("main.tf", MAIN)),
            Ok(Vec::new()),
            "{status}"
        );
    }
}

#[test]
fn a_cause_without_usable_lines_is_located_at_the_file_start() {
    for lines in [
        "",
        r#""StartLine":0,"EndLine":0"#,
        r#""StartLine":40,"EndLine":41"#,
    ] {
        let json = report_with("main.tf", &finding("HIGH", "FAIL", lines));
        let diagnostics =
            trivy::parse_report(&json, &one_file("main.tf", MAIN)).expect("report should parse");
        assert_eq!(
            summary(&diagnostics[0]),
            ("error", "trivy::AWS-0001", "main.tf", 1, 1, 1, 34),
            "{lines:?}"
        );
    }
}

#[test]
fn a_multi_line_cause_spans_to_the_end_of_its_last_line() {
    let json = report_with(
        "main.tf",
        &finding("LOW", "FAIL", r#""StartLine":1,"EndLine":3"#),
    );
    let diagnostics =
        trivy::parse_report(&json, &one_file("main.tf", MAIN)).expect("report should parse");
    assert_eq!(
        summary(&diagnostics[0]),
        ("warning", "trivy::AWS-0001", "main.tf", 1, 1, 3, 2)
    );
}

#[test]
fn empty_message_parts_are_omitted() {
    let json = report_with(
        "main.tf",
        r#""ID":"AWS-0001","Title":"Bucket  is\npublic.","Message":"","Resolution":"Block   it","Severity":"HIGH","PrimaryURL":"","Status":"FAIL""#,
    );
    let diagnostics =
        trivy::parse_report(&json, &one_file("main.tf", MAIN)).expect("report should parse");
    assert_eq!(diagnostics[0].message, "Bucket is public. Block it");
}

// --- the target filter ---------------------------------------------------

#[test]
fn a_dot_slash_target_is_a_module_file() {
    let json = report_with(
        "./main.tf",
        &finding("HIGH", "FAIL", r#""StartLine":2,"EndLine":2"#),
    );
    let diagnostics =
        trivy::parse_report(&json, &one_file("main.tf", MAIN)).expect("report should parse");
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].at.file, "main.tf");
}

#[test]
fn a_variable_file_target_is_a_module_file() {
    let sources = ModuleSources {
        variable_files: vec![SourceFile {
            path: "terraform.tfvars".to_owned(),
            text: "acl = \"public-read\"\n".to_owned(),
        }],
        ..one_file("main.tf", MAIN)
    };
    let json = report_with(
        "terraform.tfvars",
        &finding("HIGH", "FAIL", r#""StartLine":1,"EndLine":1"#),
    );
    let diagnostics = trivy::parse_report(&json, &sources).expect("report should parse");
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].at.file, "terraform.tfvars");
}

#[test]
fn targets_outside_the_modules_own_files_are_dropped() {
    for target in [
        ".",
        "child/main.tf",
        "terraform-aws-modules/vpc/aws/main.tf",
        "other.tf",
    ] {
        let json = report_with(
            target,
            &finding("HIGH", "FAIL", r#""StartLine":2,"EndLine":2"#),
        );
        assert_eq!(
            trivy::parse_report(&json, &one_file("main.tf", MAIN)),
            Ok(Vec::new()),
            "{target}"
        );
    }
}

// --- operational failures -------------------------------------------------

#[test]
fn malformed_json_is_an_operational_failure() {
    let sources = one_file("main.tf", MAIN);
    assert!(trivy::parse_report("", &sources).is_err());
    assert!(trivy::parse_report("not json", &sources).is_err());
    assert!(trivy::parse_report(r#"{"Results":[]}"#, &sources).is_err());
    assert!(trivy::parse_report(
        r#"{"SchemaVersion":2,"Results":[{"Misconfigurations":[]}]}"#,
        &sources
    )
    .is_err());
}

#[test]
fn an_unknown_schema_version_is_an_operational_failure() {
    let json = r#"{"SchemaVersion":3,"Results":[]}"#;
    assert!(trivy::parse_report(json, &one_file("main.tf", MAIN)).is_err());
}

#[test]
fn missing_results_for_a_module_with_configuration_is_an_operational_failure() {
    let json = r#"{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem"}"#;
    assert!(trivy::parse_report(json, &one_file("main.tf", MAIN)).is_err());
}

#[test]
fn missing_results_when_there_was_nothing_to_scan_is_empty() {
    let json = r#"{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem"}"#;
    assert_eq!(
        trivy::parse_report(json, &ModuleSources::default()),
        Ok(Vec::new())
    );
}

#[test]
fn a_result_without_misconfigurations_is_empty() {
    let json = r#"{"SchemaVersion":2,"Results":[{"Target":"main.tf","Class":"config","Type":"terraform"}]}"#;
    assert_eq!(
        trivy::parse_report(json, &one_file("main.tf", MAIN)),
        Ok(Vec::new())
    );
}
