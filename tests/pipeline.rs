//! Layer orchestration and report ordering.

mod support;

use stricttf::hcl::SourceFile;
use stricttf::report::{Diagnostic, Location, Report, LEVEL_ERROR, LEVEL_WARNING};
use stricttf::ModuleSources;

fn diagnostic(file: &str, line: u64, col: u64, code: &str, message: &str) -> Diagnostic {
    let mut at = Location::whole_line(file, line, "");
    at.col = col;
    Diagnostic::rule(LEVEL_ERROR, code, message, at)
}

fn file(path: &str, text: &str) -> SourceFile {
    SourceFile {
        path: path.to_owned(),
        text: text.to_owned(),
    }
}

#[test]
fn diagnostics_are_ordered_by_file_line_column_code_then_message() {
    let report = Report::build(vec![
        diagnostic("variables.tf", 1, 1, "stricttf::b", "m"),
        diagnostic("main.tf", 9, 1, "stricttf::a", "m"),
        diagnostic("main.tf", 2, 5, "stricttf::a", "m"),
        diagnostic("main.tf", 2, 1, "stricttf::b", "m"),
        diagnostic("main.tf", 2, 1, "stricttf::a", "second"),
        diagnostic("main.tf", 2, 1, "stricttf::a", "first"),
    ]);

    let order: Vec<(String, u64, u64, String, String)> = report
        .diagnostics
        .iter()
        .map(|diagnostic| {
            (
                diagnostic.at.file.clone(),
                diagnostic.at.line,
                diagnostic.at.col,
                diagnostic.code.clone(),
                diagnostic.message.clone(),
            )
        })
        .collect();

    let expected = [
        ("main.tf", 2, 1, "stricttf::a", "first"),
        ("main.tf", 2, 1, "stricttf::a", "second"),
        ("main.tf", 2, 1, "stricttf::b", "m"),
        ("main.tf", 2, 5, "stricttf::a", "m"),
        ("main.tf", 9, 1, "stricttf::a", "m"),
        ("variables.tf", 1, 1, "stricttf::b", "m"),
    ];
    let expected: Vec<(String, u64, u64, String, String)> = expected
        .iter()
        .map(|(file, line, col, code, message)| {
            (
                (*file).to_owned(),
                *line,
                *col,
                (*code).to_owned(),
                (*message).to_owned(),
            )
        })
        .collect();
    assert_eq!(order, expected);
}

#[test]
fn identical_findings_collapse_and_only_errors_fail_the_report() {
    let mut warning = diagnostic("main.tf", 3, 1, "stricttf::w", "m");
    warning.level = LEVEL_WARNING.to_owned();
    let report = Report::build(vec![
        diagnostic("main.tf", 1, 1, "stricttf::a", "m"),
        diagnostic("main.tf", 1, 1, "stricttf::a", "m"),
        warning.clone(),
    ]);
    assert_eq!(report.diagnostics.len(), 2);
    assert_eq!((report.error_count, report.warning_count), (1, 1));
    assert!(!report.ok);

    let warnings_only = Report::build(vec![warning]);
    assert!(warnings_only.ok);
}

#[test]
fn a_syntax_error_makes_the_module_uncheckable_but_other_files_are_still_checked() {
    let sources = ModuleSources {
        configuration: vec![
            file(
                "broken.tf",
                "resource \"terraform_data\" \"x\" {\n  input =\n}\n",
            ),
            file(
                "variables.tf",
                "variable \"name\" {\n  description = \"A name.\"\n}\n",
            ),
        ],
        ..ModuleSources::default()
    };

    let (diagnostics, checkable) = stricttf::check_sources(&sources);
    let report = Report::build(diagnostics);

    assert!(
        !checkable,
        "terraform must not run over a file that is not HCL"
    );
    assert!(support::has_code(&report, "stricttf::syntax_error"));
    assert!(
        support::has_code(&report, "stricttf::variable_missing_type"),
        "the parsable file must still be checked: {report:#?}"
    );
}

#[test]
fn a_broken_tfvars_or_test_file_is_reported_without_blocking_terraform() {
    let sources = ModuleSources {
        configuration: vec![file(
            "versions.tf",
            "terraform {\n  required_version = \">= 1.6.0, < 2.0.0\"\n}\n",
        )],
        variable_files: vec![file("terraform.tfvars", "name = \n")],
        test_files: vec![file("tests/main.tftest.hcl", "run \"x\" {\n")],
        lock_file: None,
    };

    let (diagnostics, checkable) = stricttf::check_sources(&sources);
    let files: Vec<&str> = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "stricttf::syntax_error")
        .map(|diagnostic| diagnostic.at.file.as_str())
        .collect();

    assert!(
        checkable,
        "terraform reports these files better than skipping"
    );
    assert_eq!(files, vec!["terraform.tfvars", "tests/main.tftest.hcl"]);
}

#[test]
fn reading_a_module_collects_configuration_variables_tests_and_the_lock_file() {
    let directory = support::empty_directory();
    let root = directory.path();
    for (path, text) in [
        ("b.tf", "locals {}\n"),
        ("a.tf", "locals {}\n"),
        ("prod.tfvars", "x = 1\n"),
        ("notes.md", "ignored\n"),
        ("override.tf.json", "{}\n"),
        (".terraform.lock.hcl", "\n"),
    ] {
        std::fs::write(root.join(path), text).expect("fixture should be written");
    }
    std::fs::create_dir_all(root.join("tests")).expect("tests dir");
    std::fs::write(root.join("tests/main.tftest.hcl"), "run \"x\" {}\n").expect("written");
    std::fs::create_dir_all(root.join("modules/child")).expect("child dir");
    std::fs::write(root.join("modules/child/main.tf"), "locals {}\n").expect("written");

    let sources = stricttf::read_module(root).expect("module should be readable");
    let paths = |files: &[SourceFile]| -> Vec<String> {
        files.iter().map(|file| file.path.clone()).collect()
    };

    assert_eq!(paths(&sources.configuration), vec!["a.tf", "b.tf"]);
    assert_eq!(paths(&sources.variable_files), vec!["prod.tfvars"]);
    assert_eq!(paths(&sources.test_files), vec!["tests/main.tftest.hcl"]);
    assert!(sources.lock_file.is_some());
}

#[cfg(unix)]
#[test]
fn a_symlinked_configuration_file_is_read_like_terraform_reads_it() {
    let directory = support::empty_directory();
    let shared = directory.path().join("shared");
    let module = directory.path().join("module");
    std::fs::create_dir_all(&shared).expect("shared dir");
    std::fs::create_dir_all(&module).expect("module dir");
    std::fs::write(
        shared.join("versions.tf"),
        "terraform {\n  required_version = \">= 1.6.0, < 2.0.0\"\n}\n",
    )
    .expect("written");
    std::fs::write(
        module.join("outputs.tf"),
        "output \"name\" {\n  description = \"A name.\"\n  value       = \"x\"\n}\n",
    )
    .expect("written");
    std::os::unix::fs::symlink("../shared/versions.tf", module.join("versions.tf"))
        .expect("symlink");

    let sources = stricttf::read_module(&module).expect("module should be readable");
    let paths: Vec<&str> = sources
        .configuration
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(paths, vec!["outputs.tf", "versions.tf"]);

    let report = stricttf::run_check_with_depth(&module, stricttf::Depth::SourceOnly)
        .expect("check should run");
    assert!(
        report.diagnostics.is_empty(),
        "the linked required_version must count: {report:#?}"
    );
}

#[test]
fn a_trivy_finding_supersedes_only_the_duplicate_it_covers() {
    let ours = |line: u64| diagnostic("main.tf", line, 3, "stricttf::public_database", "ours");
    let mut theirs = diagnostic("main.tf", 40, 1, "trivy::AWS-0180", "theirs");
    theirs.at.end_line = 45;
    let elsewhere = diagnostic("other.tf", 42, 1, "stricttf::public_database", "ours");
    let unrelated = diagnostic("main.tf", 42, 1, "stricttf::hardcoded_secret", "ours");

    let kept = stricttf::supersede_with_trivy(vec![
        ours(42),
        ours(50),
        theirs.clone(),
        elsewhere.clone(),
        unrelated.clone(),
    ]);

    assert_eq!(kept, vec![ours(50), theirs, elsewhere, unrelated]);
}

#[test]
fn without_a_trivy_finding_nothing_is_superseded() {
    let ours = diagnostic("main.tf", 12, 1, "stricttf::open_admin_ingress", "ours");
    let wrong_check = diagnostic("main.tf", 12, 1, "trivy::AWS-0092", "theirs");
    let kept = stricttf::supersede_with_trivy(vec![ours.clone(), wrong_check.clone()]);
    assert_eq!(kept, vec![ours, wrong_check]);
}
