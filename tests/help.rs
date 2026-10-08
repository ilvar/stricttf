//! The embedded manual is a public agent interface. These tests assert
//! that it stays complete, so a rule, code, or command can never ship
//! without the manual that documents it.

mod support;

use std::collections::BTreeSet;

const HELP: &str = include_str!("../src/help.txt");

fn stdout_of(arguments: &[&str]) -> String {
    let directory = support::empty_directory();
    let output = support::run_binary(arguments, directory.path());
    assert_eq!(
        output.status.code(),
        Some(0),
        "{arguments:?} should succeed"
    );
    assert!(
        output.stderr.is_empty(),
        "help is not an error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("help should be UTF-8")
}

#[test]
fn every_help_alias_prints_the_same_manual() {
    let baseline = stdout_of(&["--help"]);
    assert_eq!(baseline.trim_end(), HELP.trim_end());

    for alias in [
        vec!["-h"],
        vec!["help"],
        vec!["check", "--help"],
        vec!["fix", "-h"],
        vec!["new", "--help"],
        vec!["install-skills", "--help"],
    ] {
        assert_eq!(
            stdout_of(&alias),
            baseline,
            "{alias:?} should print the manual"
        );
    }
}

#[test]
fn the_manual_documents_every_command_and_flag() {
    for fragment in [
        "stricttf check",
        "stricttf fix",
        "stricttf new",
        "stricttf install-skills",
        "--source-only",
        "--help",
    ] {
        assert!(
            HELP.contains(fragment),
            "the manual must document {fragment}"
        );
    }
}

#[test]
fn the_manual_documents_every_required_section() {
    for section in [
        "INSTALL",
        "COMMANDS",
        "WORKFLOW",
        "OUTPUT CONTRACT",
        "EXIT CODES",
        "CHECKING LAYERS",
        "STABLE CODES",
        "WHY THE STRICT RULES EXIST",
        "FIXES",
        "GENERATED MODULES",
        "AGENT SKILL",
        "CONSTRAINTS",
    ] {
        assert!(
            HELP.contains(section),
            "the manual must contain a {section} section"
        );
    }
}

#[test]
fn the_manual_lists_every_code_the_checker_can_emit() {
    // Any code the implementation can produce but the manual does not
    // list is a code an agent cannot act on.
    let emitted = emitted_codes();
    assert!(emitted.len() > 30, "the scan should find the real code set");

    for code in &emitted {
        assert!(
            HELP.contains(code.as_str()),
            "the manual must document {code}"
        );
    }
}

#[test]
fn the_manual_lists_no_code_the_checker_cannot_emit() {
    let emitted = emitted_codes();

    for line in HELP.lines() {
        for word in line.split_whitespace() {
            let candidate = word.trim_matches(|character: char| {
                !character.is_ascii_alphanumeric()
                    && !matches!(character, ':' | '_' | '<' | '>' | '-')
            });
            if !is_code(candidate) {
                continue;
            }
            // A concrete trivy check ID, such as an example in the manual,
            // is an instance of the emitted trivy::<ID> family.
            let family = candidate.strip_prefix("trivy::").is_some_and(|id| {
                id.split_once('-').is_some_and(|(provider, number)| {
                    !provider.is_empty()
                        && provider.chars().all(|c| c.is_ascii_uppercase())
                        && !number.is_empty()
                        && number.chars().all(|c| c.is_ascii_digit())
                })
            }) && emitted.contains("trivy::<ID>");
            assert!(
                family || emitted.contains(candidate),
                "the manual documents {candidate}, which nothing emits"
            );
        }
    }
}

#[test]
fn the_manual_states_the_exit_code_contract() {
    for fragment in ["0 ", "1 ", "2 "] {
        assert!(HELP.contains(fragment));
    }
    assert!(HELP.contains("Exit code 2 always means the check did not complete."));
    assert!(HELP.contains("Never treat exit code 2 as success"));
}

#[test]
fn the_manual_forbids_inventing_fixes_and_suppressing_checks() {
    assert!(HELP.contains("Never invent a fix"));
    assert!(HELP.contains("Never suppress, skip, or delete a check"));
    assert!(HELP.contains("Match on code, never on message text"));
}

fn is_code(text: &str) -> bool {
    ["stricttf::", "terraform::", "trivy::"]
        .iter()
        .any(|prefix| text.starts_with(prefix))
}

/// Every code literal that appears in the crate's source. Trivy's codes
/// are a family -- `trivy::` followed by the check ID trivy reports -- so
/// the `format!("trivy::{id}")` that builds them stands for the documented
/// `trivy::<ID>`.
fn emitted_codes() -> BTreeSet<String> {
    let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut codes = BTreeSet::new();

    for entry in walkdir::WalkDir::new(source_root).sort_by_file_name() {
        let entry = entry.expect("source should be readable");
        if !entry.file_type().is_file()
            || entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("rs")
        {
            continue;
        }

        let text = std::fs::read_to_string(entry.path()).expect("source should be readable");
        for capture in text.split('"') {
            if capture == "trivy::{id}" {
                codes.insert("trivy::<ID>".to_owned());
            } else if is_code(capture) && !capture.contains('{') {
                codes.insert(capture.to_owned());
            }
        }
    }

    codes
}
