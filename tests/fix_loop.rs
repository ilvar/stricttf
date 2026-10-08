//! Mechanical fix application and loop termination.
//!
//! A fix that is wrong is worse than no fix at all, so these tests are
//! about refusal as much as application: refusing to escape the module,
//! refusing to split a character, refusing to apply two edits to the same
//! bytes, and refusing to spin.

mod support;

use stricttf::fixes;
use stricttf::report::{Diagnostic, EditSpan, Fix, Location, Report};
use stricttf::Depth;

fn fix(replace_with: &str, file: &str, byte_start: usize, byte_end: usize) -> Fix {
    Fix {
        hint: "test".to_owned(),
        replace_with: replace_with.to_owned(),
        line: 1,
        col: 1,
        end_line: 1,
        end_col: 1,
        edit: Some(EditSpan {
            file: file.to_owned(),
            byte_start,
            byte_end,
        }),
    }
}

fn report(fixes: Vec<Fix>) -> Report {
    Report::build(vec![Diagnostic {
        level: "error".to_owned(),
        source: "stricttf".to_owned(),
        code: "stricttf::test".to_owned(),
        message: "test".to_owned(),
        at: Location::whole_line("main.tf", 1, ""),
        fixes,
    }])
}

#[test]
fn multiple_edits_in_one_file_are_applied_back_to_front() {
    let directory = support::empty_directory();
    let source = "a: frist\nb: lsat\n";
    std::fs::write(directory.path().join("main.tf"), source).expect("fixture should be written");

    let first = source.find("frist").expect("marker should exist");
    let second = source.find("lsat").expect("marker should exist");
    let applied = fixes::apply(
        directory.path(),
        &report(vec![
            fix("first", "main.tf", first, first + 5),
            fix("last", "main.tf", second, second + 4),
        ]),
    )
    .expect("fixes should apply");

    let updated =
        std::fs::read_to_string(directory.path().join("main.tf")).expect("file should be readable");
    assert_eq!(applied, 2);
    assert_eq!(updated, "a: first\nb: last\n");
}

#[test]
fn identical_edits_are_deduplicated_and_counted_once() {
    let directory = support::empty_directory();
    std::fs::write(directory.path().join("main.tf"), "a: x\n").expect("fixture should be written");

    let applied = fixes::apply(
        directory.path(),
        &report(vec![fix("y", "main.tf", 3, 4), fix("y", "main.tf", 3, 4)]),
    )
    .expect("fixes should apply");

    assert_eq!(applied, 1);
    assert_eq!(
        std::fs::read_to_string(directory.path().join("main.tf")).expect("file should be readable"),
        "a: y\n"
    );
}

#[test]
fn the_first_of_two_overlapping_alternatives_wins_deterministically() {
    let directory = support::empty_directory();
    std::fs::write(directory.path().join("main.tf"), "a: wrong\n")
        .expect("fixture should be written");

    let applied = fixes::apply(
        directory.path(),
        &report(vec![
            fix("right", "main.tf", 3, 8),
            fix("other", "main.tf", 3, 8),
        ]),
    )
    .expect("fixes should apply");

    assert_eq!(applied, 1);
    assert_eq!(
        std::fs::read_to_string(directory.path().join("main.tf")).expect("file should be readable"),
        "a: right\n"
    );
}

#[test]
fn overlap_detection_handles_zero_width_insertions() {
    assert!(fixes::ranges_overlap(0, 5, 3, 8));
    assert!(
        !fixes::ranges_overlap(0, 3, 3, 8),
        "abutting is not overlapping"
    );
    assert!(
        fixes::ranges_overlap(4, 4, 0, 8),
        "an insertion inside a range overlaps it"
    );
    assert!(
        !fixes::ranges_overlap(8, 8, 0, 8),
        "an insertion at the edge does not"
    );
    assert!(
        fixes::ranges_overlap(4, 4, 4, 4),
        "two insertions at one point collide"
    );
    assert!(!fixes::ranges_overlap(4, 4, 5, 5));
}

#[test]
fn an_already_applied_fix_is_a_no_op() {
    let directory = support::empty_directory();
    std::fs::write(directory.path().join("main.tf"), "a: y\n").expect("fixture should be written");

    let applied = fixes::apply(directory.path(), &report(vec![fix("y", "main.tf", 3, 4)]))
        .expect("fixes should apply");

    assert_eq!(applied, 0, "fixes must be idempotent");
}

#[test]
fn a_path_outside_the_module_is_never_written() {
    let directory = support::empty_directory();
    let outside = directory.path().join("outside.yaml");
    std::fs::write(&outside, "untouched\n").expect("fixture should be written");
    let module = directory.path().join("module");
    std::fs::create_dir(&module).expect("module directory should be created");

    for escape in ["../outside.yaml", "/etc/passwd", "a/../../outside.yaml"] {
        assert!(
            fixes::contained_path(&module, escape).is_none(),
            "{escape} must be refused"
        );
        let applied = fixes::apply(&module, &report(vec![fix("x", escape, 0, 1)]))
            .expect("apply should not fail");
        assert_eq!(applied, 0);
    }

    assert_eq!(
        std::fs::read_to_string(&outside).expect("file should be readable"),
        "untouched\n"
    );
}

#[test]
fn an_edit_that_would_split_a_character_is_refused() {
    let directory = support::empty_directory();
    std::fs::write(directory.path().join("main.tf"), "a: héllo\n")
        .expect("fixture should be written");

    // Byte 4 is the middle of the two-byte `é`.
    let error = fixes::apply(directory.path(), &report(vec![fix("x", "main.tf", 4, 5)]))
        .expect_err("splitting UTF-8 must be refused");
    assert!(error.contains("UTF-8"), "{error}");

    assert_eq!(
        std::fs::read_to_string(directory.path().join("main.tf")).expect("file should be readable"),
        "a: héllo\n",
        "a refused edit must leave the file untouched"
    );
}

#[test]
fn an_out_of_range_edit_is_refused() {
    let directory = support::empty_directory();
    std::fs::write(directory.path().join("main.tf"), "a: x\n").expect("fixture should be written");

    let error = fixes::apply(directory.path(), &report(vec![fix("y", "main.tf", 0, 999)]))
        .expect_err("an edit past the end must be refused");
    assert!(error.contains("outside"), "{error}");
}

fn write_module(files: &[(&str, &str)]) -> tempfile::TempDir {
    let directory = support::empty_directory();
    for (path, text) in files {
        std::fs::write(directory.path().join(path), text).expect("fixture should be written");
    }
    directory
}

const VERSIONS: &str = "terraform {\n  required_version = \">= 1.6.0, < 2.0.0\"\n}\n";
const OUTPUTS: &str =
    "output \"id\" {\n  description = \"The resource ID.\"\n  value       = terraform_data.this.id\n}\n";

#[test]
fn the_loop_reaches_a_clean_report_when_every_defect_is_fixable() {
    let module = write_module(&[
        ("versions.tf", VERSIONS),
        (
            "variables.tf",
            "variable \"name\" {\n  type        = \"string\"\n  description = \"A name.\"\n}\n",
        ),
        (
            "main.tf",
            "resource \"terraform_data\" \"this\" {\n  input = \"${var.name}\"\n}\n",
        ),
        ("outputs.tf", OUTPUTS),
    ]);

    let before =
        stricttf::run_check_with_depth(module.path(), Depth::SourceOnly).expect("check should run");
    assert!(support::has_code(
        &before,
        "stricttf::quoted_type_constraint"
    ));
    assert!(support::has_code(&before, "stricttf::interpolation_only"));

    let after =
        stricttf::run_fix_with_limit(module.path(), Depth::SourceOnly, 10).expect("fix should run");

    assert!(after.ok, "the loop should reach a clean report: {after:#?}");
    assert!(after.diagnostics.is_empty(), "{after:#?}");
    let main = std::fs::read_to_string(module.path().join("main.tf")).expect("readable");
    let variables = std::fs::read_to_string(module.path().join("variables.tf")).expect("readable");
    assert!(main.contains("input = var.name\n"), "{main}");
    assert!(variables.contains("type        = string\n"), "{variables}");

    let again =
        stricttf::run_fix_with_limit(module.path(), Depth::SourceOnly, 10).expect("fix should run");
    assert_eq!(again, after, "a clean module is a fixed point");
}

#[test]
fn a_diagnostic_with_no_fix_leaves_the_module_alone() {
    let variables = "variable \"name\" {\n  type = string\n}\n";
    let module = write_module(&[
        ("versions.tf", VERSIONS),
        ("variables.tf", variables),
        (
            "main.tf",
            "resource \"terraform_data\" \"this\" {\n  input = var.name\n}\n",
        ),
        ("outputs.tf", OUTPUTS),
    ]);

    let report =
        stricttf::run_fix_with_limit(module.path(), Depth::SourceOnly, 10).expect("fix should run");

    assert!(support::has_code(
        &report,
        "stricttf::variable_missing_description"
    ));
    assert_eq!(
        std::fs::read_to_string(module.path().join("variables.tf")).expect("readable"),
        variables,
        "no fix is offered for a missing description, so nothing may be rewritten"
    );
}

#[test]
fn a_zero_iteration_cap_reports_without_editing() {
    let main = "resource \"terraform_data\" \"this\" {\n  input = \"${var.name}\"\n}\n";
    let module = write_module(&[
        ("versions.tf", VERSIONS),
        (
            "variables.tf",
            "variable \"name\" {\n  type        = string\n  description = \"A name.\"\n}\n",
        ),
        ("main.tf", main),
        ("outputs.tf", OUTPUTS),
    ]);

    let report =
        stricttf::run_fix_with_limit(module.path(), Depth::SourceOnly, 0).expect("fix should run");

    assert!(support::has_code(&report, "stricttf::interpolation_only"));
    assert_eq!(
        std::fs::read_to_string(module.path().join("main.tf")).expect("readable"),
        main
    );
}
