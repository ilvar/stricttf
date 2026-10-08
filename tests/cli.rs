//! CLI contract: exit codes, and the strict separation between the JSON
//! document on stdout and everything meant for a human on stderr.

mod support;

use serde_json::Value;

fn json(bytes: &[u8]) -> Value {
    let text = String::from_utf8_lossy(bytes);
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("stdout must be JSON: {error}\n{text}"))
}

#[test]
fn a_clean_module_exits_zero_with_one_json_document_on_stdout() {
    let directory = support::empty_directory();
    stricttf::template::create_module(directory.path(), "demo-module")
        .expect("generation should succeed");

    let output = support::run_binary(&["check", "demo-module", "--source-only"], directory.path());

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(json(&output.stdout).get("ok"), Some(&Value::Bool(true)));
    assert!(
        output.stderr.is_empty(),
        "a successful check says nothing to a human: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_module_with_errors_exits_one_and_still_writes_a_parsable_report() {
    let fixture = support::module_fixture("kitchen-sink");
    let output = support::run_binary(
        &["check", "kitchen-sink", "--source-only"],
        fixture.parent(),
    );

    assert_eq!(output.status.code(), Some(1));
    let report = json(&output.stdout);
    assert_eq!(report.get("ok"), Some(&Value::Bool(false)));
    assert!(report
        .get("error_count")
        .and_then(Value::as_u64)
        .is_some_and(|count| count > 0));
}

#[test]
fn a_warning_only_report_exits_zero() {
    // Warnings describe recommendations. Failing on them would make the
    // exit code useless for deciding whether a module is broken.
    let fixture = support::module_fixture("clean");
    fixture.write(
        "unused.tf",
        "variable \"unused_input\" {\n  type        = string\n  description = \"Read by nothing.\"\n  default     = \"\"\n}\n",
    );

    let output = support::run_binary(&["check", "clean", "--source-only"], fixture.parent());
    let report = json(&output.stdout);

    assert_eq!(report.get("error_count"), Some(&Value::from(0)), "{report}");
    assert!(report
        .get("warning_count")
        .and_then(Value::as_u64)
        .is_some_and(|count| count > 0));
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn an_operational_failure_exits_two_with_nothing_on_stdout() {
    let directory = support::empty_directory();
    let output = support::run_binary(
        &["check", "does-not-exist", "--source-only"],
        directory.path(),
    );

    assert_eq!(
        output.status.code(),
        Some(2),
        "a check that did not run is not a clean module"
    );
    assert!(output.stdout.is_empty(), "no JSON document may be emitted");
    assert!(!output.stderr.is_empty(), "a human needs to be told why");
}

#[test]
fn a_directory_without_configuration_is_a_diagnostic_not_a_crash() {
    let directory = support::empty_directory();
    let output = support::run_binary(&["check", ".", "--source-only"], directory.path());

    assert_eq!(output.status.code(), Some(1));
    let report = json(&output.stdout);
    let codes: Vec<&str> = report
        .get("diagnostics")
        .and_then(Value::as_array)
        .map(|diagnostics| {
            diagnostics
                .iter()
                .filter_map(|diagnostic| diagnostic.get("code").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(codes, vec!["stricttf::no_configuration"]);
}

#[test]
fn a_missing_terraform_binary_is_an_operational_failure_not_a_silent_downgrade() {
    let fixture = support::module_fixture("clean");

    // An empty PATH guarantees neither terraform nor tofu is reachable.
    let output = std::process::Command::new(support::binary())
        .args(["check", "clean"])
        .current_dir(fixture.parent())
        .env("PATH", "")
        .output()
        .expect("binary should run");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("terraform"), "{stderr}");
    assert!(
        stderr.contains("--source-only"),
        "the message must name the way forward: {stderr}"
    );
}

#[test]
fn bad_invocations_exit_two_and_print_usage_to_stderr() {
    let directory = support::empty_directory();

    for arguments in [
        vec!["--nope"],
        vec!["check", "a", "b"],
        vec!["new"],
        vec!["install-skills", "extra"],
    ] {
        let output = support::run_binary(&arguments, directory.path());
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("usage:"),
            "{arguments:?}"
        );
    }
}

#[test]
fn a_bare_path_is_treated_as_check() {
    let fixture = support::module_fixture("kitchen-sink");
    let bare = support::run_binary(&["kitchen-sink", "--source-only"], fixture.parent());
    let explicit = support::run_binary(
        &["check", "kitchen-sink", "--source-only"],
        fixture.parent(),
    );

    assert_eq!(bare.status.code(), explicit.status.code());
    assert_eq!(bare.stdout, explicit.stdout);
}

#[test]
fn new_writes_a_clean_report_and_exits_zero() {
    let directory = support::empty_directory();
    let output = support::run_binary(&["new", "demo-module"], directory.path());

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(json(&output.stdout).get("ok"), Some(&Value::Bool(true)));
    assert!(directory.path().join("demo-module/versions.tf").is_file());
}

#[test]
fn new_refuses_an_invalid_name_on_stderr_and_creates_nothing() {
    let directory = support::empty_directory();
    let output = support::run_binary(&["new", "Demo_Module"], directory.path());

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!directory.path().join("Demo_Module").exists());
}

#[test]
fn two_runs_over_the_same_module_produce_byte_identical_output() {
    let fixture = support::module_fixture("kitchen-sink");
    let first = support::run_binary(
        &["check", "kitchen-sink", "--source-only"],
        fixture.parent(),
    );
    let second = support::run_binary(
        &["check", "kitchen-sink", "--source-only"],
        fixture.parent(),
    );

    assert_eq!(first.stdout, second.stdout);
}
