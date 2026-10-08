//! End-to-end tests against a real `trivy` binary.
//!
//! These are the only tests that need trivy installed. When it is absent
//! they skip -- loudly: set `STRICTTF_REQUIRE_TRIVY=1` and a skip becomes
//! a failure instead. A Full-depth check also needs Terraform, so every
//! test additionally follows `STRICTTF_REQUIRE_TERRAFORM`.
//!
//! The modules declare the `hashicorp/aws` provider. So that no test
//! downloads it, `terraform init` is pointed at an empty filesystem
//! mirror through `TF_CLI_CONFIG_FILE`: init fails offline with one
//! `terraform::init` error, and the trivy layer still runs.

mod support;

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Output;
use stricttf::{tfcli, trivy};

/// Whether Terraform is present, failing when it is declared required.
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

/// Whether trivy (and Terraform) are present, failing when either is
/// declared required.
fn trivy_ready(test: &str) -> bool {
    if !terraform_ready(test) {
        return false;
    }
    if trivy::binary().is_some() {
        return true;
    }
    assert!(
        std::env::var_os("STRICTTF_REQUIRE_TRIVY").is_none(),
        "{test} requires trivy on PATH and STRICTTF_REQUIRE_TRIVY is set"
    );
    eprintln!("SKIPPING {test}: trivy is not on PATH");
    false
}

/// Every file and directory below `root`, with file contents.
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

/// A Terraform CLI configuration whose only provider source is an empty
/// mirror, so `init` fails without touching the network.
fn offline_cli_config(directory: &Path) -> PathBuf {
    let path = directory.join("offline.tfrc");
    let mirror = directory.join("empty-mirror");
    std::fs::create_dir_all(&mirror).expect("mirror directory should be created");
    std::fs::write(
        &path,
        format!(
            "provider_installation {{\n  filesystem_mirror {{\n    path    = {:?}\n    include = [\"*/*/*\"]\n  }}\n}}\n",
            mirror.to_string_lossy()
        ),
    )
    .expect("CLI configuration should be written");
    path
}

/// `stricttf check <module>` at Full depth, offline.
fn check_offline(fixture: &support::ModuleFixture, scratch: &Path) -> Output {
    let module = fixture
        .path()
        .file_name()
        .expect("module has a name")
        .to_owned();
    std::process::Command::new(support::binary())
        .arg("check")
        .arg(module)
        .current_dir(fixture.path().parent().expect("module has a parent"))
        .env("TF_CLI_CONFIG_FILE", offline_cli_config(scratch))
        .output()
        .expect("stricttf binary should run")
}

fn json(stdout: &[u8]) -> Value {
    serde_json::from_slice(stdout).expect("stdout should be one JSON document")
}

fn diagnostics_with_code<'a>(report: &'a Value, code: &str) -> Vec<&'a Value> {
    report
        .get("diagnostics")
        .and_then(Value::as_array)
        .expect("report has diagnostics")
        .iter()
        .filter(|diagnostic| diagnostic.get("code").and_then(Value::as_str) == Some(code))
        .collect()
}

fn at(diagnostic: &Value) -> (&str, &str, u64, u64, u64, u64) {
    let location = diagnostic.get("at").expect("diagnostic is located");
    let number = |key: &str| {
        location
            .get(key)
            .and_then(Value::as_u64)
            .expect("location field is a number")
    };
    (
        diagnostic
            .get("level")
            .and_then(Value::as_str)
            .expect("level"),
        location.get("file").and_then(Value::as_str).expect("file"),
        number("line"),
        number("col"),
        number("end_line"),
        number("end_col"),
    )
}

#[test]
fn a_full_check_reports_trivy_findings_with_code_level_and_location() {
    if !trivy_ready("a_full_check_reports_trivy_findings_with_code_level_and_location") {
        return;
    }
    let fixture = support::module_fixture("trivy/insecure");
    let scratch = support::empty_directory();

    let output = check_offline(&fixture, scratch.path());
    let report = json(&output.stdout);

    assert_eq!(output.status.code(), Some(1), "{report}");
    assert!(diagnostics_with_code(&report, "trivy::unavailable").is_empty());

    let ssh = diagnostics_with_code(&report, "trivy::AWS-0107");
    assert_eq!(ssh.len(), 3, "{report}");
    assert_eq!(at(ssh[0]), ("error", "main.tf", 12, 1, 12, 32));
    assert_eq!(ssh[0].get("source").and_then(Value::as_str), Some("trivy"));

    let tracing = diagnostics_with_code(&report, "trivy::AWS-0066");
    assert_eq!(tracing.len(), 1, "{report}");
    assert_eq!(at(tracing[0]), ("warning", "main.tf", 52, 1, 66, 2));

    // The other layers still report everything they find.
    assert!(!diagnostics_with_code(&report, "stricttf::open_admin_ingress").is_empty());
    assert!(!diagnostics_with_code(&report, "terraform::init").is_empty());
}

#[test]
fn a_full_check_with_trivy_is_byte_identical_across_runs_and_leaves_the_module_untouched() {
    if !trivy_ready(
        "a_full_check_with_trivy_is_byte_identical_across_runs_and_leaves_the_module_untouched",
    ) {
        return;
    }
    let fixture = support::module_fixture("trivy/insecure");
    let scratch = support::empty_directory();
    let before = snapshot(fixture.path());

    let first = check_offline(&fixture, scratch.path());
    let second = check_offline(&fixture, scratch.path());

    assert_eq!(first.stdout, second.stdout);
    assert_eq!(snapshot(fixture.path()), before);
}

#[test]
fn the_trivy_layer_writes_nothing_into_a_module_with_dotfiles_and_subdirectories() {
    if !trivy_ready("the_trivy_layer_writes_nothing_into_a_module_with_dotfiles_and_subdirectories")
    {
        return;
    }
    for case in ["trivy/ignored", "trivy/nested"] {
        let fixture = support::module_fixture(case);
        let before = snapshot(fixture.path());
        let sources = stricttf::read_module(fixture.path()).expect("module should be readable");

        trivy::check(fixture.path(), &sources).expect("trivy should run");

        assert_eq!(snapshot(fixture.path()), before, "{case}");
    }
}

#[test]
fn a_trivyignore_in_the_module_is_not_honoured() {
    if !trivy_ready("a_trivyignore_in_the_module_is_not_honoured") {
        return;
    }
    let fixture = support::module_fixture("trivy/ignored");
    assert!(fixture.read(".trivyignore").contains("AWS-0107"));
    let sources = stricttf::read_module(fixture.path()).expect("module should be readable");

    let diagnostics = trivy::check(fixture.path(), &sources).expect("trivy should run");

    let codes: Vec<_> = diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.at.line))
        .collect();
    assert_eq!(codes, vec![("trivy::AWS-0107", 14)]);
}

#[test]
fn a_finding_in_a_nested_directory_is_not_reported_for_the_parent() {
    if !trivy_ready("a_finding_in_a_nested_directory_is_not_reported_for_the_parent") {
        return;
    }
    let fixture = support::module_fixture("trivy/nested");
    let sources = stricttf::read_module(fixture.path()).expect("module should be readable");

    let diagnostics = trivy::check(fixture.path(), &sources).expect("trivy should run");

    assert_eq!(diagnostics.len(), 1, "{diagnostics:#?}");
    assert_eq!(diagnostics[0].at.file, "main.tf");
}

#[cfg(unix)]
#[test]
fn without_trivy_on_path_a_full_check_warns_once_and_still_passes() {
    if !terraform_ready("without_trivy_on_path_a_full_check_warns_once_and_still_passes") {
        return;
    }
    let terraform = which("terraform")
        .or_else(|| which("tofu"))
        .expect("terraform_ready found terraform or tofu on PATH");
    let bin = support::empty_directory();
    let name = terraform.file_name().expect("binary has a name");
    std::os::unix::fs::symlink(&terraform, bin.path().join(name))
        .expect("symlink should be created");
    let fixture = support::module_fixture("live-clean");

    let output = std::process::Command::new(support::binary())
        .args(["check", "live-clean"])
        .current_dir(fixture.parent())
        .env("PATH", bin.path())
        .output()
        .expect("stricttf binary should run");
    let report = json(&output.stdout);

    assert_eq!(output.status.code(), Some(0), "{report}");
    assert_eq!(report.get("ok"), Some(&Value::Bool(true)));
    assert_eq!(report.get("error_count"), Some(&Value::from(0)));
    assert_eq!(report.get("warning_count"), Some(&Value::from(1)));
    let unavailable = diagnostics_with_code(&report, "trivy::unavailable");
    assert_eq!(unavailable.len(), 1, "{report}");
    assert_eq!(
        unavailable[0].get("source").and_then(Value::as_str),
        Some("trivy")
    );
    assert_eq!(at(unavailable[0]), ("warning", ".", 1, 1, 1, 1));
}

/// The first `name` on this process's `PATH`.
#[cfg(unix)]
fn which(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|entry| entry.join(name))
        .find(|candidate| candidate.is_file())
}
