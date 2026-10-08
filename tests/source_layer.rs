//! Module-structure and configuration-source layers: every rule is shown
//! firing on the defect it names and staying silent on the nearest
//! legitimate construct.

mod support;

use proptest::prelude::{prop_assert_eq, proptest, ProptestConfig};
use std::collections::BTreeSet;
use stricttf::hcl::SourceFile;
use stricttf::report::{Diagnostic, Report};
use stricttf::{Depth, ModuleSources};
use support::{check_files, module_fixture, with_code};

/// A compliant `terraform` block, so a test can isolate one rule.
const VERSIONS: &str = r#"terraform {
  required_version = "~> 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
"#;

fn source(path: &str, text: &str) -> SourceFile {
    SourceFile {
        path: path.to_owned(),
        text: text.to_owned(),
    }
}

/// Check configuration and tfvars files at source-only depth.
fn check_module(configuration: &[(&str, &str)], tfvars: &[(&str, &str)], lock: bool) -> Report {
    let sources = ModuleSources {
        configuration: configuration
            .iter()
            .map(|(path, text)| source(path, text))
            .collect(),
        variable_files: tfvars
            .iter()
            .map(|(path, text)| source(path, text))
            .collect(),
        test_files: Vec::new(),
        lock_file: lock.then(|| source(".terraform.lock.hcl", "")),
    };
    let (diagnostics, _checkable) = stricttf::check_sources(&sources);
    Report::build(diagnostics)
}

/// Check one `main.tf` beside a compliant `versions.tf` and a lock file.
fn check_main(main: &str) -> Report {
    check_module(&[("main.tf", main), ("versions.tf", VERSIONS)], &[], true)
}

fn only<'a>(report: &'a Report, code: &str) -> &'a Diagnostic {
    let found = with_code(report, code);
    assert_eq!(found.len(), 1, "expected exactly one {code}: {report:#?}");
    found[0]
}

fn absent(report: &Report, code: &str) {
    assert!(
        with_code(report, code).is_empty(),
        "unexpected {code}: {report:#?}"
    );
}

fn at(diagnostic: &Diagnostic) -> (&str, u64, u64) {
    (
        diagnostic.at.file.as_str(),
        diagnostic.at.line,
        diagnostic.at.col,
    )
}

fn stricttf_codes(report: &Report) -> BTreeSet<String> {
    report
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code.starts_with("stricttf::"))
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

// --- required_version ---------------------------------------------------

#[test]
fn a_terraform_block_without_required_version_is_located_at_its_header() {
    let versions = "terraform {\n  required_providers {\n    aws = { source = \"hashicorp/aws\", version = \"~> 5.0\" }\n  }\n}\n";
    let report = check_module(
        &[("main.tf", "locals {}\n"), ("versions.tf", versions)],
        &[],
        true,
    );
    let finding = only(&report, "stricttf::required_version_missing");
    assert_eq!(at(finding), ("versions.tf", 1, 1));
    assert_eq!(finding.at.end_col, 10);
}

#[test]
fn without_any_terraform_block_required_version_points_at_versions_tf() {
    let report = check_module(
        &[("main.tf", "locals {}\n"), ("versions.tf", "# pins\n")],
        &[],
        true,
    );
    assert_eq!(
        at(only(&report, "stricttf::required_version_missing")),
        ("versions.tf", 1, 1)
    );
    let bare = check_module(
        &[("a.tf", "locals {}\n"), ("b.tf", "locals {}\n")],
        &[],
        true,
    );
    assert_eq!(
        at(only(&bare, "stricttf::required_version_missing")),
        ("a.tf", 1, 1)
    );
}

#[test]
fn required_version_in_any_terraform_block_satisfies_the_rule() {
    let report = check_module(
        &[
            ("backend.tf", "terraform {\n  backend \"local\" {}\n}\n"),
            ("versions.tf", VERSIONS),
        ],
        &[],
        true,
    );
    absent(&report, "stricttf::required_version_missing");
}

// --- required_providers ---------------------------------------------------

#[test]
fn a_legacy_string_requirement_has_no_source() {
    let versions = "terraform {\n  required_version = \"~> 1.9\"\n  required_providers {\n    aws = \"~> 5.0\"\n  }\n}\n";
    let report = check_module(&[("versions.tf", versions)], &[], true);
    assert_eq!(
        at(only(&report, "stricttf::provider_source_missing")),
        ("versions.tf", 4, 5)
    );
    absent(&report, "stricttf::provider_version_missing");
    absent(&report, "stricttf::provider_version_unbounded");
}

#[test]
fn an_object_requirement_needs_source_and_version() {
    let versions = "terraform {\n  required_version = \"~> 1.9\"\n  required_providers {\n    random = { version = \"~> 3.6\" }\n    tls = { source = \"hashicorp/tls\" }\n  }\n}\n";
    let report = check_module(&[("versions.tf", versions)], &[], true);
    assert_eq!(
        at(only(&report, "stricttf::provider_source_missing")),
        ("versions.tf", 4, 5)
    );
    assert_eq!(
        at(only(&report, "stricttf::provider_version_missing")),
        ("versions.tf", 5, 5)
    );
}

#[test]
fn a_complete_requirement_is_accepted() {
    let report = check_module(&[("versions.tf", VERSIONS)], &[], true);
    assert!(report.diagnostics.is_empty(), "{report:#?}");
}

#[test]
fn a_lower_bound_only_constraint_is_unbounded() {
    let versions = VERSIONS.replace("~> 5.0", ">= 5.0, != 5.3.0");
    let report = check_module(&[("versions.tf", &versions)], &[], true);
    let finding = only(&report, "stricttf::provider_version_unbounded");
    assert_eq!(at(finding), ("versions.tf", 7, 17));
    assert!(finding.message.contains(">= 5.0, != 5.3.0"), "{finding:?}");

    let capped = VERSIONS.replace("~> 5.0", ">= 5.0, < 6.0");
    absent(
        &check_module(&[("versions.tf", &capped)], &[], true),
        "stricttf::provider_version_unbounded",
    );
}

#[test]
fn an_undeclared_provider_is_reported_once_at_its_first_use() {
    let main = r#"resource "google_storage_bucket" "first" {
  name = "a"
}

resource "google_storage_bucket" "second" {
  name = "b"
}
"#;
    let report = check_main(main);
    let finding = only(&report, "stricttf::provider_undeclared");
    assert_eq!(at(finding), ("main.tf", 1, 10));
    assert!(finding.message.contains("google"), "{finding:?}");
}

#[test]
fn a_provider_meta_argument_overrides_the_type_prefix() {
    let main = r#"resource "aws_s3_bucket" "logs" {
  provider = awsalt.west
}

data "aws_caller_identity" "current" {
  provider = aws
}
"#;
    let report = check_main(main);
    let finding = only(&report, "stricttf::provider_undeclared");
    assert_eq!(at(finding), ("main.tf", 2, 14));
    assert!(finding.message.contains("awsalt"), "{finding:?}");
}

#[test]
fn provider_blocks_and_ephemeral_resources_count_as_uses() {
    let main =
        "provider \"azurerm\" {\n  features {}\n}\n\nephemeral \"vault_kv_secret\" \"db\" {}\n";
    let report = check_main(main);
    let found = with_code(&report, "stricttf::provider_undeclared");
    let places: Vec<_> = found.iter().map(|diagnostic| at(diagnostic)).collect();
    assert_eq!(places, vec![("main.tf", 1, 10), ("main.tf", 5, 11)]);
}

#[test]
fn the_builtin_terraform_provider_needs_no_requirement_or_lock() {
    let main = "resource \"terraform_data\" \"marker\" {}\n\ndata \"terraform_remote_state\" \"net\" {\n  backend = \"local\"\n}\n";
    let report = check_module(
        &[
            ("main.tf", main),
            (
                "versions.tf",
                "terraform {\n  required_version = \"~> 1.9\"\n}\n",
            ),
        ],
        &[],
        false,
    );
    absent(&report, "stricttf::provider_undeclared");
    absent(&report, "stricttf::lock_file_missing");
}

#[test]
fn a_module_using_providers_needs_a_lock_file() {
    let main = "resource \"aws_s3_bucket\" \"logs\" {}\n";
    let report = check_module(&[("main.tf", main), ("versions.tf", VERSIONS)], &[], false);
    let finding = only(&report, "stricttf::lock_file_missing");
    assert_eq!(finding.level, "warning");
    assert_eq!(at(finding), (".terraform.lock.hcl", 1, 1));
    absent(&check_main(main), "stricttf::lock_file_missing");
}

// --- tfvars -----------------------------------------------------------------

#[test]
fn a_tfvars_key_without_a_variable_is_reported_at_the_key() {
    let main = "variable \"region\" {\n  type        = string\n  description = \"Region.\"\n}\n\nlocals {\n  region = var.region\n}\n\noutput \"region\" {\n  description = \"Region.\"\n  value       = local.region\n}\n";
    let report = check_module(
        &[("main.tf", main), ("versions.tf", VERSIONS)],
        &[(
            "terraform.tfvars",
            "region = \"eu-west-1\"\nzone   = \"a\"\n",
        )],
        true,
    );
    let finding = only(&report, "stricttf::tfvars_undeclared");
    assert_eq!(at(finding), ("terraform.tfvars", 2, 1));
    assert!(finding.message.contains("zone"), "{finding:?}");
}

// --- variables ----------------------------------------------------------------

#[test]
fn a_variable_needs_a_type_and_a_description() {
    let main = "variable \"region\" {}\n\nvariable \"zone\" {\n  type        = string\n  description = \"  \"\n}\n\noutput \"o\" {\n  description = \"Both.\"\n  value       = [var.region, var.zone]\n}\n";
    let report = check_main(main);
    assert_eq!(
        at(only(&report, "stricttf::variable_missing_type")),
        ("main.tf", 1, 1)
    );
    let descriptions: Vec<_> = with_code(&report, "stricttf::variable_missing_description")
        .into_iter()
        .map(at)
        .collect();
    assert_eq!(descriptions, vec![("main.tf", 1, 1), ("main.tf", 5, 17)]);
}

#[test]
fn a_typed_described_variable_is_accepted() {
    let main = "variable \"zone\" {\n  type        = list(object({ name = string, any = optional(number) }))\n  description = \"Zones.\"\n}\n\noutput \"o\" {\n  description = \"Zones.\"\n  value       = var.zone\n}\n";
    let report = check_main(main);
    assert!(report.diagnostics.is_empty(), "{report:#?}");
}

#[test]
fn any_anywhere_in_a_type_is_reported_at_the_type() {
    for (constraint, col) in [("any", 17), ("map(any)", 17), ("object({ a = any })", 17)] {
        let main = format!(
            "variable \"v\" {{\n  type        = {constraint}\n  description = \"V.\"\n}}\n"
        );
        let report = check_main(&main);
        let finding = only(&report, "stricttf::variable_any_type");
        assert_eq!(at(finding), ("main.tf", 2, col), "{constraint}");
    }
}

#[test]
fn a_quoted_primitive_type_is_fixed_to_the_bare_keyword() {
    let main = "variable \"v\" {\n  type        = \"string\"\n  description = \"V.\"\n}\n";
    let report = check_main(main);
    let finding = only(&report, "stricttf::quoted_type_constraint");
    assert_eq!(at(finding), ("main.tf", 2, 17));
    assert_eq!(finding.fixes.len(), 1);
    assert_eq!(finding.fixes[0].replace_with, "string");
    assert_eq!(
        (
            finding.fixes[0].line,
            finding.fixes[0].col,
            finding.fixes[0].end_col
        ),
        (2, 17, 25)
    );
    absent(&report, "stricttf::variable_any_type");
}

#[test]
fn a_quoted_collection_type_is_reported_without_a_fix() {
    let main = "variable \"v\" {\n  type        = \"list\"\n  description = \"V.\"\n}\n";
    let finding = only(&check_main(main), "stricttf::quoted_type_constraint").clone();
    assert!(finding.fixes.is_empty(), "{finding:?}");
    let bare = "variable \"v\" {\n  type        = list(string)\n  description = \"V.\"\n}\n";
    absent(&check_main(bare), "stricttf::quoted_type_constraint");
}

#[test]
fn a_credential_variable_must_be_sensitive() {
    let variable = |name: &str, extra: &str| {
        format!("variable \"{name}\" {{\n  type        = string\n  description = \"Secret.\"\n{extra}}}\n")
    };
    let report = check_main(&variable("db_password", ""));
    assert_eq!(
        at(only(&report, "stricttf::sensitive_variable_unmarked")),
        ("main.tf", 1, 10)
    );
    let explicit_false = check_main(&variable("api_token", "  sensitive   = false\n"));
    only(&explicit_false, "stricttf::sensitive_variable_unmarked");

    absent(
        &check_main(&variable("db_password", "  sensitive   = true\n")),
        "stricttf::sensitive_variable_unmarked",
    );
    absent(
        &check_main(&variable("password_length", "")),
        "stricttf::sensitive_variable_unmarked",
    );
}

// --- outputs --------------------------------------------------------------------

#[test]
fn an_output_needs_a_description() {
    let main = "output \"a\" {\n  value = 1\n}\n\noutput \"b\" {\n  description = \"\"\n  value       = 2\n}\n\noutput \"c\" {\n  description = \"Three.\"\n  value       = 3\n}\n";
    let report = check_main(main);
    let found: Vec<_> = with_code(&report, "stricttf::output_missing_description")
        .into_iter()
        .map(at)
        .collect();
    assert_eq!(found, vec![("main.tf", 1, 1), ("main.tf", 6, 17)]);
}

// --- references ------------------------------------------------------------------

fn described(name: &str, extra: &str) -> String {
    format!("variable \"{name}\" {{\n  type        = string\n  description = \"D.\"\n{extra}}}\n")
}

#[test]
fn an_unreferenced_variable_is_a_warning_at_its_label() {
    let report = check_main(&described("unused", ""));
    let finding = only(&report, "stricttf::unused_variable");
    assert_eq!(finding.level, "warning");
    assert_eq!(at(finding), ("main.tf", 1, 10));
}

#[test]
fn a_reference_inside_the_variables_own_validation_does_not_count() {
    let validation = "  validation {\n    condition     = length(var.name) > 0\n    error_message = \"Required.\"\n  }\n";
    let report = check_main(&described("name", validation));
    only(&report, "stricttf::unused_variable");

    let cross = "  validation {\n    condition     = var.other != var.name\n    error_message = \"Distinct.\"\n  }\n";
    let pair = format!(
        "{}\n{}\noutput \"o\" {{\n  description = \"O.\"\n  value       = var.name\n}}\n",
        described("name", cross),
        described("other", "")
    );
    absent(&check_main(&pair), "stricttf::unused_variable");
}

#[test]
fn references_count_inside_templates_heredocs_for_expressions_and_blocks() {
    let variables: String = ["a", "b", "c", "d", "e", "f"]
        .iter()
        .map(|name| described(name, ""))
        .collect();
    let main = format!(
        r#"{variables}
resource "aws_s3_bucket" "logs" {{
  bucket = "logs-${{var.a}}"
  tags   = {{ for key in [var.b] : key => upper(var.c) }}

  dynamic "grant" {{
    for_each = var["d"] == "" ? [] : [1]
    content {{
      id = "x"
    }}
  }}
  policy = <<EOT
${{var.e}}
%{{if var.f != ""}}yes%{{endif}}
EOT
}}
"#
    );
    absent(&check_main(&main), "stricttf::unused_variable");
}

#[test]
fn an_unreferenced_local_is_a_warning_at_its_key() {
    let main = "locals {\n  used   = 1\n  unused = local.used\n}\n";
    let report = check_main(main);
    let finding = only(&report, "stricttf::unused_local");
    assert_eq!(finding.level, "warning");
    assert_eq!(at(finding), ("main.tf", 3, 3));
}

// --- module calls ------------------------------------------------------------------

fn call(source: &str, version: Option<&str>) -> Report {
    let version = version.map_or(String::new(), |version| {
        format!("  version = \"{version}\"\n")
    });
    check_main(&format!(
        "module \"net\" {{\n  source  = \"{source}\"\n{version}}}\n"
    ))
}

#[test]
fn a_registry_module_needs_a_version() {
    let report = call("terraform-aws-modules/vpc/aws", None);
    assert_eq!(
        at(only(&report, "stricttf::module_version_missing")),
        ("main.tf", 1, 1)
    );
    absent(
        &call("./modules/vpc", None),
        "stricttf::module_version_missing",
    );
    absent(
        &call("s3::https://s3.amazonaws.com/bucket/vpc.zip", None),
        "stricttf::module_version_missing",
    );
}

#[test]
fn a_registry_module_version_must_be_exact() {
    let report = call(
        "app.terraform.io/corp/vpc/aws//modules/core",
        Some("~> 5.0"),
    );
    assert_eq!(
        at(only(&report, "stricttf::module_version_inexact")),
        ("main.tf", 3, 13)
    );
    for exact in ["5.1.2", "= 5.1.2", "5.1.2-beta.1"] {
        let report = call("terraform-aws-modules/vpc/aws", Some(exact));
        absent(&report, "stricttf::module_version_inexact");
        absent(&report, "stricttf::module_version_missing");
    }
}

#[test]
fn a_vcs_module_needs_a_ref_that_is_not_a_branch() {
    let missing = only(
        &call("git::https://example.com/vpc.git", None),
        "stricttf::module_ref_missing",
    )
    .clone();
    assert_eq!(at(&missing), ("main.tf", 2, 13));
    let branch = only(
        &call("github.com/org/vpc?ref=main", None),
        "stricttf::module_ref_missing",
    )
    .clone();
    assert!(branch.message.contains("branch"), "{branch:?}");
    absent(
        &call("git::https://example.com/vpc.git//sub?ref=v1.2.0", None),
        "stricttf::module_ref_missing",
    );
    absent(
        &call("https://example.com/vpc-module.zip", None),
        "stricttf::module_ref_missing",
    );
}

// --- expressions ----------------------------------------------------------------------

#[test]
fn nondeterministic_functions_are_located_at_the_call() {
    let main = "locals {\n  stamp = timestamp()\n  id    = uuid()\n  all   = [local.stamp, local.id]\n}\n\noutput \"o\" {\n  description = \"O.\"\n  value       = local.all\n}\n";
    let found: Vec<_> = with_code(&check_main(main), "stricttf::nondeterministic_function")
        .into_iter()
        .map(|diagnostic| (diagnostic.at.line, diagnostic.at.col, diagnostic.at.end_col))
        .collect();
    assert_eq!(found, vec![(2, 11, 22), (3, 11, 17)]);
}

#[test]
fn stable_and_namespaced_functions_are_accepted() {
    let main = "locals {\n  day = formatdate(\"YYYY-MM-DD\", \"2024-01-01T00:00:00Z\")\n  ns  = provider::time::timestamp()\n  all = [local.day, local.ns]\n}\n\noutput \"o\" {\n  description = \"O.\"\n  value       = local.all\n}\n";
    absent(&check_main(main), "stricttf::nondeterministic_function");
}

#[test]
fn a_provisioner_in_any_resource_is_located_at_its_header() {
    let main = "resource \"terraform_data\" \"boot\" {\n  provisioner \"local-exec\" {\n    command = \"echo hi\"\n  }\n}\n";
    let finding = only(&check_main(main), "stricttf::provisioner").clone();
    assert_eq!(
        (finding.at.line, finding.at.col, finding.at.end_col),
        (2, 3, 27)
    );
    let plain = "resource \"terraform_data\" \"boot\" {\n  input = \"x\"\n  lifecycle {\n    create_before_destroy = true\n  }\n}\n";
    absent(&check_main(plain), "stricttf::provisioner");
}

#[test]
fn an_external_data_source_is_reported() {
    let main = "data \"external\" \"lookup\" {\n  program = [\"python3\", \"lookup.py\"]\n}\n";
    let report = check_module(&[("main.tf", main), ("versions.tf", VERSIONS)], &[], true);
    assert_eq!(
        at(only(&report, "stricttf::external_program")),
        ("main.tf", 1, 1)
    );
    absent(
        &check_main("data \"aws_caller_identity\" \"current\" {}\n"),
        "stricttf::external_program",
    );
}

fn interpolation_fixes(main: &str) -> Vec<(u64, u64, String)> {
    with_code(&check_main(main), "stricttf::interpolation_only")
        .into_iter()
        .map(|diagnostic| {
            let replacement = diagnostic
                .fixes
                .first()
                .map_or("<no fix>".to_owned(), |fix| fix.replace_with.clone());
            (diagnostic.at.line, diagnostic.at.col, replacement)
        })
        .collect()
}

#[test]
fn an_interpolation_only_string_is_fixed_to_its_expression() {
    let main = "locals {\n  a = \"${ var.name }\"\n  b = \"${var.flag ? 1 : 2}\" == \"1\"\n  c = \"${var.flag ? 1 : 2}\"\n  d = \"${var.x /* why */}\"\n}\n";
    assert_eq!(
        interpolation_fixes(main),
        vec![
            (2, 7, "var.name".to_owned()),
            (3, 7, "(var.flag ? 1 : 2)".to_owned()),
            (4, 7, "var.flag ? 1 : 2".to_owned()),
            (5, 7, "<no fix>".to_owned()),
        ]
    );
}

#[test]
fn templates_with_text_directives_heredocs_or_key_position_are_accepted() {
    let main = "locals {\n  a = \"prefix-${var.x}\"\n  b = \"%{if var.x != \"\"}${var.x}%{endif}\"\n  c = <<EOT\n${var.x}\nEOT\n  d = { \"${var.k}\" = 1 }\n  e = \"plain\"\n}\n";
    absent(&check_main(main), "stricttf::interpolation_only");
}

#[test]
fn ignore_changes_all_is_a_warning_at_the_value() {
    for (value, end_col) in [("all", 25), ("[\"*\"]", 27)] {
        let main = format!("resource \"aws_instance\" \"web\" {{\n  lifecycle {{\n    ignore_changes = {value}\n  }}\n}}\n");
        let report = check_main(&main);
        let finding = only(&report, "stricttf::ignore_changes_all");
        assert_eq!(finding.level, "warning");
        assert_eq!(
            (finding.at.line, finding.at.col, finding.at.end_col),
            (3, 22, end_col)
        );
    }
    let specific =
        "resource \"aws_instance\" \"web\" {\n  lifecycle {\n    ignore_changes = [tags]\n  }\n}\n";
    absent(&check_main(specific), "stricttf::ignore_changes_all");
}

#[test]
fn names_must_be_snake_case_at_their_label() {
    let main = "resource \"aws_s3_bucket\" \"LogBucket\" {}\n\nmodule \"net-work\" {\n  source = \"./net\"\n}\n\nlocals {\n  myLocal = 1\n  fine    = local.myLocal\n}\n\noutput \"Out\" {\n  description = \"O.\"\n  value       = local.fine\n}\n";
    let report = check_main(main);
    let found: Vec<_> = with_code(&report, "stricttf::name_not_snake_case")
        .into_iter()
        .map(at)
        .collect();
    assert_eq!(
        found,
        vec![
            ("main.tf", 1, 26),
            ("main.tf", 3, 8),
            ("main.tf", 8, 3),
            ("main.tf", 12, 8)
        ]
    );
    let snake = "resource \"aws_s3_bucket\" \"log_bucket\" {}\n\nvariable \"v2_name\" {\n  type        = string\n  description = \"V.\"\n}\n";
    absent(&check_main(snake), "stricttf::name_not_snake_case");
}

// --- incomplete modules --------------------------------------------------------------

#[test]
fn an_unparsable_file_suppresses_module_wide_absence_conclusions() {
    let broken = VERSIONS.trim_end().trim_end_matches('}');
    let main = "resource \"aws_s3_bucket\" \"logs\" {\n  bucket = var.name\n}\n\nlocals {\n  spare = 1\n}\n";
    let variables = "variable \"name\" {\n  description = \"Bucket name.\"\n}\n\nvariable \"spare\" {\n  type        = string\n  description = \"Unused here.\"\n}\n";
    let report = check_module(
        &[
            ("main.tf", main),
            ("variables.tf", variables),
            ("versions.tf", broken),
        ],
        &[("terraform.tfvars", "zone = \"a\"\n")],
        true,
    );
    only(&report, "stricttf::syntax_error");
    for code in [
        "stricttf::required_version_missing",
        "stricttf::provider_undeclared",
        "stricttf::unused_variable",
        "stricttf::unused_local",
        "stricttf::tfvars_undeclared",
    ] {
        absent(&report, code);
    }
    // Rules about a block that did parse still hold.
    only(&report, "stricttf::variable_missing_type");
}

// --- sensitive scalars ------------------------------------------------------------------

#[test]
fn a_credential_named_flag_or_count_need_not_be_sensitive() {
    for scalar in ["bool", "number"] {
        let main = format!("variable \"manage_master_user_password\" {{\n  type        = {scalar}\n  description = \"Flag.\"\n}}\n");
        absent(&check_main(&main), "stricttf::sensitive_variable_unmarked");
    }
    let quoted = "variable \"master_password\" {\n  type        = \"bool\"\n  description = \"Quoted.\"\n}\n";
    only(&check_main(quoted), "stricttf::sensitive_variable_unmarked");
    let collection = "variable \"master_password\" {\n  type        = list(string)\n  description = \"List.\"\n}\n";
    only(
        &check_main(collection),
        "stricttf::sensitive_variable_unmarked",
    );
}

// --- assertions ------------------------------------------------------------------------

#[test]
fn nondeterministic_functions_inside_assertions_are_accepted() {
    let main = r#"variable "expires" {
  type        = string
  description = "Expiry timestamp."

  validation {
    condition     = timecmp(var.expires, timestamp()) > 0
    error_message = "Must be in the future."
  }
}

check "fresh" {
  data "http" "probe" {
    url = "https://example.com/?t=${uuid()}"
  }

  assert {
    condition     = timecmp(plantimestamp(), var.expires) < 0
    error_message = "Expired."
  }
}

resource "aws_instance" "web" {
  lifecycle {
    precondition {
      condition     = timecmp(timestamp(), var.expires) < 0
      error_message = "Expired."
    }
  }
}

output "id" {
  description = "Instance."
  value       = aws_instance.web.id

  postcondition {
    condition     = uuid() != ""
    error_message = "Unreachable."
  }
}
"#;
    absent(&check_main(main), "stricttf::nondeterministic_function");

    let planned = "resource \"aws_instance\" \"web\" {\n  tags = { at = timestamp() }\n\n  lifecycle {\n    precondition {\n      condition     = true\n      error_message = \"x\"\n    }\n  }\n}\n";
    assert_eq!(
        at(only(
            &check_main(planned),
            "stricttf::nondeterministic_function"
        )),
        ("main.tf", 2, 17)
    );
}

// --- override files --------------------------------------------------------------------

#[test]
fn override_blocks_are_partial_and_not_held_to_declaration_rules() {
    let main = "variable \"db_password\" {\n  type        = string\n  description = \"Password.\"\n  sensitive   = true\n}\n\noutput \"o\" {\n  description = \"O.\"\n  value       = var.db_password\n}\n";
    let overrides = "terraform {\n  required_providers {\n    aws = { version = \"~> 5.1\" }\n  }\n}\n\nvariable \"db_password\" {\n  default = \"\"\n}\n\noutput \"o\" {\n  value = \"\"\n}\n";
    let report = check_module(
        &[
            ("main.tf", main),
            ("override.tf", overrides),
            ("versions.tf", VERSIONS),
        ],
        &[],
        true,
    );
    assert!(report.diagnostics.is_empty(), "{report:#?}");
}

#[test]
fn override_blocks_still_answer_to_expression_and_naming_rules() {
    let main = "variable \"name\" {\n  type        = string\n  description = \"Name.\"\n}\n";
    let overrides =
        "variable \"name\" {\n  type = map(any)\n}\n\nlocals {\n  BadName = \"${var.name}\"\n}\n";
    let report = check_module(
        &[
            ("main.tf", main),
            ("network_override.tf", overrides),
            ("versions.tf", VERSIONS),
        ],
        &[],
        true,
    );
    assert_eq!(
        at(only(&report, "stricttf::variable_any_type")),
        ("network_override.tf", 2, 10)
    );
    assert_eq!(
        at(only(&report, "stricttf::name_not_snake_case")),
        ("network_override.tf", 6, 3)
    );
    only(&report, "stricttf::interpolation_only");
    // The override's reference counts toward var.name, so it is used.
    absent(&report, "stricttf::unused_variable");
    only(&report, "stricttf::unused_local");
}

#[test]
fn a_variable_redeclared_in_an_override_is_reported_unused_once() {
    let main = "variable \"spare\" {\n  type        = string\n  description = \"Spare.\"\n}\n";
    let overrides = "variable \"spare\" {\n  default = \"x\"\n}\n";
    let report = check_module(
        &[
            ("main.tf", main),
            ("override.tf", overrides),
            ("versions.tf", VERSIONS),
        ],
        &[],
        true,
    );
    assert_eq!(
        at(only(&report, "stricttf::unused_variable")),
        ("main.tf", 1, 10)
    );
    assert_eq!(report.diagnostics.len(), 1, "{report:#?}");
}

#[test]
fn required_version_is_never_located_in_an_override_file() {
    let report = check_module(
        &[
            ("a_override.tf", "terraform {\n  backend \"local\" {}\n}\n"),
            ("main.tf", "locals {}\n"),
        ],
        &[],
        true,
    );
    assert_eq!(
        at(only(&report, "stricttf::required_version_missing")),
        ("main.tf", 1, 1)
    );
}

// --- required_version bounds ------------------------------------------------------------

fn versions_with(required: &str) -> String {
    VERSIONS.replace("\"~> 1.9\"", &format!("\"{required}\""))
}

#[test]
fn a_lower_bound_only_required_version_is_unbounded_at_the_value() {
    for required in [">= 1.6.0", "> 1.5", ">= 1.6, != 1.7.0"] {
        let versions = versions_with(required);
        let report = check_module(&[("versions.tf", &versions)], &[], true);
        let finding = only(&report, "stricttf::required_version_unbounded");
        assert_eq!(finding.level, "error");
        assert_eq!(at(finding), ("versions.tf", 2, 22), "{required}");
        assert_eq!(
            finding.at.end_col,
            24 + u64::try_from(required.len()).expect("short"),
            "{required}"
        );
        absent(&report, "stricttf::required_version_missing");
    }
}

#[test]
fn a_capped_required_version_is_accepted() {
    for required in [
        "~> 1.9",
        ">= 1.6.0, < 2.0.0",
        "<= 1.16.5",
        "1.16.5",
        "= 1.16.5",
    ] {
        let versions = versions_with(required);
        let report = check_module(&[("versions.tf", &versions)], &[], true);
        assert!(report.diagnostics.is_empty(), "{required}: {report:#?}");
    }
}

// --- count over a collection ------------------------------------------------------------

#[test]
fn count_over_the_length_of_a_collection_is_located_at_the_value() {
    for block in [
        "resource \"aws_instance\" \"web\"",
        "data \"aws_ami\" \"web\"",
        "module \"web\"",
    ] {
        let main = format!("{block} {{\n  count = length(var.names)\n}}\n");
        let finding = only(&check_main(&main), "stricttf::count_over_collection").clone();
        assert_eq!(at(&finding), ("main.tf", 2, 11), "{block}");
        assert_eq!(finding.at.end_col, 28, "{block}");
    }
}

#[test]
fn toggles_constants_and_for_each_are_not_count_over_a_collection() {
    for meta in [
        "count = var.enabled ? 1 : 0",
        "count = 3",
        "count = length(var.names) > 0 ? 1 : 0",
        "for_each = toset(var.names)",
        "count = provider::ns::length(var.names)",
    ] {
        let main = format!("resource \"aws_instance\" \"web\" {{\n  {meta}\n}}\n");
        absent(&check_main(&main), "stricttf::count_over_collection");
    }
    let local = "locals {\n  count = length(var.names)\n}\n";
    absent(&check_main(local), "stricttf::count_over_collection");
}

// --- deprecated index syntax ------------------------------------------------------------

/// Each `deprecated_index` finding as `(line, col, end_col, fix)`.
fn deprecated_indexes(main: &str) -> Vec<(u64, u64, u64, Option<String>)> {
    with_code(&check_main(main), "stricttf::deprecated_index")
        .into_iter()
        .map(|diagnostic| {
            (
                diagnostic.at.line,
                diagnostic.at.col,
                diagnostic.at.end_col,
                diagnostic.fixes.first().map(|fix| fix.replace_with.clone()),
            )
        })
        .collect()
}

#[test]
fn a_legacy_dot_index_is_fixed_to_brackets() {
    let main = "locals {\n  a = aws_instance.web.0.id\n  b = \"${aws_instance.web.12.id}\"\n}\n";
    assert_eq!(
        deprecated_indexes(main),
        vec![
            (2, 23, 25, Some("[0]".to_owned())),
            (3, 26, 29, Some("[12]".to_owned())),
        ]
    );
}

#[test]
fn an_attribute_splat_is_fixed_only_when_no_index_or_splat_follows() {
    let main = "locals {\n  a = aws_instance.web.*.id\n  b = aws_instance.web.*.ids[0]\n  c = aws_instance.web.*.ids.0\n  d = aws_instance.web.*.tags.*.name\n}\n";
    assert_eq!(
        deprecated_indexes(main),
        vec![
            (2, 23, 25, Some("[*]".to_owned())),
            (3, 23, 25, None),
            // `.0` after `.*` is captured by the splat; `[0]` would not be.
            (4, 23, 25, None),
            (4, 29, 31, None),
            (5, 23, 25, None),
            (5, 30, 32, None),
        ]
    );
}

#[test]
fn bracket_indexes_and_full_splats_are_accepted() {
    let main = "locals {\n  a = aws_instance.web[0].id\n  b = aws_instance.web[*].ids[0]\n  c = var.map[\"k\"].v\n  d = (aws_instance.web[*].ids)[0]\n}\n";
    assert!(deprecated_indexes(main).is_empty());
}

// --- comment syntax ---------------------------------------------------------------------

#[test]
fn a_double_slash_comment_is_located_and_fixed_to_a_hash() {
    let main = "// leading\nlocals {\n  a = 1 // trailing  \n}\n";
    let report = check_main(main);
    let found = with_code(&report, "stricttf::comment_syntax");
    let places: Vec<_> = found
        .iter()
        .map(|diagnostic| {
            let fix = &diagnostic.fixes[0];
            (
                at(diagnostic),
                diagnostic.at.end_col,
                (fix.line, fix.col, fix.end_col, fix.replace_with.as_str()),
            )
        })
        .collect();
    assert_eq!(
        places,
        vec![
            (("main.tf", 1, 1), 11, (1, 1, 3, "#")),
            (("main.tf", 3, 9), 20, (3, 9, 11, "#")),
        ]
    );
}

#[test]
fn the_fixed_comment_reparses_and_is_not_reported_again() {
    let fixed = "# leading\nlocals {\n  a = 1 # trailing\n}\n";
    stricttf::hcl::parse(&source("main.tf", fixed)).expect("fixed file should parse");
    absent(&check_main(fixed), "stricttf::comment_syntax");
}

#[test]
fn double_slashes_in_strings_heredocs_labels_and_other_comments_are_accepted() {
    let main = "locals {\n  url = \"https://example.com//path\"\n  tpl = \"${var.x}//${var.y}\"\n  doc = <<EOT\n  // not a comment\nEOT\n  key = { \"a//b\" = 1 }\n  /* block // comment */\n  # hash // comment\n  q = 4 / 2\n}\n\nresource \"aws_s3_bucket\" \"x\" {\n  bucket = \"a//b\"\n}\n";
    absent(&check_main(main), "stricttf::comment_syntax");
}

#[test]
fn a_double_slash_comment_in_a_tfvars_file_is_reported() {
    let report = check_module(
        &[("versions.tf", VERSIONS)],
        &[("terraform.tfvars", "// note\n")],
        true,
    );
    assert_eq!(
        at(only(&report, "stricttf::comment_syntax")),
        ("terraform.tfvars", 1, 1)
    );
}

// --- sensitive outputs ------------------------------------------------------------------

fn output(name: &str, extra: &str) -> String {
    format!("output \"{name}\" {{\n  description = \"D.\"\n  value       = \"x\"\n{extra}}}\n")
}

#[test]
fn a_credential_output_must_be_sensitive_at_its_label() {
    for extra in ["", "  sensitive   = false\n"] {
        let report = check_main(&output("db_password", extra));
        let finding = only(&report, "stricttf::sensitive_output_unmarked");
        assert_eq!(at(finding), ("main.tf", 1, 8));
        assert_eq!(finding.at.end_col, 21);
    }
}

#[test]
fn sensitive_computed_or_non_credential_outputs_are_accepted() {
    for main in [
        output("db_password", "  sensitive   = true\n"),
        output("db_password", "  sensitive   = var.hide\n"),
        output("password_length", ""),
        output("secret_arn", ""),
    ] {
        absent(&check_main(&main), "stricttf::sensitive_output_unmarked");
    }
    let report = check_module(
        &[
            ("main.tf", &output("db_password", "  sensitive   = true\n")),
            (
                "override.tf",
                "output \"db_password\" {\n  value = \"y\"\n}\n",
            ),
            ("versions.tf", VERSIONS),
        ],
        &[],
        true,
    );
    absent(&report, "stricttf::sensitive_output_unmarked");
}

// --- lock file platforms ----------------------------------------------------------------

fn check_locked(lock: &str) -> Report {
    let sources = ModuleSources {
        configuration: vec![
            source("main.tf", "resource \"aws_s3_bucket\" \"logs\" {}\n"),
            source("versions.tf", VERSIONS),
        ],
        variable_files: Vec::new(),
        test_files: Vec::new(),
        lock_file: Some(source(".terraform.lock.hcl", lock)),
    };
    let (diagnostics, _checkable) = stricttf::check_sources(&sources);
    Report::build(diagnostics)
}

fn lock_with(hashes: &[&str]) -> String {
    let hashes: String = hashes
        .iter()
        .map(|hash| format!("    \"{hash}\",\n"))
        .collect();
    format!("# lock\n\nprovider \"registry.terraform.io/hashicorp/aws\" {{\n  version     = \"5.100.0\"\n  constraints = \"~> 5.0\"\n  hashes = [\n{hashes}  ]\n}}\n")
}

#[test]
fn a_lock_entry_with_one_platform_hash_is_a_warning_at_the_provider_header() {
    let report = check_locked(&lock_with(&[
        "h1:Ijt7pOlB7Tr7maGQIqtsLFbl7pSMIj06TVdkoSBcYOw=",
    ]));
    let finding = only(&report, "stricttf::lock_file_single_platform");
    assert_eq!(finding.level, "warning");
    assert_eq!(at(finding), (".terraform.lock.hcl", 3, 1));
    assert_eq!(finding.at.end_col, 47);
    assert!(finding
        .message
        .contains("terraform providers lock -platform=linux_amd64 -platform=darwin_arm64"));
    absent(&report, "stricttf::lock_file_missing");
}

#[test]
fn a_registry_lock_or_a_multi_platform_lock_is_accepted() {
    let registry = support::fixture_text("clean/.terraform.lock.hcl");
    absent(
        &check_locked(&registry),
        "stricttf::lock_file_single_platform",
    );
    let mirrored = lock_with(&["h1:aaaa", "h1:bbbb"]);
    absent(
        &check_locked(&mirrored),
        "stricttf::lock_file_single_platform",
    );
}

// --- coupling and ordering --------------------------------------------------------------

#[test]
fn remote_state_is_a_warning_at_the_data_header() {
    let main = "data \"terraform_remote_state\" \"net\" {\n  backend = \"local\"\n}\n";
    let finding = only(&check_main(main), "stricttf::remote_state_coupling").clone();
    assert_eq!(finding.level, "warning");
    assert_eq!(at(&finding), ("main.tf", 1, 1));
    assert_eq!(finding.at.end_col, 36);
    let ssm = "data \"aws_ssm_parameter\" \"vpc_id\" {\n  name = \"/network/vpc_id\"\n}\n";
    absent(&check_main(ssm), "stricttf::remote_state_coupling");
}

#[test]
fn depends_on_in_a_module_is_a_warning_at_the_attribute() {
    let main = "module \"app\" {\n  source     = \"./app\"\n  depends_on = [aws_iam_role.app]\n}\n";
    let finding = only(&check_main(main), "stricttf::module_depends_on").clone();
    assert_eq!(finding.level, "warning");
    assert_eq!(at(&finding), ("main.tf", 3, 3));
    assert_eq!(finding.at.end_col, 34);
    let resource = "resource \"aws_instance\" \"web\" {\n  depends_on = [aws_iam_role.app]\n}\n";
    absent(&check_main(resource), "stricttf::module_depends_on");
}

// --- fixtures ----------------------------------------------------------------------------

#[test]
fn the_clean_fixture_produces_no_diagnostics() {
    let fixture = module_fixture("clean");
    let report = stricttf::run_check_with_depth(fixture.path(), Depth::SourceOnly)
        .expect("clean fixture should be checkable");
    assert!(report.diagnostics.is_empty(), "{report:#?}");
    assert!(report.ok);
}

#[test]
fn the_kitchen_sink_fixture_produces_exactly_its_expected_codes() {
    let fixture = module_fixture("kitchen-sink");
    let report = stricttf::run_check_with_depth(fixture.path(), Depth::SourceOnly)
        .expect("kitchen-sink fixture should be checkable");
    let expected: BTreeSet<String> = support::fixture_text("kitchen-sink/expected-codes.txt")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(stricttf_codes(&report), expected, "{report:#?}");
}

#[test]
fn the_fixable_fixture_converges_and_stays_fixed() {
    let fixture = module_fixture("fixable");
    let report = stricttf::run_fix_with_limit(fixture.path(), Depth::SourceOnly, 10)
        .expect("fix loop should run");
    assert!(report.ok, "{report:#?}");
    assert!(fixture
        .read("variables.tf")
        .contains("type        = string\n"));
    assert!(fixture
        .read("main.tf")
        .contains("bucket = var.bucket_name\n"));
    assert!(fixture
        .read("outputs.tf")
        .contains("value       = aws_s3_bucket.artifacts.arn\n"));

    let files = ["main.tf", "outputs.tf", "variables.tf"];
    let before: Vec<String> = files.iter().map(|file| fixture.read(file)).collect();
    let again = stricttf::run_fix_with_limit(fixture.path(), Depth::SourceOnly, 10)
        .expect("fix loop should run again");
    assert!(again.ok, "{again:#?}");
    let after: Vec<String> = files.iter().map(|file| fixture.read(file)).collect();
    assert_eq!(before, after);
}

#[test]
fn an_unparsable_file_does_not_hide_rules_on_the_parsable_ones() {
    let fixture = module_fixture("unparsable");
    let report = stricttf::run_check_with_depth(fixture.path(), Depth::SourceOnly)
        .expect("unparsable fixture should be checkable");
    let syntax = only(&report, "stricttf::syntax_error");
    assert_eq!(syntax.at.file, "broken.tf");
    assert_eq!(
        at(only(&report, "stricttf::variable_missing_type")),
        ("variables.tf", 1, 1)
    );
    // broken.tf could hold the requirement or the reference, so absence
    // is not concluded from the half that parsed.
    absent(&report, "stricttf::required_version_missing");
    absent(&report, "stricttf::unused_variable");
}

// --- robustness ----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_text_never_panics_and_reports_deterministically(
        text in "(variable|resource|locals|module|terraform|\"|\\$\\{|\\}|\\{|=|var\\.x|local\\.y|any|timestamp\\(\\)|\\[|\\]|,|\\n| |[a-z_]{1,6}|.){0,60}"
    ) {
        let first = check_files(&[("main.tf", &text)]);
        let second = check_files(&[("main.tf", &text)]);
        prop_assert_eq!(first, second);
    }
}
