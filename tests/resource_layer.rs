mod support;

use proptest::prelude::{prop_assert, proptest, ProptestConfig};
use std::collections::BTreeSet;
use stricttf::report::{Diagnostic, Report};
use stricttf::Depth;
use support::{check_files, codes, module_fixture, with_code};

const RESOURCE_CODES: &[&str] = &[
    "stricttf::hardcoded_secret",
    "stricttf::open_admin_ingress",
    "stricttf::public_bucket_acl",
    "stricttf::public_database",
    "stricttf::wildcard_iam_action",
];

fn check(text: &str) -> Report {
    check_files(&[("main.tf", text)])
}

/// Check a configuration together with one variable file.
fn check_with_tfvars(configuration: &str, tfvars: &str) -> Report {
    let file = |path: &str, text: &str| stricttf::hcl::SourceFile {
        path: path.to_owned(),
        text: text.to_owned(),
    };
    let sources = stricttf::ModuleSources {
        configuration: vec![file("main.tf", configuration)],
        variable_files: vec![file("terraform.tfvars", tfvars)],
        ..stricttf::ModuleSources::default()
    };
    let (diagnostics, _checkable) = stricttf::check_sources(&sources);
    Report::build(diagnostics)
}

/// The `(line, col)` of every diagnostic carrying `code`.
fn positions(report: &Report, code: &str) -> Vec<(u64, u64)> {
    with_code(report, code)
        .iter()
        .map(|diagnostic| (diagnostic.at.line, diagnostic.at.col))
        .collect()
}

fn located_text<'a>(text: &'a str, diagnostic: &Diagnostic) -> &'a str {
    let line = text
        .lines()
        .nth(usize::try_from(diagnostic.at.line - 1).unwrap())
        .unwrap();
    let start = usize::try_from(diagnostic.at.col - 1).unwrap();
    let end = usize::try_from(diagnostic.at.end_col - 1).unwrap();
    &line[start..end]
}

// --- hardcoded_secret -------------------------------------------------

#[test]
fn literal_password_on_a_resource_is_a_hardcoded_secret() {
    let text = "resource \"aws_db_instance\" \"main\" {\n  password = \"hunter2-hunter2\"\n}\n";
    let report = check(text);
    let found = with_code(&report, "stricttf::hardcoded_secret");
    assert_eq!(found.len(), 1, "{:?}", codes(&report));
    assert_eq!((found[0].at.line, found[0].at.col), (2, 14));
    assert_eq!(located_text(text, found[0]), "\"hunter2-hunter2\"");
    assert_eq!(found[0].level, "error");
    assert!(
        !found[0].message.contains("hunter2"),
        "{}",
        found[0].message
    );
    assert!(found[0].message.contains("password"));
}

#[test]
fn secrets_are_found_in_nested_blocks_and_object_keys() {
    let text = r#"resource "aws_lambda_function" "worker" {
  environment {
    variables = {
      DB_PASSWORD = "hunter2-hunter2"
      "api_token" = "tok-123"
      settings = {
        client_secret = "deep"
      }
    }
  }
}
"#;
    let report = check(text);
    assert_eq!(
        positions(&report, "stricttf::hardcoded_secret"),
        vec![(4, 21), (5, 21), (7, 25)]
    );
}

#[test]
fn secrets_are_found_in_provider_module_data_ephemeral_and_locals() {
    let text = r#"provider "aws" {
  secret_key = "AKIAEXAMPLE"
}

module "db" {
  source         = "./db"
  admin_password = "literal"
}

data "vault_generic_secret" "x" {
  token = "s.literal"
}

ephemeral "random_password" "x" {
  api_key = "literal"
}

locals {
  service_token = "literal"
}
"#;
    let report = check(text);
    assert_eq!(
        positions(&report, "stricttf::hardcoded_secret"),
        vec![(2, 16), (7, 20), (11, 11), (15, 13), (19, 19)]
    );
}

#[test]
fn literal_default_of_a_secret_variable_is_a_hardcoded_secret() {
    let text = "variable \"api_token\" {\n  type      = string\n  sensitive = true\n  default   = \"tok-123\"\n}\n";
    let report = check(text);
    assert_eq!(
        positions(&report, "stricttf::hardcoded_secret"),
        vec![(4, 15)]
    );
}

#[test]
fn literal_secret_in_a_variable_file_is_a_hardcoded_secret() {
    let report = check_with_tfvars(
        "variable \"db_password\" {\n  type = string\n}\n",
        "region      = \"us-east-1\"\ndb_password = \"hunter2\"\n",
    );
    let found = with_code(&report, "stricttf::hardcoded_secret");
    assert_eq!(found.len(), 1, "{:?}", codes(&report));
    assert_eq!(found[0].at.file, "terraform.tfvars");
    assert_eq!((found[0].at.line, found[0].at.col), (2, 15));
}

#[test]
fn references_empty_strings_and_secret_metadata_are_not_secrets() {
    let text = r#"variable "db_password" {
  type      = string
  sensitive = true
}

variable "password_length" {
  type    = number
  default = 16
}

variable "api_token" {
  type    = string
  default = ""
}

resource "aws_db_instance" "main" {
  password        = var.db_password
  token           = ""
  secret_arn      = "arn:aws:secretsmanager:us-east-1:123456789012:secret:x"
  password_length = 16
  api_key         = "${var.db_password}-suffix"
}

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length = 16
}

output "password" {
  value = "not a configuration argument"
}
"#;
    let report = check(text);
    assert!(
        with_code(&report, "stricttf::hardcoded_secret").is_empty(),
        "{:?}",
        with_code(&report, "stricttf::hardcoded_secret")
    );
}

#[test]
fn non_secret_variable_with_literal_default_is_not_a_secret() {
    let text = "variable \"region\" {\n  default = \"us-east-1\"\n}\n";
    let report = check(text);
    assert!(with_code(&report, "stricttf::hardcoded_secret").is_empty());
}

#[test]
fn secrets_are_found_in_terraform_blocks_outputs_and_object_defaults() {
    let text = r#"terraform {
  backend "s3" {
    bucket     = "state"
    access_key = "AKIAEXAMPLE"
    secret_key = "literal"
  }
}

output "connection" {
  value = { username = "app", password = "hunter2" }
}

variable "database" {
  type = object({ username = string, password = string })
  default = {
    username = "app"
    nested   = { api_token = "tok-123" }
    password = "hunter2"
  }
}
"#;
    let report = check(text);
    assert_eq!(
        positions(&report, "stricttf::hardcoded_secret"),
        vec![(4, 18), (5, 18), (10, 42), (17, 30), (18, 16)]
    );
    let messages: Vec<&str> = with_code(&report, "stricttf::hardcoded_secret")
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect();
    assert!(
        messages.iter().all(|message| !message.contains("hunter2")),
        "{messages:?}"
    );
}

#[test]
fn identifiers_and_computed_values_in_new_locations_are_not_secrets() {
    let text = r#"terraform {
  backend "s3" {
    bucket     = "state"
    access_key = var.access_key
  }
}

variable "access_key" {
  type      = string
  sensitive = true
}

output "connection" {
  value = { username = "app", password = var.access_key }
}

variable "database" {
  type    = object({ username = string, password = string })
  default = { username = "app", password = "" }
}

resource "aws_efs_file_system" "shared" {
  creation_token = "my-product"
}

resource "google_cloud_run_v2_service" "api" {
  template {
    containers {
      env {
        value_source {
          secret_key_ref {
            secret  = "my-secret"
            version = "latest"
          }
        }
      }
    }
  }
}

resource "aws_lambda_invocation" "once" {
  client_token      = "deploy-1"
  idempotency_token = "deploy-1"
}
"#;
    let report = check(text);
    assert!(
        with_code(&report, "stricttf::hardcoded_secret").is_empty(),
        "{:?}",
        with_code(&report, "stricttf::hardcoded_secret")
    );
}

// --- open_admin_ingress ------------------------------------------------

#[test]
fn world_open_ssh_in_a_security_group_is_reported_at_the_cidr() {
    let text = r#"resource "aws_security_group" "bastion" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"]
  }
}
"#;
    let report = check(text);
    let found = with_code(&report, "stricttf::open_admin_ingress");
    assert_eq!(found.len(), 1, "{:?}", codes(&report));
    assert_eq!(located_text(text, found[0]), "\"0.0.0.0/0\"");
    assert_eq!((found[0].at.line, found[0].at.col), (6, 34));
    assert!(found[0].message.contains("SSH"), "{}", found[0].message);
}

#[test]
fn all_protocols_and_wide_tcp_ranges_are_reported() {
    let text = r#"resource "aws_security_group_rule" "everything" {
  type             = "ingress"
  from_port        = 0
  to_port          = 0
  protocol         = "-1"
  ipv6_cidr_blocks = ["::/0"]
}

resource "aws_security_group" "numeric" {
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "range" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;
    let report = check(text);
    assert_eq!(
        positions(&report, "stricttf::open_admin_ingress"),
        vec![(6, 23), (14, 20), (23, 20)]
    );
    let messages: Vec<&str> = with_code(&report, "stricttf::open_admin_ingress")
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect();
    assert!(messages[0].contains("every port"), "{}", messages[0]);
    assert!(
        messages[2].contains("SSH") && messages[2].contains("RDP"),
        "{}",
        messages[2]
    );
}

#[test]
fn world_open_rdp_in_a_vpc_ingress_rule_is_reported() {
    let text = r#"resource "aws_vpc_security_group_ingress_rule" "rdp" {
  security_group_id = "sg-123"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 3389
  to_port           = 3389
  ip_protocol       = "tcp"
}
"#;
    let report = check(text);
    assert_eq!(
        positions(&report, "stricttf::open_admin_ingress"),
        vec![(3, 23)]
    );
}

#[test]
fn https_private_sources_egress_icmp_and_computed_ports_are_not_admin_ingress() {
    let text = r#"variable "port" {
  type = number
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    from_port   = var.port
    to_port     = var.port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8
    to_port     = 0
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "out" {
  type        = "egress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = "sg-123"
  cidr_ipv6         = "::/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}
"#;
    let report = check(text);
    assert!(
        with_code(&report, "stricttf::open_admin_ingress").is_empty(),
        "{:?}",
        with_code(&report, "stricttf::open_admin_ingress")
    );
}

// --- public_bucket_acl -------------------------------------------------

#[test]
fn public_canned_acl_is_reported_on_both_bucket_resources() {
    let text = r#"resource "aws_s3_bucket" "legacy" {
  acl = "public-read-write"
}

resource "aws_s3_bucket_acl" "site" {
  bucket = "site"
  acl    = "authenticated-read"
}
"#;
    let report = check(text);
    assert_eq!(
        positions(&report, "stricttf::public_bucket_acl"),
        vec![(2, 9), (7, 12)]
    );
}

#[test]
fn private_and_computed_acls_are_not_public() {
    let text = r#"variable "acl" {
  type = string
}

resource "aws_s3_bucket_acl" "site" {
  bucket = "site"
  acl    = "private"
}

resource "aws_s3_bucket_acl" "computed" {
  bucket = "computed"
  acl    = var.acl
}

resource "aws_s3_object" "unrelated" {
  acl = "public-read"
}
"#;
    let report = check(text);
    assert!(with_code(&report, "stricttf::public_bucket_acl").is_empty());
}

// --- public_database ---------------------------------------------------

#[test]
fn publicly_accessible_database_is_reported_at_the_value() {
    let text = r#"resource "aws_db_instance" "main" {
  publicly_accessible = true
}

resource "aws_redshift_cluster" "warehouse" {
  publicly_accessible = true
}

resource "aws_dms_replication_instance" "quoted" {
  publicly_accessible = "True"
}
"#;
    let report = check(text);
    assert_eq!(
        positions(&report, "stricttf::public_database"),
        vec![(2, 25), (6, 25), (10, 25)]
    );
}

#[test]
fn private_and_computed_databases_are_not_public() {
    let text = r#"variable "public" {
  type = bool
}

resource "aws_db_instance" "main" {
  publicly_accessible = false
}

resource "aws_redshift_cluster" "quoted" {
  publicly_accessible = "false"
}

resource "aws_rds_cluster_instance" "computed" {
  publicly_accessible = var.public
}

resource "aws_instance" "unrelated" {
  publicly_accessible = true
}
"#;
    let report = check(text);
    assert!(with_code(&report, "stricttf::public_database").is_empty());
}

// --- wildcard_iam_action -----------------------------------------------

#[test]
fn wildcard_action_in_a_policy_document_is_reported_at_the_literal() {
    let text = r#"data "aws_iam_policy_document" "admin" {
  statement {
    actions   = ["s3:GetObject", "*"]
    resources = ["*"]
  }

  statement {
    effect  = "Allow"
    actions = ["*:*"]
  }
}
"#;
    let report = check(text);
    let found = with_code(&report, "stricttf::wildcard_iam_action");
    assert_eq!(
        positions(&report, "stricttf::wildcard_iam_action"),
        vec![(3, 34), (9, 16)]
    );
    assert_eq!(located_text(text, found[0]), "\"*\"");
}

#[test]
fn wildcard_action_in_jsonencode_is_reported_at_any_depth() {
    let text = r#"resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
      {
        "Action" = ["s3:GetObject", "*:*"]
      },
    ]
  })
}
"#;
    let report = check(text);
    assert_eq!(
        positions(&report, "stricttf::wildcard_iam_action"),
        vec![(7, 20), (11, 37)]
    );
}

#[test]
fn scoped_denied_negated_and_computed_statements_are_not_wildcards() {
    let text = r#"variable "effect" {
  type = string
}

data "aws_iam_policy_document" "guard" {
  statement {
    actions = ["s3:GetObject", "s3:*"]
  }

  statement {
    effect  = "Deny"
    actions = ["*"]
  }

  statement {
    not_actions = ["*"]
  }

  statement {
    effect  = var.effect
    actions = ["*"]
  }
}

resource "aws_iam_policy" "guard" {
  policy = jsonencode({
    Statement = [
      { Effect = "Deny", Action = "*", Resource = "*" },
      { Effect = "Allow", NotAction = "*", Resource = "*" },
      { Effect = "Allow", Action = ["s3:*"], Resource = "*" },
    ]
  })
}

locals {
  unencoded = { Effect = "Allow", Action = "*" }
}
"#;
    let report = check(text);
    assert!(
        with_code(&report, "stricttf::wildcard_iam_action").is_empty(),
        "{:?}",
        with_code(&report, "stricttf::wildcard_iam_action")
    );
}

// --- fixtures ----------------------------------------------------------

#[test]
fn insecure_fixture_produces_exactly_the_expected_resource_codes() {
    let fixture = module_fixture("insecure");
    let report = stricttf::run_check_with_depth(fixture.path(), Depth::SourceOnly).unwrap();
    let found: BTreeSet<String> = codes(&report)
        .into_iter()
        .filter(|code| RESOURCE_CODES.contains(&code.as_str()))
        .collect();
    let expected: BTreeSet<String> = fixture
        .read("expected-codes.txt")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect();
    assert_eq!(found, expected);
}

#[test]
fn secure_fixture_is_clean() {
    let fixture = module_fixture("secure");
    let report = stricttf::run_check_with_depth(fixture.path(), Depth::SourceOnly).unwrap();
    assert!(report.diagnostics.is_empty(), "{:#?}", report.diagnostics);
}

// --- robustness --------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_input_never_panics(text in "\\PC{0,400}") {
        let report = check(&text);
        prop_assert!(report.diagnostics.len() < usize::MAX);
    }

    #[test]
    fn resource_shaped_input_never_panics(
        kind in "(aws_security_group|aws_security_group_rule|aws_vpc_security_group_ingress_rule|aws_s3_bucket_acl|aws_db_instance)",
        key in "(password|cidr_blocks|cidr_ipv4|from_port|to_port|protocol|ip_protocol|acl|publicly_accessible|type)",
        value in "(\"\"|\"0.0.0.0/0\"|\\[\"::/0\"\\]|-1|22|99999999999999999999|true|var\\.x|jsonencode\\(\\{Action = \"\\*\"\\}\\)|\"\\PC{0,8}\")",
    ) {
        let text = format!(
            "resource \"{kind}\" \"x\" {{\n  {key} = {value}\n  ingress {{\n    {key} = {value}\n  }}\n}}\n"
        );
        let report = check(&text);
        prop_assert!(report.diagnostics.len() < usize::MAX);
    }
}
