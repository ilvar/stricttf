//! Resource policy layer.
//!
//! Some security defects are fully decided by the configuration text: a
//! password written as a literal, a security group open to the internet
//! on SSH, a bucket ACL that grants public read. This layer reports only
//! those. Whenever a value is computed -- a variable reference, a
//! function call, a template with interpolation -- the outcome depends on
//! inputs `stricttf` cannot see, and the construct is left alone rather
//! than guessed at. A finding here is therefore always a defect in the
//! bytes it points at, never a hunch about what a plan might produce.

use crate::hcl::{self, ParsedFile};
use crate::report::{Diagnostic, LEVEL_ERROR};
use crate::Module;
use hcl_edit::expr::{Expression, FuncCall, Object, ObjectKey};
use hcl_edit::structure::{Attribute, Block, Body};
use hcl_edit::visit::{visit_attr, visit_func_call, visit_object, Visit};
use hcl_edit::Span;
use std::ops::Range;

/// Top-level blocks whose arguments are sent to providers, backends, or
/// child modules, or published as outputs, so a literal credential there
/// is committed configuration.
const SECRET_BEARING_BLOCKS: &[&str] = &[
    "data",
    "ephemeral",
    "locals",
    "module",
    "output",
    "provider",
    "resource",
    "terraform",
];

/// CIDR ranges that admit every address.
const WORLD_CIDRS: &[&str] = &["0.0.0.0/0", "::/0"];

/// Protocol values that mean "every protocol, every port" to AWS.
const ALL_PROTOCOLS: &[&str] = &["-1", "all"];

/// Protocol values under which a port range names TCP ports. Other
/// protocols (ICMP in particular) reuse the port fields for something
/// else, so a range there says nothing about SSH or RDP.
const TCP_PROTOCOLS: &[&str] = &["6", "tcp"];

/// Administrative ports that must never face the internet.
const ADMIN_PORTS: &[(u64, &str)] = &[(22, "SSH (port 22)"), (3389, "RDP (port 3389)")];

/// Canned S3 ACLs that grant read or write beyond the bucket owner.
const PUBLIC_ACLS: &[&str] = &["authenticated-read", "public-read", "public-read-write"];

/// Resource types whose `publicly_accessible` argument attaches a public
/// endpoint to a database.
const DATABASE_TYPES: &[&str] = &[
    "aws_db_instance",
    "aws_dms_replication_instance",
    "aws_rds_cluster_instance",
    "aws_redshift_cluster",
];

/// IAM action patterns that grant every action on every service.
/// Service wildcards such as `s3:*` are deliberately absent: they are
/// broad, but scoped, and often the intended grant.
const WILDCARD_ACTIONS: &[&str] = &["*", "*:*"];

/// Check every resource rule against a parsed module.
pub fn check(module: &Module) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    for file in &module.configuration {
        for block in file.body.blocks() {
            check_block(file, block, &mut diagnostics);
        }
        check_policy_documents(file, &mut diagnostics);
    }

    for file in &module.variable_files {
        let mut finder = SecretFinder::default();
        finder.visit_body(&file.body);
        report_secrets(file, finder.found, "this variable file", &mut diagnostics);
    }

    diagnostics
}

fn check_block(file: &ParsedFile, block: &Block, diagnostics: &mut Vec<Diagnostic>) {
    let ident = block.ident.as_str();
    let context = describe(block);

    if SECRET_BEARING_BLOCKS.contains(&ident) {
        let mut finder = SecretFinder::default();
        finder.visit_body(&block.body);
        report_secrets(file, finder.found, &context, diagnostics);
    }

    match (ident, hcl::label(block, 0)) {
        ("variable", Some(name)) => check_variable_default(file, block, name, diagnostics),
        ("resource", Some("aws_security_group")) => {
            for ingress in block
                .body
                .blocks()
                .filter(|nested| nested.has_ident("ingress"))
            {
                check_cidr_ingress(file, &ingress.body, &context, diagnostics);
            }
        }
        ("resource", Some("aws_security_group_rule")) => {
            let is_ingress = hcl::attribute(&block.body, "type")
                .and_then(|attribute| hcl::literal_string(&attribute.value))
                == Some("ingress");
            if is_ingress {
                check_cidr_ingress(file, &block.body, &context, diagnostics);
            }
        }
        ("resource", Some("aws_vpc_security_group_ingress_rule")) => {
            check_vpc_ingress_rule(file, &block.body, &context, diagnostics);
        }
        ("resource", Some("aws_s3_bucket" | "aws_s3_bucket_acl")) => {
            check_bucket_acl(file, &block.body, &context, diagnostics);
        }
        ("resource", Some(kind)) if DATABASE_TYPES.contains(&kind) => {
            check_public_database(file, &block.body, &context, diagnostics);
        }
        ("data", Some("aws_iam_policy_document")) => {
            check_policy_document_statements(file, &block.body, &context, diagnostics);
        }
        _other => {}
    }
}

/// `resource "aws_s3_bucket" "logs"`, as an agent would search for it.
fn describe(block: &Block) -> String {
    let mut description = block.ident.as_str().to_owned();
    for label in &block.labels {
        description.push_str(" \"");
        description.push_str(label.as_str());
        description.push('"');
    }
    description
}

/// A literal secret: where its value is, and the key it was assigned to.
struct SecretAssignment {
    span: Range<usize>,
    key: String,
}

/// Collects every non-empty literal string assigned to a secret-named
/// argument or object key, at any depth of nested blocks and object
/// constructors, so `environment = { DB_PASSWORD = "..." }` is found as
/// surely as `password = "..."`.
#[derive(Default)]
struct SecretFinder {
    found: Vec<SecretAssignment>,
}

impl SecretFinder {
    fn consider(&mut self, key: &str, value: &Expression) {
        if !hcl::is_secret_name(key) {
            return;
        }
        let is_nonempty_literal = hcl::literal_string(value).is_some_and(|text| !text.is_empty());
        if let (true, Some(span)) = (is_nonempty_literal, value.span()) {
            self.found.push(SecretAssignment {
                span,
                key: key.to_owned(),
            });
        }
    }
}

impl Visit for SecretFinder {
    fn visit_attr(&mut self, node: &Attribute) {
        self.consider(node.key.as_str(), &node.value);
        visit_attr(self, node);
    }

    fn visit_object(&mut self, node: &Object) {
        for (key, value) in node.iter() {
            if let Some(name) = object_key_name(key) {
                self.consider(name, value.expr());
            }
        }
        visit_object(self, node);
    }
}

/// The name an object key spells literally, whether written bare or
/// quoted.
fn object_key_name(key: &ObjectKey) -> Option<&str> {
    match key {
        ObjectKey::Ident(ident) => Some(ident.as_str()),
        ObjectKey::Expression(expression) => hcl::literal_string(expression),
    }
}

fn report_secrets(
    file: &ParsedFile,
    found: Vec<SecretAssignment>,
    context: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for secret in found {
        diagnostics.push(Diagnostic::rule(
            LEVEL_ERROR,
            "stricttf::hardcoded_secret",
            format!(
                "`{}` in {context} is a literal credential; pass it in through a variable marked `sensitive = true` or read it from a secret store instead of committing it",
                secret.key
            ),
            file.location(&secret.span),
        ));
    }
}

/// A variable's literal default ships to every caller that does not
/// override it: as a whole when the variable is secret-named, and key by
/// key when the default is an object or map with secret-named keys.
fn check_variable_default(
    file: &ParsedFile,
    block: &Block,
    name: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(default) = hcl::attribute(&block.body, "default") else {
        return;
    };
    let mut whole = SecretFinder::default();
    whole.consider(name, &default.value);
    for secret in whole.found {
        diagnostics.push(Diagnostic::rule(
            LEVEL_ERROR,
            "stricttf::hardcoded_secret",
            format!(
                "variable \"{}\" has a literal credential as its default; remove the default so callers must supply the value",
                secret.key
            ),
            file.location(&secret.span),
        ));
    }
    let mut nested = SecretFinder::default();
    nested.visit_expr(&default.value);
    let context = format!("the default of variable \"{name}\"");
    report_secrets(file, nested.found, &context, diagnostics);
}

/// What a decided ingress rule exposes.
enum Exposure {
    AllPorts,
    AdminPorts(Vec<&'static str>),
}

impl Exposure {
    fn describe(&self) -> String {
        match self {
            Exposure::AllPorts => "every port".to_owned(),
            Exposure::AdminPorts(names) => names.join(" and "),
        }
    }
}

/// Decide what an ingress rule exposes from its literal protocol and
/// port range. `None` means either nothing administrative, or that the
/// answer depends on a computed value.
fn exposure(
    protocol: Option<&Expression>,
    from_port: Option<&Expression>,
    to_port: Option<&Expression>,
) -> Option<Exposure> {
    let protocol = protocol.and_then(literal_protocol)?;
    if ALL_PROTOCOLS
        .iter()
        .any(|all| protocol.eq_ignore_ascii_case(all))
    {
        return Some(Exposure::AllPorts);
    }
    if !TCP_PROTOCOLS
        .iter()
        .any(|tcp| protocol.eq_ignore_ascii_case(tcp))
    {
        return None;
    }
    let from = from_port.and_then(literal_port)?;
    let to = to_port.and_then(literal_port)?;
    let reached: Vec<&'static str> = ADMIN_PORTS
        .iter()
        .filter(|(port, _name)| from <= *port && *port <= to)
        .map(|(_port, name)| *name)
        .collect();
    if reached.is_empty() {
        None
    } else {
        Some(Exposure::AdminPorts(reached))
    }
}

/// A protocol written as a string (`"tcp"`, `"-1"`) or a number (`6`,
/// `-1`), normalised to its string spelling.
fn literal_protocol(expression: &Expression) -> Option<String> {
    if let Some(text) = hcl::literal_string(expression) {
        return Some(text.to_owned());
    }
    expression
        .as_number()
        .and_then(|number| number.as_i64())
        .map(|value| value.to_string())
}

/// A port written as a number or as a string of digits, which Terraform
/// converts to a number.
fn literal_port(expression: &Expression) -> Option<u64> {
    match hcl::literal_string(expression) {
        Some(text) => text.parse().ok(),
        None => expression.as_number().and_then(|number| number.as_u64()),
    }
}

/// A world-open CIDR literal: its spelling and where it is written.
struct WorldCidr<'a> {
    cidr: &'a str,
    span: Range<usize>,
}

fn world_cidr(expression: &Expression) -> Option<WorldCidr<'_>> {
    let cidr = hcl::literal_string(expression).filter(|cidr| WORLD_CIDRS.contains(cidr))?;
    let span = expression.span()?;
    Some(WorldCidr { cidr, span })
}

/// World-open CIDR literals inside a literal array.
fn world_cidrs_in(expression: Option<&Expression>) -> Vec<WorldCidr<'_>> {
    expression
        .and_then(Expression::as_array)
        .map(|array| array.iter().filter_map(world_cidr).collect())
        .unwrap_or_default()
}

fn value<'a>(body: &'a Body, key: &str) -> Option<&'a Expression> {
    hcl::attribute(body, key).map(|attribute| &attribute.value)
}

/// An `ingress` block of `aws_security_group`, or an
/// `aws_security_group_rule`: both spell sources as CIDR lists.
fn check_cidr_ingress(
    file: &ParsedFile,
    body: &Body,
    context: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut world = world_cidrs_in(value(body, "cidr_blocks"));
    world.extend(world_cidrs_in(value(body, "ipv6_cidr_blocks")));
    if world.is_empty() {
        return;
    }
    let Some(exposure) = exposure(
        value(body, "protocol"),
        value(body, "from_port"),
        value(body, "to_port"),
    ) else {
        return;
    };
    report_ingress(file, &world, context, &exposure, diagnostics);
}

/// `aws_vpc_security_group_ingress_rule` spells one source per rule, as
/// a single CIDR string.
fn check_vpc_ingress_rule(
    file: &ParsedFile,
    body: &Body,
    context: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let world: Vec<WorldCidr<'_>> = [value(body, "cidr_ipv4"), value(body, "cidr_ipv6")]
        .into_iter()
        .flatten()
        .filter_map(world_cidr)
        .collect();
    if world.is_empty() {
        return;
    }
    let Some(exposure) = exposure(
        value(body, "ip_protocol"),
        value(body, "from_port"),
        value(body, "to_port"),
    ) else {
        return;
    };
    report_ingress(file, &world, context, &exposure, diagnostics);
}

fn report_ingress(
    file: &ParsedFile,
    world: &[WorldCidr<'_>],
    context: &str,
    exposure: &Exposure,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for source in world {
        diagnostics.push(Diagnostic::rule(
            LEVEL_ERROR,
            "stricttf::open_admin_ingress",
            format!(
                "{context} opens {} to the whole internet ({}); restrict the source to known networks, or reach hosts through a bastion or Session Manager",
                exposure.describe(),
                source.cidr
            ),
            file.location(&source.span),
        ));
    }
}

fn check_bucket_acl(
    file: &ParsedFile,
    body: &Body,
    context: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(acl) = value(body, "acl") else {
        return;
    };
    let Some(granted) = hcl::literal_string(acl).filter(|acl| PUBLIC_ACLS.contains(acl)) else {
        return;
    };
    let Some(span) = acl.span() else {
        return;
    };
    diagnostics.push(Diagnostic::rule(
        LEVEL_ERROR,
        "stricttf::public_bucket_acl",
        format!(
            "{context} uses the canned ACL \"{granted}\", which grants access beyond the bucket owner; use \"private\" and grant access through a bucket policy"
        ),
        file.location(&span),
    ));
}

fn check_public_database(
    file: &ParsedFile,
    body: &Body,
    context: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(public) = value(body, "publicly_accessible") else {
        return;
    };
    if !is_literal_true(public) {
        return;
    }
    let Some(span) = public.span() else {
        return;
    };
    diagnostics.push(Diagnostic::rule(
        LEVEL_ERROR,
        "stricttf::public_database",
        format!(
            "{context} sets `publicly_accessible = true`, giving the database an internet-facing endpoint; set it to false and connect from inside the VPC"
        ),
        file.location(&span),
    ));
}

/// A literal `true`, or a string Terraform converts to it.
fn is_literal_true(expression: &Expression) -> bool {
    match hcl::literal_string(expression) {
        Some(text) => text.eq_ignore_ascii_case("true"),
        None => expression.as_bool() == Some(true),
    }
}

/// Whether an `Effect`/`effect` value leaves the statement allowing. An
/// absent effect defaults to Allow; a computed one is undecidable.
fn allows(effect: Option<&Expression>) -> bool {
    match effect {
        None => true,
        Some(effect) => hcl::literal_string(effect) == Some("Allow"),
    }
}

fn is_wildcard_action(expression: &Expression) -> bool {
    hcl::literal_string(expression).is_some_and(|action| WILDCARD_ACTIONS.contains(&action))
}

/// `statement` blocks of `data "aws_iam_policy_document"`.
fn check_policy_document_statements(
    file: &ParsedFile,
    body: &Body,
    context: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for statement in body.blocks().filter(|nested| nested.has_ident("statement")) {
        if !allows(value(&statement.body, "effect")) {
            continue;
        }
        let Some(actions) = value(&statement.body, "actions").and_then(Expression::as_array) else {
            continue;
        };
        let wildcards = actions
            .iter()
            .filter(|action| is_wildcard_action(action))
            .filter_map(Span::span);
        for span in wildcards {
            report_wildcard(file, &span, context, diagnostics);
        }
    }
}

/// Policies written inline as `jsonencode({ Statement = [...] })`,
/// anywhere in the configuration.
fn check_policy_documents(file: &ParsedFile, diagnostics: &mut Vec<Diagnostic>) {
    let mut finder = JsonPolicyFinder::default();
    finder.visit_body(&file.body);
    for span in finder.found {
        report_wildcard(file, &span, "a jsonencode policy", diagnostics);
    }
}

/// Finds allowing statements with a full wildcard `Action` inside
/// `jsonencode` arguments. The depth counter, rather than a nested walk
/// per call, keeps a `jsonencode` nested inside another from being
/// reported twice.
#[derive(Default)]
struct JsonPolicyFinder {
    depth: usize,
    found: Vec<Range<usize>>,
}

impl Visit for JsonPolicyFinder {
    fn visit_func_call(&mut self, node: &FuncCall) {
        let is_jsonencode =
            node.name.namespace.is_empty() && node.name.name.as_str() == "jsonencode";
        if is_jsonencode {
            self.depth = self.depth.saturating_add(1);
        }
        visit_func_call(self, node);
        if is_jsonencode {
            self.depth = self.depth.saturating_sub(1);
        }
    }

    fn visit_object(&mut self, node: &Object) {
        if self.depth > 0 {
            let entry = |wanted: &str| {
                node.iter()
                    .find(|(key, _value)| object_key_name(key) == Some(wanted))
                    .map(|(_key, value)| value.expr())
            };
            if let (true, Some(action)) = (allows(entry("Effect")), entry("Action")) {
                let actions: Vec<&Expression> = match action.as_array() {
                    Some(array) => array.iter().collect(),
                    None => vec![action],
                };
                self.found.extend(
                    actions
                        .into_iter()
                        .filter(|action| is_wildcard_action(action))
                        .filter_map(Span::span),
                );
            }
        }
        visit_object(self, node);
    }
}

fn report_wildcard(
    file: &ParsedFile,
    span: &Range<usize>,
    context: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    diagnostics.push(Diagnostic::rule(
        LEVEL_ERROR,
        "stricttf::wildcard_iam_action",
        format!(
            "an Allow statement in {context} grants every action on every service; list the specific actions the principal needs"
        ),
        file.location(span),
    ));
}
