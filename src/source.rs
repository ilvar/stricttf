//! Module-structure and configuration-source layers.
//!
//! Everything here is decided from the literal configuration text alone:
//! version constraints, provider requirements, variable and output
//! contracts, module-call pinning, and expressions Terraform accepts but
//! a strict profile does not. Whenever a construct's meaning depends on
//! evaluation -- a version built from a variable, a source assembled by a
//! function -- the rule stays silent, because a guess an agent cannot
//! verify is worse than no finding at all.

use crate::hcl::{self, ParsedFile};
use crate::report::{Diagnostic, Fix, Location, LEVEL_ERROR, LEVEL_WARNING};
use crate::{Module, LOCK_FILE};
use hcl_edit::expr::{BinaryOp, Conditional, UnaryOp};
use hcl_edit::expr::{Expression, FuncCall, Object, ObjectKey, Traversal, TraversalOperator};
use hcl_edit::structure::{Attribute, Block, Structure};
use hcl_edit::template::{Element, Interpolation, StringTemplate};
use hcl_edit::visit::{self, Visit};
use hcl_edit::Span;
use std::collections::BTreeSet;
use std::ops::Range;

/// The provider Terraform ships built in. It needs no requirement entry
/// and no lock-file pin, so `terraform_data` and `terraform_remote_state`
/// never count as provider usage.
const BUILTIN_PROVIDER: &str = "terraform";

/// Functions whose result changes on every plan, so a configuration using
/// them can never converge to an empty plan.
const NONDETERMINISTIC_FUNCTIONS: &[&str] = &["bcrypt", "plantimestamp", "timestamp", "uuid"];

/// Branch names that a module `ref` commonly points at. A branch moves,
/// so pinning one is no pin at all.
const BRANCH_REFS: &[&str] = &["HEAD", "develop", "main", "master", "trunk"];

/// Source prefixes Terraform hands to its VCS getters.
const GIT_PREFIXES: &[&str] = &["git::", "git@", "github.com/", "bitbucket.org/", "hg::"];

/// Primitive type keywords a quoted legacy constraint can be rewritten to
/// without changing its meaning.
const PRIMITIVE_TYPES: &[&str] = &["bool", "number", "string"];

/// Run every configuration-source rule over a parsed module.
pub fn check(module: &Module) -> Vec<Diagnostic> {
    let files = module.configuration.as_slice();
    let mut diagnostics = Vec::new();

    if module.complete {
        // A file that failed to parse may hold the declaration or the
        // reference these rules would report as absent, so module-wide
        // absence is only concluded over the whole configuration.
        required_version(files, &mut diagnostics);
        variable_files(module, &mut diagnostics);
    }
    provider_requirements(module, &mut diagnostics);
    variables(files, &mut diagnostics);
    outputs(files, &mut diagnostics);
    expressions(files, module.complete, &mut diagnostics);
    module_calls(files, &mut diagnostics);
    resource_meta_arguments(files, &mut diagnostics);
    names(files, &mut diagnostics);

    diagnostics
}

fn error(code: &str, message: impl Into<String>, at: Location) -> Diagnostic {
    Diagnostic::rule(LEVEL_ERROR, code, message, at)
}

fn warning(code: &str, message: impl Into<String>, at: Location) -> Diagnostic {
    Diagnostic::rule(LEVEL_WARNING, code, message, at)
}

/// The location of a block's label at `index`, or of its header when the
/// label is absent.
fn locate_label(file: &ParsedFile, block: &Block, index: usize) -> Location {
    match block.labels.get(index) {
        Some(label) => file.locate(label),
        None => file.locate_header(block),
    }
}

/// The value of `key` inside an HCL object, whether the key is written as
/// a bare identifier or a quoted string.
fn object_field<'a>(object: &'a Object, key: &str) -> Option<&'a Expression> {
    object.iter().find_map(|(candidate, value)| {
        let matches = match candidate {
            ObjectKey::Ident(ident) => ident.as_str() == key,
            ObjectKey::Expression(expression) => hcl::literal_string(expression) == Some(key),
        };
        matches.then(|| value.expr())
    })
}

// ---------------------------------------------------------------------
// terraform { required_version }
// ---------------------------------------------------------------------

/// An unconstrained Terraform version lets any future release with
/// changed semantics plan this module, so the constraint is required.
fn required_version(files: &[ParsedFile], diagnostics: &mut Vec<Diagnostic>) {
    let settings = hcl::blocks(files, "terraform");
    if settings
        .iter()
        .any(|(_file, block)| hcl::attribute(&block.body, "required_version").is_some())
    {
        return;
    }

    // The fix belongs in a primary file: an override file only patches
    // settings declared elsewhere.
    let primary = || files.iter().filter(|file| !file.is_override());
    let at = match settings.iter().find(|(file, _block)| !file.is_override()) {
        Some((file, block)) => file.locate_header(block),
        None => {
            let versions = primary()
                .find(|file| file.path == "versions.tf" || file.path.ends_with("/versions.tf"));
            match versions.or_else(|| primary().next()) {
                Some(file) => Location::file_start(file.path.as_str(), &file.text),
                None => return,
            }
        }
    };
    diagnostics.push(error(
        "stricttf::required_version_missing",
        "no terraform block sets required_version; add `required_version = \"~> 1.9\"` (or the range this module supports) to the terraform block",
        at,
    ));
}

// ---------------------------------------------------------------------
// terraform { required_providers }
// ---------------------------------------------------------------------

/// Every `required_providers` entry across the module, in file order.
fn provider_entries(files: &[ParsedFile]) -> Vec<(&ParsedFile, &Attribute)> {
    hcl::blocks(files, "terraform")
        .into_iter()
        .flat_map(|(file, block)| {
            block
                .body
                .get_blocks("required_providers")
                .flat_map(|requirements| requirements.body.attributes())
                .map(move |entry| (file, entry))
        })
        .collect()
}

fn provider_requirements(module: &Module, diagnostics: &mut Vec<Diagnostic>) {
    let files = module.configuration.as_slice();
    let entries = provider_entries(files);
    let mut declared = BTreeSet::new();

    for (file, entry) in &entries {
        let name = entry.key.as_str();
        declared.insert(name.to_owned());
        let (source, version) = match &entry.value {
            Expression::Object(object) => (
                object_field(object, "source"),
                object_field(object, "version"),
            ),
            // The pre-0.13 shorthand `aws = "~> 5.0"` is a bare version
            // constraint with no source address.
            Expression::String(_) => (None, Some(&entry.value)),
            Expression::Null(_)
            | Expression::Bool(_)
            | Expression::Number(_)
            | Expression::Array(_)
            | Expression::StringTemplate(_)
            | Expression::HeredocTemplate(_)
            | Expression::Parenthesis(_)
            | Expression::Variable(_)
            | Expression::Conditional(_)
            | Expression::FuncCall(_)
            | Expression::Traversal(_)
            | Expression::UnaryOp(_)
            | Expression::BinaryOp(_)
            | Expression::ForExpr(_) => continue,
        };

        // An override entry patches a requirement declared in a primary
        // file, so the fields it omits are inherited, not missing.
        let partial = file.is_override();
        if source.is_none() && !partial {
            diagnostics.push(error(
                "stricttf::provider_source_missing",
                format!("required provider {name} has no source address; write it as `{name} = {{ source = \"<namespace>/{name}\", version = \"~> X.Y\" }}`"),
                file.locate(&entry.key),
            ));
        }
        match version {
            None if partial => {}
            None => diagnostics.push(error(
                "stricttf::provider_version_missing",
                format!("required provider {name} has no version constraint; add `version = \"~> X.Y\"` so upgrades are deliberate"),
                file.locate(&entry.key),
            )),
            Some(version) => {
                if let Some(constraint) = hcl::literal_string(version) {
                    if !is_bounded_constraint(constraint) {
                        diagnostics.push(error(
                            "stricttf::provider_version_unbounded",
                            format!("version constraint \"{constraint}\" for provider {name} has no upper bound; use a pessimistic constraint such as \"~> X.Y\""),
                            file.locate(version),
                        ));
                    }
                }
            }
        }
    }

    let used = provider_uses(files);
    // An unparsed file may hold the requirement entry, so a provider is
    // only undeclared when the whole configuration was read.
    for (name, file, at) in &used {
        if module.complete && !declared.contains(name.as_str()) {
            diagnostics.push(error(
                "stricttf::provider_undeclared",
                format!("provider {name} is used but not declared; add it to terraform {{ required_providers }} with a source and version"),
                file.location(at),
            ));
        }
    }

    let needs_providers = declared
        .iter()
        .map(String::as_str)
        .chain(used.iter().map(|(name, _file, _at)| name.as_str()))
        .any(|name| name != BUILTIN_PROVIDER);
    if needs_providers && !module.has_lock_file {
        diagnostics.push(warning(
            "stricttf::lock_file_missing",
            format!("this module uses providers but has no {LOCK_FILE}; run `terraform init` and commit the lock file so every run selects the same provider builds"),
            Location::whole_line(LOCK_FILE, 1, ""),
        ));
    }
}

/// Whether a comma-separated version constraint caps the versions it
/// admits. `~>`, `<`, `<=`, `=`, and a bare version all do; `>`, `>=`,
/// and `!=` on their own admit every future major release.
fn is_bounded_constraint(constraint: &str) -> bool {
    constraint.split(',').map(str::trim).any(|part| {
        part.starts_with("~>")
            || part.starts_with('<')
            || part.starts_with('=')
            || part.starts_with(|first: char| first.is_ascii_digit())
    })
}

/// Each non-builtin provider local name the configuration uses, with the
/// span of its first use, in file then source order.
fn provider_uses(files: &[ParsedFile]) -> Vec<(String, &ParsedFile, Range<usize>)> {
    let mut seen = BTreeSet::new();
    let mut uses = Vec::new();

    for file in files {
        for block in file.body.blocks() {
            let found = match block.ident.as_str() {
                "resource" | "data" | "ephemeral" => resource_provider(block),
                "provider" => block
                    .labels
                    .first()
                    .and_then(|label| Some((label.as_str().to_owned(), label.span()?))),
                _other => None,
            };
            let Some((name, span)) = found else {
                continue;
            };
            if name != BUILTIN_PROVIDER && seen.insert(name.clone()) {
                uses.push((name, file, span));
            }
        }
    }
    uses
}

/// The provider a resource-like block belongs to: its `provider`
/// meta-argument when present, else the type prefix before the first
/// underscore, which is how Terraform itself infers it.
fn resource_provider(block: &Block) -> Option<(String, Range<usize>)> {
    if let Some(meta) = hcl::attribute(&block.body, "provider") {
        let name = match &meta.value {
            Expression::Variable(name) => Some(name.as_str()),
            Expression::Traversal(traversal) => match &traversal.expr {
                Expression::Variable(name) => Some(name.as_str()),
                _other => None,
            },
            _other => None,
        };
        return Some((name?.to_owned(), meta.value.span()?));
    }
    let label = block.labels.first()?;
    let kind = label.as_str();
    let prefix = kind.split_once('_').map_or(kind, |(prefix, _rest)| prefix);
    Some((prefix.to_owned(), label.span()?))
}

// ---------------------------------------------------------------------
// *.tfvars
// ---------------------------------------------------------------------

/// Terraform only warns about an undeclared tfvars key, so a misspelled
/// variable name silently falls back to its default.
fn variable_files(module: &Module, diagnostics: &mut Vec<Diagnostic>) {
    let declared: BTreeSet<&str> = hcl::blocks(&module.configuration, "variable")
        .into_iter()
        .filter_map(|(_file, block)| hcl::label(block, 0))
        .collect();

    for file in &module.variable_files {
        for entry in file.body.attributes() {
            let name = entry.key.as_str();
            if !declared.contains(name) {
                diagnostics.push(error(
                    "stricttf::tfvars_undeclared",
                    format!("{} sets {name}, which no variable block declares; declare `variable \"{name}\"` or remove the assignment", file.path),
                    file.locate(&entry.key),
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------
// variable and output contracts
// ---------------------------------------------------------------------

fn variables(files: &[ParsedFile], diagnostics: &mut Vec<Diagnostic>) {
    for (file, block) in hcl::blocks(files, "variable") {
        let Some(name) = hcl::label(block, 0) else {
            continue;
        };
        let constraint = hcl::attribute(&block.body, "type");
        if let Some(constraint) = constraint {
            type_constraint(file, name, &constraint.value, diagnostics);
        }
        // An override block patches a declaration made elsewhere; what it
        // omits is inherited, so only what it does say is checked.
        if file.is_override() {
            continue;
        }

        if constraint.is_none() {
            diagnostics.push(error(
                "stricttf::variable_missing_type",
                format!(
                    "variable {name} has no type; add a type constraint such as `type = string`"
                ),
                file.locate_header(block),
            ));
        }

        if let Some(at) = missing_description(file, block) {
            diagnostics.push(error(
                "stricttf::variable_missing_description",
                format!("variable {name} has no description; add a one-sentence `description` of what it controls"),
                at,
            ));
        }

        let sensitive = hcl::attribute(&block.body, "sensitive")
            .is_some_and(|flag| matches!(&flag.value, Expression::Bool(value) if *value.value()));
        // A flag or a count such as `manage_master_user_password` or
        // `password_length` cannot carry the credential itself.
        let scalar = constraint.is_some_and(|constraint| {
            matches!(&constraint.value, Expression::Variable(keyword) if matches!(keyword.as_str(), "bool" | "number"))
        });
        if hcl::is_secret_name(name) && !sensitive && !scalar {
            diagnostics.push(error(
                "stricttf::sensitive_variable_unmarked",
                format!("variable {name} names credential material but is not marked sensitive; add `sensitive = true`"),
                locate_label(file, block, 0),
            ));
        }
    }
}

fn type_constraint(
    file: &ParsedFile,
    name: &str,
    constraint: &Expression,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Some(quoted) = hcl::literal_string(constraint) {
        let mut diagnostic = error(
            "stricttf::quoted_type_constraint",
            format!("variable {name} uses the legacy quoted type \"{quoted}\"; write the type unquoted, e.g. `type = string` or `type = list(string)`"),
            file.locate(constraint),
        );
        if let (true, Some(span)) = (PRIMITIVE_TYPES.contains(&quoted), constraint.span()) {
            diagnostic = diagnostic.with_fix(Fix::replace(
                format!("unquote the type constraint to `{quoted}`"),
                file.path.as_str(),
                &file.text,
                span.start,
                span.end,
                quoted,
            ));
        }
        diagnostics.push(diagnostic);
        return;
    }

    let mut search = AnyType { found: false };
    search.visit_expr(constraint);
    if search.found {
        diagnostics.push(error(
            "stricttf::variable_any_type",
            format!("variable {name} accepts `any`, which disables type checking for callers; spell out the concrete type"),
            file.locate(constraint),
        ));
    }
}

/// Finds the `any` keyword anywhere inside a type expression.
struct AnyType {
    found: bool,
}

impl Visit for AnyType {
    fn visit_expr(&mut self, node: &Expression) {
        if let Expression::Variable(name) = node {
            self.found |= name.as_str() == "any";
        }
        visit::visit_expr(self, node);
    }
}

/// Where a block's description is missing: its header when absent, or
/// the value when it is a literal with no visible text.
fn missing_description(file: &ParsedFile, block: &Block) -> Option<Location> {
    match hcl::attribute(&block.body, "description") {
        None => Some(file.locate_header(block)),
        Some(description) => hcl::literal_string(&description.value)
            .filter(|text| text.trim().is_empty())
            .map(|_empty| file.locate(&description.value)),
    }
}

fn outputs(files: &[ParsedFile], diagnostics: &mut Vec<Diagnostic>) {
    for (file, block) in hcl::blocks(files, "output") {
        let name = hcl::label(block, 0).unwrap_or_default();
        if file.is_override() {
            continue;
        }
        if let Some(at) = missing_description(file, block) {
            diagnostics.push(error(
                "stricttf::output_missing_description",
                format!("output {name} has no description; add a one-sentence `description` of what it exposes"),
                at,
            ));
        }
    }
}

// ---------------------------------------------------------------------
// expressions: references, functions, interpolation
// ---------------------------------------------------------------------

fn expressions(files: &[ParsedFile], complete: bool, diagnostics: &mut Vec<Diagnostic>) {
    let mut variables = BTreeSet::new();
    let mut locals = BTreeSet::new();

    for file in files {
        let mut walk = ExpressionWalk {
            file,
            diagnostics: Vec::new(),
            variables: BTreeSet::new(),
            locals: BTreeSet::new(),
            position: Position::Free,
            assertions: 0,
        };
        for structure in file.body.iter() {
            walk.visit_structure(structure);
            // A variable's own validation necessarily mentions it; that
            // reference does not make the variable used.
            if let Structure::Block(block) = structure {
                if let (true, Some(name)) = (block.has_ident("variable"), hcl::label(block, 0)) {
                    walk.variables.remove(name);
                }
            }
            variables.append(&mut walk.variables);
        }
        locals.append(&mut walk.locals);
        diagnostics.append(&mut walk.diagnostics);
    }
    if !complete {
        return;
    }

    // A variable re-declared in an override file is still one variable:
    // report it once, at its first declaration.
    let mut reported = BTreeSet::new();
    for (file, block) in hcl::blocks(files, "variable") {
        let Some(name) = hcl::label(block, 0) else {
            continue;
        };
        if !reported.insert(name) {
            continue;
        }
        if !variables.contains(name) {
            diagnostics.push(warning(
                "stricttf::unused_variable",
                format!("variable {name} is never referenced as var.{name}; use it or remove it"),
                locate_label(file, block, 0),
            ));
        }
    }

    let mut reported = BTreeSet::new();
    for (file, block) in hcl::blocks(files, "locals") {
        for entry in block.body.attributes() {
            let name = entry.key.as_str();
            if !locals.contains(name) && reported.insert(name) {
                diagnostics.push(warning(
                    "stricttf::unused_local",
                    format!("local value {name} is never referenced as local.{name}; use it or remove it"),
                    file.locate(&entry.key),
                ));
            }
        }
    }
}

/// What syntactic slot the expression about to be visited occupies. An
/// unwrapped interpolation is only safe to splice in where precedence
/// cannot change, and never as an object key, where a bare traversal
/// would read as a literal name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Position {
    #[default]
    Free,
    Operand,
    ObjectKey,
}

struct ExpressionWalk<'a> {
    file: &'a ParsedFile,
    diagnostics: Vec<Diagnostic>,
    variables: BTreeSet<String>,
    locals: BTreeSet<String>,
    position: Position,
    /// How many assertion blocks enclose the current node. Assertions
    /// are evaluated but never planned, so a nondeterministic value there
    /// cannot keep the plan from converging.
    assertions: usize,
}

/// Blocks whose expressions only assert and never become planned state.
const ASSERTION_BLOCKS: &[&str] = &["check", "postcondition", "precondition", "validation"];

impl ExpressionWalk<'_> {
    fn record_reference(&mut self, traversal: &Traversal) {
        let Expression::Variable(root) = &traversal.expr else {
            return;
        };
        let Some(first) = traversal.operators.first() else {
            return;
        };
        let name = match first.value() {
            TraversalOperator::GetAttr(name) => name.as_str(),
            TraversalOperator::Index(index) => match hcl::literal_string(index) {
                Some(name) => name,
                None => return,
            },
            TraversalOperator::AttrSplat(_)
            | TraversalOperator::FullSplat(_)
            | TraversalOperator::LegacyIndex(_) => return,
        };
        match root.as_str() {
            "var" => {
                self.variables.insert(name.to_owned());
            }
            "local" => {
                self.locals.insert(name.to_owned());
            }
            _other => {}
        }
    }

    fn interpolation_only(&mut self, template: &StringTemplate, position: Position) {
        if position == Position::ObjectKey {
            return;
        }
        let mut elements = template.iter();
        let (Some(Element::Interpolation(interpolation)), None) =
            (elements.next(), elements.next())
        else {
            return;
        };
        let Some(span) = template.span() else {
            return;
        };

        let mut diagnostic = error(
            "stricttf::interpolation_only",
            "this string is a single interpolation; write the expression directly without \"${ }\"",
            self.file.location(&span),
        );
        if let Some(fix) = self.unwrap_fix(&span, interpolation, position) {
            diagnostic = diagnostic.with_fix(fix);
        }
        self.diagnostics.push(diagnostic);
    }

    /// Replace `"${expr}"` with `expr`, parenthesised where it is an
    /// operand and could otherwise rebind. Offered only when nothing but
    /// whitespace surrounds the expression (a comment would be lost) and
    /// the rewritten file still parses.
    fn unwrap_fix(
        &self,
        span: &Range<usize>,
        interpolation: &Interpolation,
        position: Position,
    ) -> Option<Fix> {
        let text = &self.file.text;
        let inner = self.file.source_of(&interpolation.expr)?;
        let written = self.file.source_of(interpolation)?;
        let between = written.strip_prefix("${")?.strip_suffix('}')?;
        let between = between.strip_prefix('~').unwrap_or(between);
        let between = between.strip_suffix('~').unwrap_or(between);
        if between.trim() != inner.trim() {
            return None;
        }

        let inner = inner.trim();
        let replacement = if position == Position::Operand && !is_atomic(&interpolation.expr) {
            format!("({inner})")
        } else {
            inner.to_owned()
        };
        let candidate = format!(
            "{}{}{}",
            text.get(..span.start)?,
            replacement,
            text.get(span.end..)?
        );
        hcl_edit::parser::parse_body(&candidate).ok()?;

        Some(Fix::replace(
            format!("replace the template with `{replacement}`"),
            self.file.path.as_str(),
            text,
            span.start,
            span.end,
            replacement,
        ))
    }
}

/// Whether an expression binds tighter than any operator, so it can
/// stand as an operand without parentheses.
fn is_atomic(expression: &Expression) -> bool {
    match expression {
        Expression::Null(_)
        | Expression::Bool(_)
        | Expression::Number(_)
        | Expression::String(_)
        | Expression::Array(_)
        | Expression::Object(_)
        | Expression::StringTemplate(_)
        | Expression::Parenthesis(_)
        | Expression::Variable(_)
        | Expression::FuncCall(_)
        | Expression::Traversal(_)
        | Expression::ForExpr(_) => true,
        Expression::HeredocTemplate(_)
        | Expression::Conditional(_)
        | Expression::UnaryOp(_)
        | Expression::BinaryOp(_) => false,
    }
}

impl Visit for ExpressionWalk<'_> {
    fn visit_expr(&mut self, node: &Expression) {
        let position = std::mem::take(&mut self.position);
        if let Expression::StringTemplate(template) = node {
            self.interpolation_only(template, position);
        }
        visit::visit_expr(self, node);
    }

    fn visit_block(&mut self, node: &Block) {
        let assertion = ASSERTION_BLOCKS.contains(&node.ident.as_str());
        if assertion {
            self.assertions = self.assertions.saturating_add(1);
        }
        visit::visit_block(self, node);
        if assertion {
            self.assertions = self.assertions.saturating_sub(1);
        }
    }

    fn visit_func_call(&mut self, node: &FuncCall) {
        let name = node.name.name.as_str();
        if self.assertions == 0
            && !node.name.is_namespaced()
            && NONDETERMINISTIC_FUNCTIONS.contains(&name)
        {
            self.diagnostics.push(error(
                "stricttf::nondeterministic_function",
                format!("{name}() returns a different value on every run, so this configuration never reaches an empty plan; pass the value in as a variable or use a stable resource such as time_static or random_uuid"),
                self.file.locate(node),
            ));
        }
        visit::visit_func_call(self, node);
    }

    fn visit_traversal(&mut self, node: &Traversal) {
        self.record_reference(node);
        self.position = Position::Operand;
        self.visit_expr(&node.expr);
        for operator in &node.operators {
            self.visit_traversal_operator(operator);
        }
    }

    fn visit_unary_op(&mut self, node: &UnaryOp) {
        self.position = Position::Operand;
        self.visit_expr(&node.expr);
    }

    fn visit_binary_op(&mut self, node: &BinaryOp) {
        self.position = Position::Operand;
        self.visit_expr(&node.lhs_expr);
        self.position = Position::Operand;
        self.visit_expr(&node.rhs_expr);
    }

    fn visit_conditional(&mut self, node: &Conditional) {
        for branch in [&node.cond_expr, &node.true_expr, &node.false_expr] {
            self.position = Position::Operand;
            self.visit_expr(branch);
        }
    }

    fn visit_object_key(&mut self, node: &ObjectKey) {
        match node {
            ObjectKey::Ident(_) => {}
            ObjectKey::Expression(expression) => {
                self.position = Position::ObjectKey;
                self.visit_expr(expression);
            }
        }
    }
}

// ---------------------------------------------------------------------
// module calls
// ---------------------------------------------------------------------

fn module_calls(files: &[ParsedFile], diagnostics: &mut Vec<Diagnostic>) {
    for (file, block) in hcl::blocks(files, "module") {
        let name = hcl::label(block, 0).unwrap_or_default();
        let Some(source_attribute) = hcl::attribute(&block.body, "source") else {
            continue;
        };
        let Some(source) = hcl::literal_string(&source_attribute.value) else {
            continue;
        };

        if is_registry_source(source) {
            match hcl::attribute(&block.body, "version") {
                None => diagnostics.push(error(
                    "stricttf::module_version_missing",
                    format!("module {name} calls registry module {source} without a version; pin it with `version = \"X.Y.Z\"`"),
                    file.locate_header(block),
                )),
                Some(version) => {
                    if let Some(constraint) = hcl::literal_string(&version.value) {
                        if !is_exact_version(constraint) {
                            diagnostics.push(error(
                                "stricttf::module_version_inexact",
                                format!("module {name} version \"{constraint}\" admits more than one release; pin exactly one version such as \"1.2.3\""),
                                file.locate(&version.value),
                            ));
                        }
                    }
                }
            }
        } else if GIT_PREFIXES.iter().any(|prefix| source.starts_with(prefix)) {
            if let Some(problem) = ref_problem(source) {
                diagnostics.push(error(
                    "stricttf::module_ref_missing",
                    format!("module {name} source {problem}; pin a tag or commit with `?ref=<tag-or-sha>`"),
                    file.locate(&source_attribute.value),
                ));
            }
        }
    }
}

/// Whether a module source is a Terraform registry address:
/// `[host/]namespace/name/provider`, optionally followed by `//subdir`.
fn is_registry_source(source: &str) -> bool {
    if source.contains("::")
        || source.contains('?')
        || source.starts_with("github.com/")
        || source.starts_with("bitbucket.org/")
    {
        return false;
    }
    let address = source
        .split_once("//")
        .map_or(source, |(address, _subdir)| address);
    let parts: Vec<&str> = address.split('/').collect();
    match parts.as_slice() {
        [namespace, name, provider] => {
            is_registry_name(namespace) && is_registry_name(name) && is_provider_name(provider)
        }
        [host, namespace, name, provider] => {
            is_hostname(host)
                && is_registry_name(namespace)
                && is_registry_name(name)
                && is_provider_name(provider)
        }
        _other => false,
    }
}

fn is_registry_name(segment: &str) -> bool {
    segment
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && segment
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn is_provider_name(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .chars()
            .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
}

fn is_hostname(segment: &str) -> bool {
    let host = segment.split_once(':').map_or(segment, |(host, port)| {
        if !port.is_empty() && port.chars().all(|digit| digit.is_ascii_digit()) {
            host
        } else {
            ""
        }
    });
    host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
}

/// Whether a module version constraint selects exactly one release:
/// `1.2.3` or `= 1.2.3`, with optional prerelease and build suffixes.
fn is_exact_version(constraint: &str) -> bool {
    let trimmed = constraint.trim();
    let version = trimmed.strip_prefix('=').unwrap_or(trimmed).trim_start();
    let (version, build) = match version.split_once('+') {
        Some((version, build)) => (version, Some(build)),
        None => (version, None),
    };
    let (core, prerelease) = match version.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (version, None),
    };
    let numbers: Vec<&str> = core.split('.').collect();
    let core_ok = numbers.len() == 3
        && numbers
            .iter()
            .all(|number| !number.is_empty() && number.chars().all(|digit| digit.is_ascii_digit()));
    let suffix_ok = |suffix: Option<&str>| {
        suffix.is_none_or(|text| {
            !text.is_empty()
                && text.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '-')
                })
        })
    };
    core_ok && suffix_ok(prerelease) && suffix_ok(build)
}

/// Why a VCS module source is not pinned, or `None` when its `ref`
/// names something other than a well-known branch.
fn ref_problem(source: &str) -> Option<String> {
    let query = source.split_once('?').map_or("", |(_address, query)| query);
    // Mercurial sources pin with `rev=`; accept it rather than misreport.
    let accepted: &[&str] = if source.starts_with("hg::") {
        &["ref=", "rev="]
    } else {
        &["ref="]
    };
    let pinned = query.split('&').find_map(|parameter| {
        accepted
            .iter()
            .find_map(|key| parameter.strip_prefix(key))
            .filter(|value| !value.is_empty())
    });
    match pinned {
        None => Some("has no ref, so it follows the default branch".to_owned()),
        Some(branch) if BRANCH_REFS.contains(&branch) => Some(format!(
            "ref={branch} names a branch, which moves; pin a tag or commit"
        )),
        Some(_pinned) => None,
    }
}

// ---------------------------------------------------------------------
// resource meta-arguments
// ---------------------------------------------------------------------

fn resource_meta_arguments(files: &[ParsedFile], diagnostics: &mut Vec<Diagnostic>) {
    for (file, block) in hcl::blocks(files, "resource") {
        for provisioner in block.body.get_blocks("provisioner") {
            diagnostics.push(error(
                "stricttf::provisioner",
                "provisioners run imperative steps Terraform cannot plan or diff; move the work into a provider resource, cloud-init/user_data, or a configuration-management tool",
                file.locate_header(provisioner),
            ));
        }

        for lifecycle in block.body.get_blocks("lifecycle") {
            let Some(ignored) = hcl::attribute(&lifecycle.body, "ignore_changes") else {
                continue;
            };
            let ignores_all = match &ignored.value {
                Expression::Variable(keyword) => keyword.as_str() == "all",
                Expression::Array(items) => items
                    .iter()
                    .any(|item| hcl::literal_string(item) == Some("*")),
                _other => false,
            };
            if ignores_all {
                diagnostics.push(warning(
                    "stricttf::ignore_changes_all",
                    "ignore_changes = all hides every drift on this resource from plans; list only the attributes that are managed elsewhere",
                    file.locate(&ignored.value),
                ));
            }
        }
    }

    for (file, block) in hcl::blocks(files, "data") {
        if hcl::label(block, 0) == Some("external") {
            diagnostics.push(error(
                "stricttf::external_program",
                "data \"external\" runs an arbitrary local program during every plan; use a provider data source or pass the value in as a variable",
                file.locate_header(block),
            ));
        }
    }
}

// ---------------------------------------------------------------------
// naming
// ---------------------------------------------------------------------

/// Terraform accepts any identifier, but mixed conventions make references
/// unguessable for an agent; the registry style is lower snake case.
fn names(files: &[ParsedFile], diagnostics: &mut Vec<Diagnostic>) {
    for file in files {
        for block in file.body.blocks() {
            let (kind, index) = match block.ident.as_str() {
                "resource" | "data" | "ephemeral" => ("resource name", 1),
                "module" => ("module name", 0),
                "variable" => ("variable name", 0),
                "output" => ("output name", 0),
                "locals" => {
                    for entry in block.body.attributes() {
                        snake_case(
                            file,
                            "local name",
                            entry.key.as_str(),
                            &entry.key,
                            diagnostics,
                        );
                    }
                    continue;
                }
                _other => continue,
            };
            if let Some(label) = block.labels.get(index) {
                snake_case(file, kind, label.as_str(), label, diagnostics);
            }
        }
    }
}

fn snake_case(
    file: &ParsedFile,
    kind: &str,
    name: &str,
    node: &impl Span,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !hcl::is_snake_case(name) {
        diagnostics.push(error(
            "stricttf::name_not_snake_case",
            format!("{kind} \"{name}\" is not lower snake case; rename it using only lowercase letters, digits, and single underscores"),
            file.locate(node),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::{is_bounded_constraint, is_exact_version, is_registry_source, ref_problem};

    #[test]
    fn bounded_constraints_cap_the_major_version() {
        for bounded in [
            "~> 5.0",
            ">= 5.0, < 6.0",
            "5.82.2",
            "= 5.82.2",
            "<= 6",
            ">= 1.0,~> 1.2",
        ] {
            assert!(is_bounded_constraint(bounded), "{bounded}");
        }
        for unbounded in [">= 5.0", "> 5", "!= 5.1.0", ">= 5.0, != 5.3.0", ""] {
            assert!(!is_bounded_constraint(unbounded), "{unbounded}");
        }
    }

    #[test]
    fn exact_versions_select_one_release() {
        for exact in [
            "1.2.3",
            "= 1.2.3",
            "=1.2.3",
            " 1.2.3 ",
            "1.2.3-rc.1",
            "1.2.3+build.7",
        ] {
            assert!(is_exact_version(exact), "{exact}");
        }
        for inexact in [
            "~> 1.2",
            ">= 1.2.3",
            "1.2",
            "1.2.3, < 2.0.0",
            "v1.2.3",
            "1.2.x",
            "",
        ] {
            assert!(!is_exact_version(inexact), "{inexact}");
        }
    }

    #[test]
    fn registry_sources_are_recognised_by_shape() {
        for registry in [
            "terraform-aws-modules/vpc/aws",
            "app.terraform.io/example-corp/k8s-cluster/azurerm",
            "hashicorp/consul/aws//modules/consul-cluster",
            "registry.example.com:8443/ns/name/aws",
        ] {
            assert!(is_registry_source(registry), "{registry}");
        }
        for other in [
            "./modules/vpc",
            "github.com/hashicorp/example",
            "git::https://example.com/vpc.git",
            "s3::https://s3.amazonaws.com/bucket/vpc.zip",
            "https://example.com/vpc-module.zip",
            "hashicorp/consul",
            "bitbucket.org/hashicorp/terraform-consul-aws",
        ] {
            assert!(!is_registry_source(other), "{other}");
        }
    }

    #[test]
    fn vcs_refs_must_name_something_other_than_a_branch() {
        assert!(ref_problem("git::https://example.com/vpc.git").is_some());
        assert!(ref_problem("git::https://example.com/vpc.git?ref=main").is_some());
        assert!(ref_problem("github.com/org/repo?ref=").is_some());
        assert!(ref_problem("git::https://example.com/vpc.git//sub?ref=v1.2.0").is_none());
        assert!(ref_problem("git@github.com:org/repo.git?depth=1&ref=0a1b2c3").is_none());
        assert!(ref_problem("hg::http://example.com/vpc.hg?rev=v1.0.0").is_none());
    }
}
