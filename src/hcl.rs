//! Parsing and location helpers shared by every source-level layer.
//!
//! `stricttf` does not interpret Terraform; it parses HCL only to locate
//! constructs exactly. `hcl-edit` keeps byte spans for every block,
//! attribute, and expression it parses, so each diagnostic points at the
//! precise bytes it is about, and each fix rewrites exactly those bytes.

use crate::report::{Diagnostic, Location, LEVEL_ERROR};
use hcl_edit::expr::Expression;
use hcl_edit::structure::{Attribute, Block, Body};
use hcl_edit::Span;
use std::ops::Range;

/// One module file, addressed relative to the module root with `/`
/// separators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    pub path: String,
    pub text: String,
}

/// A file that parsed as HCL, with its spans intact.
#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub path: String,
    pub text: String,
    pub body: Body,
}

impl ParsedFile {
    /// Whether Terraform treats this file as an override file
    /// (`override.tf` or `*_override.tf`), whose blocks are partial by
    /// design: they merge into a block declared elsewhere, so the
    /// arguments that block already sets are legitimately absent here.
    pub fn is_override(&self) -> bool {
        let name = self.path.rsplit('/').next().unwrap_or(self.path.as_str());
        name == "override.tf" || name.ends_with("_override.tf")
    }

    /// The location of a byte span within this file.
    pub fn location(&self, span: &Range<usize>) -> Location {
        Location::from_span(self.path.as_str(), &self.text, span.start, span.end)
    }

    /// The location of anything carrying a span, falling back to the
    /// first line of the file when the parser recorded none.
    pub fn locate(&self, node: &impl Span) -> Location {
        match node.span() {
            Some(span) => self.location(&span),
            None => Location::file_start(self.path.as_str(), &self.text),
        }
    }

    /// The location of a block's header -- its type and labels -- rather
    /// than of the whole multi-line block.
    pub fn locate_header(&self, block: &Block) -> Location {
        let start = block.ident.span().or_else(|| block.span());
        let end = block
            .labels
            .last()
            .and_then(|label| label.span())
            .or_else(|| block.ident.span());
        match (start, end) {
            (Some(start), Some(end)) => self.location(&(start.start..end.end)),
            _other => self.locate(block),
        }
    }

    /// The source text of a spanned node, exactly as written.
    pub fn source_of(&self, node: &impl Span) -> Option<&str> {
        node.span().and_then(|span| self.text.get(span))
    }
}

/// Parse a file, or return the located `stricttf::syntax_error` that
/// explains why it is not HCL.
pub fn parse(file: &SourceFile) -> Result<ParsedFile, Box<Diagnostic>> {
    match hcl_edit::parser::parse_body(&file.text) {
        Ok(body) => Ok(ParsedFile {
            path: file.path.clone(),
            text: file.text.clone(),
            body,
        }),
        Err(error) => {
            let offset = error.location().offset();
            let message = format!("{} is not valid HCL: {}", file.path, error.message().trim());
            Err(Box::new(Diagnostic::rule(
                LEVEL_ERROR,
                "stricttf::syntax_error",
                message,
                Location::from_span(file.path.as_str(), &file.text, offset, offset),
            )))
        }
    }
}

/// The label at `index`, if the block has that many.
pub fn label(block: &Block, index: usize) -> Option<&str> {
    block.labels.get(index).map(|label| label.as_str())
}

/// The first attribute named `key` directly inside `body`.
pub fn attribute<'a>(body: &'a Body, key: &str) -> Option<&'a Attribute> {
    body.get_attribute(key)
}

/// Every top-level block of a given type, across all parsed files, paired
/// with the file that declares it, in file order.
pub fn blocks<'a>(files: &'a [ParsedFile], ident: &str) -> Vec<(&'a ParsedFile, &'a Block)> {
    files
        .iter()
        .flat_map(|file| {
            file.body
                .blocks()
                .filter(move |block| block.has_ident(ident))
                .map(move |block| (file, block))
        })
        .collect()
}

/// The value of a literal string expression, if the expression is one.
/// A template containing any interpolation or directive is not literal.
pub fn literal_string(expression: &Expression) -> Option<&str> {
    match expression {
        Expression::String(value) => Some(value.as_str()),
        Expression::Null(_)
        | Expression::Bool(_)
        | Expression::Number(_)
        | Expression::Array(_)
        | Expression::Object(_)
        | Expression::StringTemplate(_)
        | Expression::HeredocTemplate(_)
        | Expression::Parenthesis(_)
        | Expression::Variable(_)
        | Expression::Conditional(_)
        | Expression::FuncCall(_)
        | Expression::Traversal(_)
        | Expression::UnaryOp(_)
        | Expression::BinaryOp(_)
        | Expression::ForExpr(_) => None,
    }
}

/// Whether an identifier is lower snake case: lowercase ASCII letters,
/// digits, and single underscores, starting with a letter.
pub fn is_snake_case(name: &str) -> bool {
    let mut characters = name.chars();
    let starts_with_letter = characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase());
    starts_with_letter
        && name.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
        && !name.contains("__")
        && !name.ends_with('_')
}

/// Final name segments that, on their own, name credential material.
const SECRET_WORDS: &[&str] = &["passphrase", "passwd", "password", "token"];

/// Final name segments that name credential material only when qualified
/// by a preceding segment. A bare `secret` is how GCP and Kubernetes
/// arguments *refer to* a stored secret by name (`secret_key_ref`,
/// `secret_environment_variables`), while `client_secret` holds one.
const QUALIFIED_SECRET_WORDS: &[&str] = &["secret"];

/// Final two-segment suffixes that name credential material.
const SECRET_PAIRS: &[(&str, &str)] = &[
    ("access", "key"),
    ("api", "key"),
    ("private", "key"),
    ("secret", "key"),
    ("secret", "string"),
];

/// Final two-segment suffixes that end in a credential word but name an
/// idempotency key -- a caller-chosen deduplication string such as
/// `aws_efs_file_system.creation_token` -- which is not secret at all.
const IDEMPOTENCY_PAIRS: &[(&str, &str)] = &[
    ("client", "token"),
    ("creation", "token"),
    ("idempotency", "token"),
];

/// Whether an argument or variable name denotes credential material.
///
/// Only the *final* segment decides, so `db_password` and `api_token` are
/// secrets while `password_length`, `token_ttl`, and `secret_arn` -- which
/// describe a secret without containing one -- are not. A bare `secret`
/// and the idempotency keys (`creation_token`, `client_token`,
/// `idempotency_token`) name identifiers, not credentials.
pub fn is_secret_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    let segments: Vec<&str> = lowered
        .split(['_', '-'])
        .filter(|segment| !segment.is_empty())
        .collect();
    let Some((last, rest)) = segments.split_last() else {
        return false;
    };
    let before = rest.last();
    if before.is_some_and(|before| IDEMPOTENCY_PAIRS.contains(&(*before, *last))) {
        return false;
    }
    if SECRET_WORDS.contains(last) {
        return true;
    }
    if QUALIFIED_SECRET_WORDS.contains(last) {
        return before.is_some();
    }
    before.is_some_and(|before| SECRET_PAIRS.contains(&(*before, *last)))
}

#[cfg(test)]
mod tests {
    use super::{is_secret_name, is_snake_case, label, parse, SourceFile};

    #[test]
    fn only_the_final_name_segment_marks_a_secret() {
        for secret in [
            "password",
            "passwd",
            "passphrase",
            "token",
            "db_password",
            "api_token",
            "client_secret",
            "app_secret",
            "private_key",
            "aws-secret-key",
            "secret_string",
            "ADMIN_PASSWORD",
            "access_token",
        ] {
            assert!(is_secret_name(secret), "{secret}");
        }
        for plain in [
            "password_length",
            "token_ttl",
            "secret_arn",
            "secret",
            "SECRET",
            "creation_token",
            "client_token",
            "idempotency_token",
            "key",
            "key_name",
            "",
            "_",
        ] {
            assert!(!is_secret_name(plain), "{plain}");
        }
    }

    fn source(text: &str) -> SourceFile {
        SourceFile {
            path: "main.tf".to_owned(),
            text: text.to_owned(),
        }
    }

    #[test]
    fn a_syntax_error_is_located_where_the_parser_stopped() {
        let error = parse(&source("variable \"a\" {\n  type = \n}\n"))
            .expect_err("an attribute without a value is not HCL");
        assert_eq!(error.code, "stricttf::syntax_error");
        assert_eq!(error.at.file, "main.tf");
        assert!(error.at.line >= 2, "{error:?}");
    }

    #[test]
    fn block_headers_stop_before_the_opening_brace() {
        let parsed = parse(&source(
            "resource \"aws_s3_bucket\" \"logs\" {\n  bucket = \"x\"\n}\n",
        ))
        .expect("valid HCL parses");
        let block = parsed.body.blocks().next().expect("one block");
        assert_eq!(label(block, 1), Some("logs"));
        let header = parsed.locate_header(block);
        assert_eq!((header.line, header.col, header.end_line), (1, 1, 1));
        assert_eq!(header.end_col, 32);
    }

    #[test]
    fn snake_case_is_strict() {
        for good in ["a", "web_server", "v2_name"] {
            assert!(is_snake_case(good), "{good}");
        }
        for bad in [
            "",
            "Web",
            "web-server",
            "_web",
            "web_",
            "web__server",
            "2web",
        ] {
            assert!(!is_snake_case(bad), "{bad}");
        }
    }
}
