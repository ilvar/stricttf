//! The diagnostic contract shared by every checking layer.
//!
//! This module is the public API between `stricttf` and a coding agent.
//! Its JSON shape is deliberately narrow, fully ordered, and free of
//! summary noise so an agent can consume a report in a
//! check -> patch -> re-check loop without heuristics.

use serde::Serialize;
use std::cmp::Ordering;

/// Diagnostic severity. Only these two levels reach the report; the
/// checker never emits notes or help-only entries as top-level records.
pub const LEVEL_ERROR: &str = "error";
/// See [`LEVEL_ERROR`].
pub const LEVEL_WARNING: &str = "warning";

/// A diagnostic produced by the `terraform` (or `tofu`) binary itself.
pub const SOURCE_TERRAFORM: &str = "terraform";
/// A diagnostic produced by a `stricttf` rule.
pub const SOURCE_STRICTTF: &str = "stricttf";

/// A single machine-readable report. Exactly one of these is written to
/// stdout per operational invocation.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Report {
    pub ok: bool,
    pub error_count: usize,
    pub warning_count: usize,
    pub diagnostics: Vec<Diagnostic>,
}

impl Report {
    /// A report with no diagnostics, used by non-checking commands that
    /// still have to satisfy the single-JSON-document contract.
    pub fn clean() -> Report {
        Report {
            ok: true,
            error_count: 0,
            warning_count: 0,
            diagnostics: Vec::new(),
        }
    }

    /// Sort, deduplicate, and count a diagnostic set into a report.
    ///
    /// Ordering is total and machine-independent: `(file, line, col,
    /// code, message)`. Deduplication happens after sorting so identical
    /// findings reported twice collapse into one record.
    pub fn build(mut diagnostics: Vec<Diagnostic>) -> Report {
        diagnostics.sort_by(compare_diagnostics);
        diagnostics.dedup();

        let error_count = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.level == LEVEL_ERROR)
            .count();
        let warning_count = diagnostics.len().saturating_sub(error_count);

        Report {
            ok: error_count == 0,
            error_count,
            warning_count,
            diagnostics,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Diagnostic {
    pub level: String,
    pub source: String,
    pub code: String,
    pub message: String,
    pub at: Location,
    pub fixes: Vec<Fix>,
}

impl Diagnostic {
    /// A located `stricttf` rule violation.
    pub fn rule(level: &str, code: &str, message: impl Into<String>, at: Location) -> Diagnostic {
        Diagnostic {
            level: level.to_owned(),
            source: SOURCE_STRICTTF.to_owned(),
            code: code.to_owned(),
            message: message.into(),
            at,
            fixes: Vec::new(),
        }
    }

    /// A located diagnostic normalised from the Terraform binary.
    pub fn terraform(
        level: &str,
        code: &str,
        message: impl Into<String>,
        at: Location,
    ) -> Diagnostic {
        Diagnostic {
            level: level.to_owned(),
            source: SOURCE_TERRAFORM.to_owned(),
            code: code.to_owned(),
            message: message.into(),
            at,
            fixes: Vec::new(),
        }
    }

    /// Attach a conservative mechanical fix.
    pub fn with_fix(mut self, fix: Fix) -> Diagnostic {
        self.fixes.push(fix);
        self
    }
}

/// A source span. Lines and columns are 1-based; columns count Unicode
/// scalar values, and `end_col` points one past the last character.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Location {
    pub file: String,
    pub line: u64,
    pub col: u64,
    pub end_line: u64,
    pub end_col: u64,
    /// The full text of the first line the span touches.
    pub snippet: String,
}

impl Location {
    /// A span covering an entire source line.
    pub fn whole_line(file: impl Into<String>, line: u64, snippet: &str) -> Location {
        Location {
            file: file.into(),
            line,
            col: 1,
            end_line: line,
            end_col: count(snippet.chars().count()).saturating_add(1),
            snippet: snippet.to_owned(),
        }
    }

    /// The location of the first line of `text`, or of an empty file.
    /// Used for findings about a file as a whole.
    pub fn file_start(file: impl Into<String>, text: &str) -> Location {
        Location::whole_line(file, 1, text.lines().next().unwrap_or_default())
    }

    /// A span over the byte range `start..end` of `text`.
    ///
    /// Out-of-range or non-boundary offsets are clamped to the nearest
    /// preceding character boundary, so a location can always be built
    /// and never panics on hostile input.
    pub fn from_span(file: impl Into<String>, text: &str, start: usize, end: usize) -> Location {
        let start = floor_boundary(text, start);
        let end = floor_boundary(text, end.max(start));
        let (line, col) = line_col(text, start);
        let (end_line, end_col) = line_col(text, end);
        Location {
            file: file.into(),
            line,
            col,
            end_line,
            end_col,
            snippet: line_text(text, line),
        }
    }
}

/// The 1-based `(line, column)` of a byte offset, counting columns in
/// characters. An offset inside a character counts as that character.
pub fn line_col(text: &str, offset: usize) -> (u64, u64) {
    let offset = floor_boundary(text, offset);
    let before = text.get(..offset).unwrap_or(text);
    let line_start = before
        .rfind('\n')
        .map_or(0, |index| index.saturating_add(1));
    let line = count(before.matches('\n').count()).saturating_add(1);
    let col = count(before.get(line_start..).unwrap_or("").chars().count()).saturating_add(1);
    (line, col)
}

/// The text of a 1-based line, without its terminator, or empty when the
/// line does not exist.
pub fn line_text(text: &str, line: u64) -> String {
    let index = usize::try_from(line.saturating_sub(1)).unwrap_or(usize::MAX);
    text.lines()
        .nth(index)
        .unwrap_or_default()
        .trim_end_matches('\r')
        .to_owned()
}

/// The byte offset where a 1-based line begins, if the line exists. A
/// line one past a trailing newline begins at the end of the text.
pub fn line_start(text: &str, line: u64) -> Option<usize> {
    if line == 0 {
        return None;
    }
    let mut remaining = line.saturating_sub(1);
    let mut offset = 0usize;
    while remaining > 0 {
        let rest = text.get(offset..)?;
        let newline = rest.find('\n')?;
        offset = offset.saturating_add(newline).saturating_add(1);
        remaining = remaining.saturating_sub(1);
    }
    Some(offset)
}

fn floor_boundary(text: &str, offset: usize) -> usize {
    let mut offset = offset.min(text.len());
    while offset > 0 && !text.is_char_boundary(offset) {
        offset = offset.saturating_sub(1);
    }
    offset
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// A replacement `stricttf` is willing to apply mechanically.
///
/// Every fix is span-exact and idempotent by construction. Rules that
/// cannot describe an unambiguous replacement emit no fix at all rather
/// than guessing.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Fix {
    pub hint: String,
    pub replace_with: String,
    pub line: u64,
    pub col: u64,
    pub end_line: u64,
    pub end_col: u64,
    #[serde(skip)]
    pub edit: Option<EditSpan>,
}

impl Fix {
    /// Replace the byte range `start..end` of `file`, whose full text is
    /// `text`, with `replace_with`.
    pub fn replace(
        hint: impl Into<String>,
        file: &str,
        text: &str,
        start: usize,
        end: usize,
        replace_with: impl Into<String>,
    ) -> Fix {
        let span = Location::from_span(file, text, start, end);
        Fix {
            hint: hint.into(),
            replace_with: replace_with.into(),
            line: span.line,
            col: span.col,
            end_line: span.end_line,
            end_col: span.end_col,
            edit: Some(EditSpan {
                file: file.to_owned(),
                byte_start: start,
                byte_end: end,
            }),
        }
    }
}

/// The byte range a fix rewrites. Retained as internal metadata so edits
/// are applied against real offsets instead of reconstructed from display
/// columns; `#[serde(skip)]` keeps it out of the public JSON shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditSpan {
    pub file: String,
    pub byte_start: usize,
    pub byte_end: usize,
}

/// Total order over diagnostics. Exposed so every layer sorts the same
/// way and golden files stay stable across machines.
pub fn compare_diagnostics(left: &Diagnostic, right: &Diagnostic) -> Ordering {
    diagnostic_key(left).cmp(&diagnostic_key(right))
}

fn diagnostic_key(diagnostic: &Diagnostic) -> (&str, u64, u64, &str, &str) {
    (
        diagnostic.at.file.as_str(),
        diagnostic.at.line,
        diagnostic.at.col,
        diagnostic.code.as_str(),
        diagnostic.message.as_str(),
    )
}

#[cfg(test)]
mod tests {
    use super::{line_col, line_start, line_text, Location};

    #[test]
    fn spans_count_characters_not_bytes() {
        let text = "a = \"é\"\nb = 1\n";
        let start = text.find('b').expect("b is present");
        let span = Location::from_span("main.tf", text, start, start.saturating_add(1));
        assert_eq!(
            (span.line, span.col, span.end_line, span.end_col),
            (2, 1, 2, 2)
        );
        assert_eq!(span.snippet, "b = 1");
        assert_eq!(line_col(text, 7), (1, 7));
        assert_eq!(line_col(text, 6), (1, 6));
    }

    #[test]
    fn hostile_offsets_are_clamped_instead_of_panicking() {
        let text = "é";
        let span = Location::from_span("main.tf", text, 1, 99);
        assert_eq!((span.line, span.col), (1, 1));
        assert_eq!(line_text(text, 5), "");
    }

    #[test]
    fn line_starts_are_byte_offsets() {
        let text = "one\ntwo\n";
        assert_eq!(line_start(text, 1), Some(0));
        assert_eq!(line_start(text, 2), Some(4));
        assert_eq!(line_start(text, 3), Some(8));
        assert_eq!(line_start(text, 4), None);
        assert_eq!(line_start(text, 0), None);
    }
}
