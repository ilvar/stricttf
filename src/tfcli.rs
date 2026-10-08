//! Terraform oracle layer.
//!
//! Terraform is the authority on whether a module formats, initialises,
//! and validates. `stricttf` does not reimplement any of that; it runs
//! `fmt`, `init`, and `validate` and normalises their output into the same
//! located, deterministic diagnostic records every other layer produces.
//!
//! A check must leave the module exactly as it found it. Terraform's
//! working data therefore lives in a per-module cache directory outside
//! the module, an existing lock file is only ever read, and a lock file
//! that `init` creates is removed again before the check returns.
//!
//! Every parser here is pure and takes the captured text, so the
//! normalisation contract is golden-tested without a Terraform binary.

use crate::capability::{self, Invocation};
use crate::hcl::SourceFile;
use crate::report::{line_text, Diagnostic, Fix, Location, LEVEL_ERROR, LEVEL_WARNING};
use crate::{ModuleSources, LOCK_FILE};
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

const CODE_FMT: &str = "terraform::fmt";
const CODE_INIT: &str = "terraform::init";
const CODE_VALIDATE: &str = "terraform::validate";

/// The binary the Terraform layer runs: `terraform` when present, else
/// OpenTofu, whose `fmt`, `init`, and `validate` share the same contract.
pub fn binary() -> Option<&'static str> {
    ["terraform", "tofu"]
        .into_iter()
        .find(|name| capability::executable_on_path(name))
}

/// Run `fmt`, `init`, and `validate` against a module and normalise what
/// they report.
///
/// An `Err` is an operational failure -- the binary could not run, or
/// produced output that cannot be understood -- never a finding about
/// the module.
pub fn check(
    module_dir: &Path,
    binary: &str,
    sources: &ModuleSources,
) -> Result<Vec<Diagnostic>, String> {
    let environment = environment(module_dir)?;
    let mut diagnostics = format_diagnostics(module_dir, binary, &environment, sources)?;

    let lock_file = module_dir.join(LOCK_FILE);
    let had_lock_file = capability::is_file(&lock_file);
    let checked = init_and_validate(module_dir, binary, &environment, sources, had_lock_file);
    // The lock file `init` wrote is needed by `validate`, so it is only
    // removed once both have run -- and removed even when they failed.
    let restored = if had_lock_file {
        Ok(())
    } else {
        capability::remove_file(&lock_file)
    };

    diagnostics.extend(checked?);
    restored?;
    Ok(diagnostics)
}

/// The environment every invocation runs with: no prompts, no colour, no
/// update check, and working data kept out of the module.
fn environment(module_dir: &Path) -> Result<Vec<(String, String)>, String> {
    let canonical = capability::canonicalize(module_dir)?;
    let key = fnv1a_64(canonical.as_os_str().as_encoded_bytes());
    let data_dir = capability::cache_dir(&format!("data-{key:016x}"))?;
    let data_dir = data_dir
        .to_str()
        .ok_or_else(|| format!("cache directory {} is not UTF-8", data_dir.display()))?
        .to_owned();

    Ok(vec![
        ("TF_IN_AUTOMATION".to_owned(), "1".to_owned()),
        ("TF_INPUT".to_owned(), "0".to_owned()),
        ("CHECKPOINT_DISABLE".to_owned(), "1".to_owned()),
        ("TF_DATA_DIR".to_owned(), data_dir),
    ])
}

/// FNV-1a, 64-bit. The cache key only has to be stable across runs and
/// machines, not cryptographic, so a dependency would buy nothing.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    bytes.iter().fold(OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
    })
}

fn invoke(
    module_dir: &Path,
    binary: &str,
    environment: &[(String, String)],
    arguments: &[&str],
    stdin: Option<&str>,
) -> Result<capability::ToolOutput, String> {
    let arguments: Vec<String> = arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect();
    capability::run_with(&Invocation {
        program: binary,
        arguments: &arguments,
        working_dir: module_dir,
        environment,
        stdin,
    })
}

/// Format every file through `fmt` on stdin, so nothing is rewritten in
/// place and each difference becomes a span-exact fix.
fn format_diagnostics(
    module_dir: &Path,
    binary: &str,
    environment: &[(String, String)],
    sources: &ModuleSources,
) -> Result<Vec<Diagnostic>, String> {
    let mut diagnostics = Vec::new();
    let files = sources
        .configuration
        .iter()
        .chain(&sources.variable_files)
        .chain(&sources.test_files);

    for file in files {
        let output = invoke(
            module_dir,
            binary,
            environment,
            &["fmt", "-no-color", "-"],
            Some(&file.text),
        )?;
        // A file `fmt` cannot parse has no canonical form; `validate`
        // reports why, with a location.
        if output.success {
            diagnostics.extend(fmt_diagnostic(file, &output.stdout));
        }
    }

    Ok(diagnostics)
}

fn init_and_validate(
    module_dir: &Path,
    binary: &str,
    environment: &[(String, String)],
    sources: &ModuleSources,
    had_lock_file: bool,
) -> Result<Vec<Diagnostic>, String> {
    let mut arguments = vec!["init", "-backend=false", "-input=false", "-no-color"];
    if had_lock_file {
        arguments.push("-lockfile=readonly");
    }
    let init = invoke(module_dir, binary, environment, &arguments, None)?;
    if !init.success {
        let diagnostics = parse_init_errors(&init.stderr, sources);
        if diagnostics.is_empty() {
            return Err(format!(
                "{binary} init failed without a parsable error: {}",
                init.stderr.trim()
            ));
        }
        // Without an initialised working directory `validate` can only
        // repeat that providers or modules are missing.
        return Ok(diagnostics);
    }

    let validate = invoke(
        module_dir,
        binary,
        environment,
        &["validate", "-json", "-no-color"],
        None,
    )?;
    parse_validate_json(&validate.stdout, sources).map_err(|error| {
        format!(
            "{binary} validate produced no usable report ({error}): {}",
            validate.stderr.trim()
        )
    })
}

/// The `terraform::fmt` diagnostic for a file whose canonical form is
/// `formatted`, or `None` when the file is already canonical.
///
/// The fix replaces only the bytes between the first and last
/// difference, so it is minimal, and replaces them with exactly what
/// `fmt` wrote there, so applying it makes the file equal to `formatted`.
pub fn fmt_diagnostic(file: &SourceFile, formatted: &str) -> Option<Diagnostic> {
    if file.text == formatted {
        return None;
    }
    let (start, old_end, new_end) = differing_range(&file.text, formatted);
    let replacement = formatted.get(start..new_end)?;

    let at = Location::from_span(file.path.as_str(), &file.text, start, old_end);
    let fix = Fix::replace(
        "rewrite this region the way terraform fmt lays it out",
        &file.path,
        &file.text,
        start,
        old_end,
        replacement,
    );
    Some(
        Diagnostic::terraform(
            LEVEL_ERROR,
            CODE_FMT,
            format!(
                "{} is not in terraform fmt layout; apply the fix or run terraform fmt",
                file.path
            ),
            at,
        )
        .with_fix(fix),
    )
}

/// `(start, old_end, new_end)` such that `old[start..old_end]` is the only
/// region where `old` and `new[start..new_end]` differ. Both ends sit on
/// character boundaries in both texts, so either slice is valid UTF-8.
fn differing_range(old: &str, new: &str) -> (usize, usize, usize) {
    let old_bytes = old.as_bytes();
    let new_bytes = new.as_bytes();

    let mut prefix = old_bytes
        .iter()
        .zip(new_bytes)
        .take_while(|(left, right)| left == right)
        .count();
    while prefix > 0 && !(old.is_char_boundary(prefix) && new.is_char_boundary(prefix)) {
        prefix = prefix.saturating_sub(1);
    }

    // The suffix may not overlap the prefix in the shorter text.
    let limit = old.len().min(new.len()).saturating_sub(prefix);
    let mut suffix = old_bytes
        .iter()
        .rev()
        .zip(new_bytes.iter().rev())
        .take(limit)
        .take_while(|(left, right)| left == right)
        .count();
    loop {
        let old_end = old.len().saturating_sub(suffix);
        let new_end = new.len().saturating_sub(suffix);
        if suffix == 0 || (old.is_char_boundary(old_end) && new.is_char_boundary(new_end)) {
            return (prefix, old_end, new_end);
        }
        suffix = suffix.saturating_sub(1);
    }
}

#[derive(Deserialize)]
struct ValidateOutput {
    diagnostics: Vec<ValidateDiagnostic>,
}

#[derive(Deserialize)]
struct ValidateDiagnostic {
    severity: String,
    summary: String,
    #[serde(default)]
    detail: String,
    range: Option<ValidateRange>,
    snippet: Option<ValidateSnippet>,
}

#[derive(Deserialize)]
struct ValidateRange {
    filename: String,
    start: ValidatePosition,
    end: ValidatePosition,
}

#[derive(Deserialize)]
struct ValidatePosition {
    line: u64,
    column: u64,
    byte: usize,
}

#[derive(Deserialize)]
struct ValidateSnippet {
    code: String,
}

/// Normalise `validate -json` output into diagnostics.
///
/// Terraform's byte offsets are preferred over its columns whenever the
/// file is one of the module's own, so the location is computed exactly
/// the way every `stricttf` rule computes one. An `Err` means the text is
/// not a validate report at all.
pub fn parse_validate_json(text: &str, sources: &ModuleSources) -> Result<Vec<Diagnostic>, String> {
    let output: ValidateOutput = serde_json::from_str(text)
        .map_err(|error| format!("validate output is not the expected JSON: {error}"))?;

    let mut diagnostics = Vec::new();
    for diagnostic in output.diagnostics {
        let level = match diagnostic.severity.as_str() {
            "error" => LEVEL_ERROR,
            "warning" => LEVEL_WARNING,
            other => return Err(format!("validate reported unknown severity {other:?}")),
        };
        let at = match diagnostic.range {
            Some(range) => range_location(&range, diagnostic.snippet.as_ref(), sources),
            None => Location::whole_line(".", 1, ""),
        };
        diagnostics.push(Diagnostic::terraform(
            level,
            CODE_VALIDATE,
            message(&diagnostic.summary, &diagnostic.detail),
            at,
        ));
    }
    Ok(diagnostics)
}

fn range_location(
    range: &ValidateRange,
    snippet: Option<&ValidateSnippet>,
    sources: &ModuleSources,
) -> Location {
    let file = normalise_path(&range.filename);
    if let Some(source) = find_source(sources, &file) {
        return Location::from_span(file, &source.text, range.start.byte, range.end.byte);
    }
    // A file outside the module's own set, such as a child module's: keep
    // Terraform's coordinates and the code line it quoted.
    let snippet = snippet
        .and_then(|snippet| snippet.code.lines().next())
        .unwrap_or_default();
    Location {
        file,
        line: range.start.line,
        col: range.start.column,
        end_line: range.end.line,
        end_col: range.end.column,
        snippet: snippet.to_owned(),
    }
}

/// One `Error:` block of `init`'s human-oriented stderr.
struct ErrorBlock<'a> {
    /// Every line up to the first blank one: Terraform wraps a long
    /// summary onto continuation lines before the blank line that
    /// separates it from the detail.
    summary: Vec<&'a str>,
    lines: Vec<&'a str>,
}

/// Normalise a failed `init`'s stderr into `terraform::init` errors.
///
/// Each `Error: <summary>` block becomes one diagnostic. Its location is
/// the `on <file> line <n>` reference Terraform prints when it has one,
/// else a `<file>:<n>` reference to a module file inside the detail,
/// else the module as a whole. Warning blocks are dropped: they did not
/// cause the failure.
pub fn parse_init_errors(stderr: &str, sources: &ModuleSources) -> Vec<Diagnostic> {
    let (Ok(source_line), Ok(excerpt), Ok(embedded)) = (
        Regex::new(r"^\s*on (.+?) line (\d+)(?:,.*)?:\s*$"),
        Regex::new(r"^\s*(?:(\d+):|[├│╵╷])"),
        Regex::new(r"\bat ([^\s:]+):(\d+)\b"),
    ) else {
        return Vec::new();
    };

    let mut diagnostics = Vec::new();
    for block in error_blocks(stderr) {
        let mut location: Option<(String, u64)> = None;
        let mut excerpts: Vec<(u64, &str)> = Vec::new();
        let mut detail: Vec<&str> = Vec::new();

        for line in &block.lines {
            if let Some(capture) = source_line.captures(line) {
                let parsed = capture
                    .get(2)
                    .and_then(|number| number.as_str().parse::<u64>().ok());
                if let (Some(file), Some(number), None) = (capture.get(1), parsed, &location) {
                    location = Some((normalise_path(file.as_str()), number));
                }
                continue;
            }
            if let Some(capture) = excerpt.captures(line) {
                let number = capture
                    .get(1)
                    .and_then(|number| number.as_str().parse::<u64>().ok());
                if let (Some(number), Some((_prefix, code))) = (number, line.split_once(':')) {
                    excerpts.push((number, code.strip_prefix(' ').unwrap_or(code)));
                }
                continue;
            }
            detail.push(line);
        }

        let detail = detail.join("\n");
        if location.is_none() {
            location = embedded
                .captures_iter(&detail)
                .filter_map(|capture| {
                    let file = normalise_path(capture.get(1)?.as_str());
                    let number = capture.get(2)?.as_str().parse::<u64>().ok()?;
                    find_source(sources, &file).map(|_source| (file, number))
                })
                .next();
        }

        let at = match location {
            Some((file, number)) => {
                let snippet = match find_source(sources, &file) {
                    Some(source) => line_text(&source.text, number),
                    None => excerpts
                        .iter()
                        .find(|(line, _code)| *line == number)
                        .map(|(_line, code)| (*code).to_owned())
                        .unwrap_or_default(),
                };
                Location::whole_line(file, number, &snippet)
            }
            None => Location::whole_line(".", 1, ""),
        };
        diagnostics.push(Diagnostic::terraform(
            LEVEL_ERROR,
            CODE_INIT,
            message(&block.summary.join(" "), &detail),
            at,
        ));
    }
    diagnostics
}

fn error_blocks(stderr: &str) -> Vec<ErrorBlock<'_>> {
    let mut blocks = Vec::new();
    let mut current: Option<ErrorBlock<'_>> = None;

    for line in stderr.lines() {
        let error = line.strip_prefix("Error: ");
        if error.is_some() || line.starts_with("Warning: ") {
            blocks.extend(current.take());
            current = error.map(|summary| ErrorBlock {
                summary: vec![summary],
                lines: Vec::new(),
            });
            continue;
        }
        if let Some(block) = current.as_mut() {
            if block.lines.is_empty() && !line.trim().is_empty() {
                block.summary.push(line);
            } else {
                block.lines.push(line);
            }
        }
    }
    blocks.extend(current);
    blocks
}

/// `summary: detail` on one line. Terraform wraps detail text to the
/// terminal width; collapsing whitespace makes the message independent
/// of where the wrap fell.
fn message(summary: &str, detail: &str) -> String {
    let summary = collapse_whitespace(summary);
    let detail = collapse_whitespace(detail);
    if detail.is_empty() {
        summary
    } else {
        format!("{summary}: {detail}")
    }
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Module-relative with `/` separators, the way the report addresses
/// every file.
fn normalise_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let mut trimmed = path.as_str();
    while let Some(rest) = trimmed.strip_prefix("./") {
        trimmed = rest;
    }
    trimmed.to_owned()
}

fn find_source<'a>(sources: &'a ModuleSources, path: &str) -> Option<&'a SourceFile> {
    sources
        .configuration
        .iter()
        .chain(&sources.variable_files)
        .chain(&sources.test_files)
        .find(|file| file.path == path)
}

#[cfg(test)]
mod tests {
    use super::{differing_range, fnv1a_64, normalise_path};

    #[test]
    fn fnv1a_matches_the_published_test_vectors() {
        assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    fn apply(old: &str, new: &str) -> String {
        let (start, old_end, new_end) = differing_range(old, new);
        format!(
            "{}{}{}",
            &old[..start],
            &new[start..new_end],
            &old[old_end..]
        )
    }

    #[test]
    fn the_differing_range_trims_the_common_prefix_and_suffix() {
        assert_eq!(differing_range("a=1\n", "a = 1\n"), (1, 2, 4));
        assert_eq!(differing_range("abc", "abc"), (3, 3, 3));
        assert_eq!(differing_range("", "x\n"), (0, 0, 2));
    }

    #[test]
    fn the_differing_range_never_splits_a_character() {
        for (old, new) in [
            ("é", "è"),
            ("xéy", "xèy"),
            ("aé", "a"),
            ("\u{1F600}a", "\u{1F601}a"),
            ("ab", "aab"),
            ("aa", "a"),
        ] {
            assert_eq!(apply(old, new), new, "{old:?} -> {new:?}");
        }
    }

    #[test]
    fn paths_are_module_relative_with_forward_slashes() {
        assert_eq!(normalise_path("./main.tf"), "main.tf");
        assert_eq!(
            normalise_path("modules\\net\\main.tf"),
            "modules/net/main.tf"
        );
    }
}
