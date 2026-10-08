//! Trivy security-scan layer.
//!
//! `trivy config` evaluates the module against trivy's embedded
//! misconfiguration checks. `stricttf` does not reimplement any of them;
//! it runs the scan and normalises each failed check into the same
//! located, deterministic diagnostic record every other layer produces.
//!
//! The scan must depend only on the module and the trivy version:
//!
//! - only the checks embedded in the binary run (`--skip-check-update`
//!   against a cache directory `stricttf` owns, which never receives a
//!   downloaded bundle);
//! - the module cannot weaken the scan: a `.trivyignore` and a
//!   `trivy.yaml` in it are not loaded (`--ignorefile ""`,
//!   `--config ""`). Inline `#trivy:ignore:` comments are honoured by
//!   trivy and cannot be disabled;
//! - remote module sources are never fetched: every HTTP client is sent
//!   to a proxy that refuses connections and git may use no transport,
//!   so a registry's state cannot change the result;
//! - trivy's temporary files live in the cache directory, and nothing is
//!   written into the module.
//!
//! The parser is pure and takes the captured JSON, so the normalisation
//! contract is golden-tested without a trivy binary.

use crate::capability::{self, Invocation};
use crate::hcl::SourceFile;
use crate::report::{
    line_start, line_text, Diagnostic, Location, LEVEL_ERROR, LEVEL_WARNING, SOURCE_TRIVY,
};
use crate::ModuleSources;
use serde::Deserialize;
use std::path::Path;

const CODE_UNAVAILABLE: &str = "trivy::unavailable";

/// The only JSON report schema the parser understands.
const SCHEMA_VERSION: u64 = 2;

/// An address nothing listens on, so any download fails immediately.
const REFUSING_PROXY: &str = "http://127.0.0.1:9";

/// The binary the security-scan layer runs, when it is on `PATH`.
pub fn binary() -> Option<&'static str> {
    ["trivy"]
        .into_iter()
        .find(|name| capability::executable_on_path(name))
}

/// Run `trivy config` against a module and normalise its failed checks.
///
/// Without a trivy binary the layer is skipped loudly: one warning says
/// so, and the check does not fail because of it. An `Err` is an
/// operational failure -- trivy could not run, or produced output that
/// cannot be understood -- never a finding about the module.
pub fn check(module_dir: &Path, sources: &ModuleSources) -> Result<Vec<Diagnostic>, String> {
    let Some(binary) = binary() else {
        return Ok(vec![unavailable()]);
    };

    let cache_dir = capability::cache_dir("trivy")?;
    let temp_dir = capability::cache_dir("trivy/tmp")?;
    let arguments: Vec<String> = [
        "config",
        "--quiet",
        "--format",
        "json",
        "--exit-code",
        "0",
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
        "--misconfig-scanners",
        "terraform",
        "--severity",
        "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
        "--cache-dir",
        utf8(&cache_dir)?,
        "--module-dir",
        utf8(&cache_dir.join("modules"))?,
        "--config",
        "",
        "--ignorefile",
        "",
        ".",
    ]
    .iter()
    .map(|argument| (*argument).to_owned())
    .collect();

    let mut environment = vec![("TMPDIR".to_owned(), utf8(&temp_dir)?.to_owned())];
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        environment.push((name.to_owned(), REFUSING_PROXY.to_owned()));
    }
    for name in ["NO_PROXY", "no_proxy"] {
        environment.push((name.to_owned(), String::new()));
    }
    environment.push(("GIT_ALLOW_PROTOCOL".to_owned(), "none".to_owned()));
    environment.push(("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()));

    let output = capability::run_with(&Invocation {
        program: binary,
        arguments: &arguments,
        working_dir: module_dir,
        environment: &environment,
        stdin: None,
    })?;
    if !output.success {
        return Err(format!(
            "trivy config failed: {}",
            collapse_whitespace(&output.stderr)
        ));
    }
    parse_report(&output.stdout, sources)
}

fn utf8(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("cache directory {} is not UTF-8", path.display()))
}

fn unavailable() -> Diagnostic {
    trivy_diagnostic(
        LEVEL_WARNING,
        CODE_UNAVAILABLE.to_owned(),
        "The trivy security-scan layer did not run because trivy is not on PATH; install trivy (CI pins 0.75.0) to run it.",
        Location::whole_line(".", 1, ""),
    )
}

fn trivy_diagnostic(
    level: &str,
    code: String,
    message: impl Into<String>,
    at: Location,
) -> Diagnostic {
    Diagnostic {
        level: level.to_owned(),
        source: SOURCE_TRIVY.to_owned(),
        code,
        message: message.into(),
        at,
        fixes: Vec::new(),
    }
}

#[derive(Deserialize)]
struct ScanReport {
    #[serde(rename = "SchemaVersion")]
    schema_version: u64,
    #[serde(rename = "Results")]
    results: Option<Vec<ScanResult>>,
}

#[derive(Deserialize)]
struct ScanResult {
    #[serde(rename = "Target")]
    target: String,
    #[serde(rename = "Misconfigurations")]
    misconfigurations: Option<Vec<Misconfiguration>>,
}

#[derive(Deserialize)]
struct Misconfiguration {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Message", default)]
    message: String,
    #[serde(rename = "Resolution", default)]
    resolution: String,
    #[serde(rename = "Severity")]
    severity: String,
    #[serde(rename = "PrimaryURL", default)]
    primary_url: String,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "CauseMetadata", default)]
    cause: CauseMetadata,
}

#[derive(Deserialize, Default)]
struct CauseMetadata {
    #[serde(rename = "StartLine")]
    start_line: Option<u64>,
    #[serde(rename = "EndLine")]
    end_line: Option<u64>,
}

/// Normalise a `trivy config --format json` report into diagnostics.
///
/// Only findings in files directly in the module are kept: a finding in
/// a nested directory belongs to that module's own check. Only failed
/// checks are findings. An `Err` means the text is not a report this
/// parser understands, or the scan of a module with configuration
/// produced no results at all.
pub fn parse_report(json: &str, sources: &ModuleSources) -> Result<Vec<Diagnostic>, String> {
    let report: ScanReport = serde_json::from_str(json)
        .map_err(|error| format!("trivy output is not the expected JSON: {error}"))?;
    if report.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "trivy reported schema version {}, but only {SCHEMA_VERSION} is understood",
            report.schema_version
        ));
    }
    let Some(results) = report.results else {
        // trivy omits `Results` only when it found nothing to scan, which
        // cannot be true of a module with configuration files.
        if sources.configuration.is_empty() {
            return Ok(Vec::new());
        }
        return Err("trivy scanned the module but reported no results".to_owned());
    };

    let mut diagnostics = Vec::new();
    for result in results {
        let Some(file) = module_file(sources, &normalise_path(&result.target)) else {
            continue;
        };
        for misconfiguration in result.misconfigurations.unwrap_or_default() {
            if misconfiguration.status != "FAIL" {
                continue;
            }
            diagnostics.push(diagnostic(file, &misconfiguration)?);
        }
    }
    Ok(diagnostics)
}

fn diagnostic(
    file: &SourceFile,
    misconfiguration: &Misconfiguration,
) -> Result<Diagnostic, String> {
    let level = match misconfiguration.severity.as_str() {
        "CRITICAL" | "HIGH" => LEVEL_ERROR,
        "MEDIUM" | "LOW" | "UNKNOWN" => LEVEL_WARNING,
        other => return Err(format!("trivy reported unknown severity {other:?}")),
    };
    let id = misconfiguration.id.trim();
    if id.is_empty() || id.contains(char::is_whitespace) {
        return Err(format!("trivy reported an unusable check ID {id:?}"));
    }
    Ok(trivy_diagnostic(
        level,
        format!("trivy::{id}"),
        message(misconfiguration),
        cause_location(file, &misconfiguration.cause),
    ))
}

/// From the start of `StartLine` to the end of `EndLine`'s text, or the
/// start of the file when trivy gave no usable line.
fn cause_location(file: &SourceFile, cause: &CauseMetadata) -> Location {
    let start_line = cause.start_line.unwrap_or_default();
    let end_line = cause.end_line.unwrap_or_default().max(start_line);
    let (Some(start), Some(end_start)) = (
        line_start(&file.text, start_line),
        line_start(&file.text, end_line),
    ) else {
        return Location::file_start(file.path.as_str(), &file.text);
    };
    let end = end_start.saturating_add(line_text(&file.text, end_line).len());
    Location::from_span(file.path.as_str(), &file.text, start, end)
}

/// `Title: Message. Resolution (PrimaryURL)` on one line, omitting the
/// parts trivy left empty.
fn message(misconfiguration: &Misconfiguration) -> String {
    let mut text = collapse_whitespace(&misconfiguration.title);
    let detail = collapse_whitespace(&misconfiguration.message);
    if !detail.is_empty() {
        if !text.is_empty() {
            // "Title.: Message" reads as a typo; the colon replaces the stop.
            text = text.trim_end_matches('.').to_owned();
            text.push_str(": ");
        }
        text.push_str(&detail);
    }
    let resolution = collapse_whitespace(&misconfiguration.resolution);
    if !resolution.is_empty() {
        if !text.is_empty() {
            if !text.ends_with('.') {
                text.push('.');
            }
            text.push(' ');
        }
        text.push_str(&resolution);
    }
    let url = collapse_whitespace(&misconfiguration.primary_url);
    if !url.is_empty() {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push('(');
        text.push_str(&url);
        text.push(')');
    }
    text
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

/// The configuration or variable file directly in the module at `path`.
fn module_file<'a>(sources: &'a ModuleSources, path: &str) -> Option<&'a SourceFile> {
    sources
        .configuration
        .iter()
        .chain(&sources.variable_files)
        .find(|file| file.path == path)
}
