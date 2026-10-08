//! `stricttf` turns a Terraform module into a deterministic,
//! machine-readable oracle for LLM code generation.
//!
//! A check runs four layers in increasing order of cost, and every layer
//! reports everything it finds rather than stopping at the first defect:
//!
//! 1. **module structure** -- syntax, version constraints, provider
//!    requirements, and variable files;
//! 2. **configuration source** -- variables, outputs, module calls, and
//!    expressions that Terraform accepts but a strict profile does not;
//! 3. **resource policy** -- security defects in resource arguments that
//!    are decidable from the configuration alone;
//! 4. **terraform** -- `fmt`, `init`, and `validate`, with Terraform as
//!    the authority.
//!
//! Layer 4 is skipped when layer 1 proves the configuration cannot be
//! parsed, because Terraform's error for a file that is not HCL tells an
//! agent strictly less than the located syntax diagnostic already does.

pub mod capability;
pub mod fixes;
pub mod hcl;
pub mod report;
pub mod resources;
pub mod skills;
pub mod source;
pub mod template;
pub mod tfcli;
pub mod trivy;

use crate::hcl::{ParsedFile, SourceFile};
use crate::report::{Diagnostic, Location, Report, LEVEL_ERROR};
use std::path::Path;

/// Fix passes attempted before the loop gives up.
pub const DEFAULT_MAX_FIX_ITERATIONS: usize = 10;

/// The dependency lock file Terraform writes beside a root module.
pub const LOCK_FILE: &str = ".terraform.lock.hcl";

/// The directory `terraform test` reads test files from.
pub const TESTS_DIR: &str = "tests";

/// Which layers a check should run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    /// Every layer, including `terraform fmt`, `init`, and `validate`.
    Full,
    /// Only the layers that need no Terraform binary. Useful in a sandbox,
    /// and deliberately explicit so a check never silently loses its
    /// oracle.
    SourceOnly,
}

/// Everything read from a module directory, kept separate from the rules
/// so the whole rule set can be exercised without a filesystem.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleSources {
    /// `*.tf` files directly inside the module, in path order.
    pub configuration: Vec<SourceFile>,
    /// `*.tfvars` files directly inside the module, in path order.
    pub variable_files: Vec<SourceFile>,
    /// `tests/*.tftest.hcl` files, in path order.
    pub test_files: Vec<SourceFile>,
    /// `.terraform.lock.hcl` beside the configuration, when it exists.
    pub lock_file: Option<SourceFile>,
}

/// The parsed module the rule layers inspect. Files that failed to parse
/// are absent here; their syntax errors are reported separately.
#[derive(Debug, Clone)]
pub struct Module {
    pub configuration: Vec<ParsedFile>,
    pub variable_files: Vec<ParsedFile>,
    /// Whether `.terraform.lock.hcl` exists, whether or not it parsed.
    pub has_lock_file: bool,
    /// The parsed lock file, when it exists and is valid HCL.
    pub lock_file: Option<ParsedFile>,
    /// Whether every `.tf` file parsed. When one did not, a module-wide
    /// conclusion that something is absent or unused could be false --
    /// the missing declaration or reference may be in the broken file --
    /// so rules drawing such conclusions stay silent.
    pub complete: bool,
}

/// Check a module directory, running every layer.
pub fn run_check(module_dir: &Path) -> Result<Report, String> {
    run_check_with_depth(module_dir, Depth::Full)
}

/// Check a module directory at the requested depth.
pub fn run_check_with_depth(module_dir: &Path, depth: Depth) -> Result<Report, String> {
    if !capability::is_dir(module_dir) {
        return Err(format!("{} is not a directory", module_dir.display()));
    }
    let binary = match depth {
        Depth::SourceOnly => None,
        Depth::Full => Some(tfcli::binary().ok_or_else(|| {
            "neither terraform nor tofu was found on PATH; install one, or run with --source-only to check just the layers that do not need it"
                .to_owned()
        })?),
    };

    let sources = read_module(module_dir)?;
    let (mut diagnostics, checkable) = check_sources(&sources);

    if let (true, Some(binary)) = (checkable, binary) {
        diagnostics.extend(tfcli::check(module_dir, binary, &sources)?);
        diagnostics.extend(trivy::check(module_dir, &sources)?);
        diagnostics = supersede_with_trivy(diagnostics);
    }

    Ok(Report::build(diagnostics))
}

/// Resource-policy rules that trivy's embedded checks duplicate exactly,
/// paired with the trivy check that supersedes each. Ours exist so the
/// defect is still caught without trivy; with trivy, one defect must not
/// produce two diagnostics. `tests/trivy_live.rs` pins every pair against
/// the pinned trivy, so an upgrade that renames or drops a check fails CI
/// rather than silently losing coverage.
pub const TRIVY_SUPERSEDES: &[(&str, &str)] = &[
    ("stricttf::open_admin_ingress", "trivy::AWS-0107"),
    ("stricttf::public_bucket_acl", "trivy::AWS-0092"),
    ("stricttf::public_database", "trivy::AWS-0180"),
];

/// Drop each superseded `stricttf` finding that its trivy counterpart
/// reports in the same file over a span containing the finding's line.
/// A finding trivy missed -- a different location, a narrower check -- is
/// kept, so the rule never loses coverage by being superseded.
pub fn supersede_with_trivy(diagnostics: Vec<Diagnostic>) -> Vec<Diagnostic> {
    let covered = |diagnostic: &Diagnostic| {
        TRIVY_SUPERSEDES
            .iter()
            .filter(|(ours, _theirs)| *ours == diagnostic.code)
            .any(|(_ours, theirs)| {
                diagnostics.iter().any(|candidate| {
                    candidate.code == *theirs
                        && candidate.at.file == diagnostic.at.file
                        && candidate.at.line <= diagnostic.at.line
                        && diagnostic.at.line <= candidate.at.end_line
                })
            })
    };
    let keep: Vec<bool> = diagnostics.iter().map(|d| !covered(d)).collect();
    diagnostics
        .into_iter()
        .zip(keep)
        .filter_map(|(diagnostic, keep)| keep.then_some(diagnostic))
        .collect()
}

/// Run every layer that needs no Terraform binary.
///
/// Returns the diagnostics and whether the configuration is sound enough
/// for the Terraform layer to add information.
pub fn check_sources(sources: &ModuleSources) -> (Vec<Diagnostic>, bool) {
    let mut diagnostics = Vec::new();

    if sources.configuration.is_empty() {
        diagnostics.push(Diagnostic::rule(
            LEVEL_ERROR,
            "stricttf::no_configuration",
            "no .tf files were found in this directory; point stricttf at a Terraform module root",
            Location::whole_line(".", 1, ""),
        ));
        return (diagnostics, false);
    }

    let configuration = parse_all(&sources.configuration, &mut diagnostics);
    let parsable = configuration.len() == sources.configuration.len();
    let variable_files = parse_all(&sources.variable_files, &mut diagnostics);
    let _tests = parse_all(&sources.test_files, &mut diagnostics);
    let lock_file = parse_all(sources.lock_file.as_slice(), &mut diagnostics)
        .into_iter()
        .next();

    let module = Module {
        configuration,
        variable_files,
        has_lock_file: sources.lock_file.is_some(),
        lock_file,
        complete: parsable,
    };
    diagnostics.extend(source::check(&module));
    diagnostics.extend(resources::check(&module));

    (diagnostics, parsable)
}

fn parse_all(files: &[SourceFile], diagnostics: &mut Vec<Diagnostic>) -> Vec<ParsedFile> {
    let mut parsed = Vec::new();
    for file in files {
        match hcl::parse(file) {
            Ok(file) => parsed.push(file),
            Err(diagnostic) => diagnostics.push(*diagnostic),
        }
    }
    parsed
}

/// The file `name` directly in `directory`, if it exists.
fn read_optional(directory: &Path, name: &str) -> Result<Option<SourceFile>, String> {
    let path = directory.join(name);
    if !capability::is_file(&path) {
        return Ok(None);
    }
    Ok(Some(SourceFile {
        path: name.to_owned(),
        text: capability::read_to_string(&path)?,
    }))
}

/// Check, apply mechanical fixes, and re-check until the loop stops.
pub fn run_fix(module_dir: &Path) -> Result<Report, String> {
    run_fix_with_limit(module_dir, Depth::Full, DEFAULT_MAX_FIX_ITERATIONS)
}

/// The fix loop with an explicit depth and iteration cap.
///
/// The loop terminates on any of four conditions, so it can neither spin
/// nor thrash: the report is clean, no applicable fix remains, a pass
/// changed nothing observable, or the cap is reached.
pub fn run_fix_with_limit(
    module_dir: &Path,
    depth: Depth,
    max_iterations: usize,
) -> Result<Report, String> {
    let mut report = run_check_with_depth(module_dir, depth)?;

    for _pass in 0..max_iterations {
        if report.ok {
            break;
        }

        let applied = fixes::apply(module_dir, &report)?;
        if applied == 0 {
            break;
        }

        let next = run_check_with_depth(module_dir, depth)?;
        let made_progress = next != report;
        report = next;
        if !made_progress {
            break;
        }
    }

    Ok(report)
}

/// Read every file a check depends on from a module directory.
pub fn read_module(module_dir: &Path) -> Result<ModuleSources, String> {
    let configuration = read_matching(module_dir, "", |name| name.ends_with(".tf"))?;
    let variable_files = read_matching(module_dir, "", |name| name.ends_with(".tfvars"))?;

    let tests_dir = module_dir.join(TESTS_DIR);
    let test_files = if capability::is_dir(&tests_dir) {
        read_matching(&tests_dir, TESTS_DIR, |name| name.ends_with(".tftest.hcl"))?
    } else {
        Vec::new()
    };

    Ok(ModuleSources {
        configuration,
        variable_files,
        test_files,
        lock_file: read_optional(module_dir, LOCK_FILE)?,
    })
}

/// Every file directly in `directory` whose name satisfies `wanted`,
/// addressed as `prefix/name` (or bare `name` without a prefix).
fn read_matching(
    directory: &Path,
    prefix: &str,
    wanted: impl Fn(&str) -> bool,
) -> Result<Vec<SourceFile>, String> {
    let mut files = Vec::new();
    for path in capability::list_files(directory)? {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue; // a non-UTF-8 name cannot be a Terraform file
        };
        if !wanted(name) {
            continue;
        }
        let relative = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        files.push(SourceFile {
            path: relative,
            text: capability::read_to_string(&path)?,
        });
    }
    Ok(files)
}
