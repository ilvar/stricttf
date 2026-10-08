//! Deterministic module generation.
//!
//! `stricttf new` produces a module that already passes `stricttf check`,
//! `terraform validate`, and `terraform test`. That is the point: an agent
//! starting from this scaffold begins inside the strict subset instead of
//! being told, one diagnostic at a time, how far outside it a hand-written
//! first draft lands.
//!
//! The module is provider-free -- it is built on the builtin
//! `terraform_data` resource -- so the whole generated gate runs offline
//! and needs no lock file.
//!
//! Generation is atomic. Every file is written into a staging directory
//! and the whole tree is renamed into place only after the last write
//! succeeds, so a failure never leaves a half-generated module behind.

use crate::capability;
use std::path::{Path, PathBuf};

/// Substituted with the module name when a template is rendered.
///
/// The name only ever lands inside strings, documentation, and CI
/// configuration, never in an HCL identifier, so every valid name renders
/// a valid module.
const MODULE_PLACEHOLDER: &str = "__MODULE__";

/// Substituted with the version of the `stricttf` that generated the
/// module, so its CI installs exactly that release instead of whatever the
/// default branch holds on the day it runs -- the same pinning discipline
/// `stricttf::module_ref_missing` imposes on module sources.
const VERSION_PLACEHOLDER: &str = "__STRICTTF_VERSION__";

/// The longest accepted module name. Long enough for any descriptive
/// repository name, short enough to stay a usable tag value and directory.
const MAX_NAME_LENGTH: usize = 64;

/// Every generated file, as `(relative path, contents, executable)`.
///
/// The list is ordered and exhaustive: it is the generated-module contract,
/// and a golden test compares the whole tree against it.
const FILES: &[(&str, &str, bool)] = &[
    (
        ".github/workflows/ci.yml",
        include_str!("../templates/module/ci.yml"),
        false,
    ),
    (
        ".gitignore",
        include_str!("../templates/module/gitignore"),
        false,
    ),
    (
        ".pre-commit-config.yaml",
        include_str!("../templates/module/pre-commit-config.yaml"),
        false,
    ),
    (
        ".terraform-version",
        include_str!("../templates/module/terraform-version"),
        false,
    ),
    (
        ".tflint.hcl",
        include_str!("../templates/module/tflint.hcl"),
        false,
    ),
    (
        "AGENTS.md",
        include_str!("../templates/module/AGENTS.md"),
        false,
    ),
    (
        "CLAUDE.md",
        include_str!("../templates/module/CLAUDE.md"),
        false,
    ),
    (
        "Makefile",
        include_str!("../templates/module/Makefile"),
        false,
    ),
    (
        "README.md",
        include_str!("../templates/module/README.md"),
        false,
    ),
    (
        "scripts/check.sh",
        include_str!("../templates/module/check.sh"),
        true,
    ),
    (
        "versions.tf",
        include_str!("../templates/module/versions.tf"),
        false,
    ),
    (
        "variables.tf",
        include_str!("../templates/module/variables.tf"),
        false,
    ),
    (
        "main.tf",
        include_str!("../templates/module/main.tf"),
        false,
    ),
    (
        "outputs.tf",
        include_str!("../templates/module/outputs.tf"),
        false,
    ),
    (
        "tests/main.tftest.hcl",
        include_str!("../templates/module/main.tftest.hcl"),
        false,
    ),
];

/// The relative paths `create_module` writes, in generation order.
pub fn generated_paths() -> Vec<&'static str> {
    FILES
        .iter()
        .map(|(path, _text, _executable)| *path)
        .collect()
}

/// The rendered contents of one generated file, for golden tests.
pub fn rendered_file(path: &str, name: &str) -> Option<String> {
    FILES
        .iter()
        .find(|(candidate, _text, _executable)| *candidate == path)
        .map(|(_path, text, _executable)| render(text, name))
}

/// Create a module named `name` under `parent`.
pub fn create_module(parent: &Path, name: &str) -> Result<PathBuf, String> {
    validate_name(name)?;

    let destination = parent.join(name);
    if capability::exists(&destination) {
        return Err(format!(
            "destination already exists: {}",
            destination.display()
        ));
    }

    let staging = parent.join(format!(".{name}.stricttf-tmp"));
    if capability::exists(&staging) {
        return Err(format!(
            "staging path already exists: {}",
            staging.display()
        ));
    }

    capability::create_dir_all(&staging)?;

    if let Err(error) = write_module(&staging, name) {
        return Err(discard_staging(&staging, error));
    }

    if let Err(error) = capability::rename(&staging, &destination) {
        return Err(discard_staging(&staging, error));
    }

    Ok(destination)
}

/// Remove a failed staging tree, keeping the original error as the one
/// reported and appending a cleanup failure so it is never silently lost.
fn discard_staging(staging: &Path, error: String) -> String {
    match capability::remove_dir_all(staging) {
        Ok(()) => error,
        Err(cleanup) => format!("{error}; additionally failed to remove staging path: {cleanup}"),
    }
}

fn write_module(staging: &Path, name: &str) -> Result<(), String> {
    for (relative, text, executable) in FILES {
        let path = staging.join(relative);
        let parent = path
            .parent()
            .ok_or_else(|| format!("invalid generated path: {relative}"))?;
        capability::create_dir_all(parent)?;
        capability::write(&path, &render(text, name))?;
        if *executable {
            capability::set_executable(&path)?;
        }
    }

    Ok(())
}

fn render(text: &str, name: &str) -> String {
    text.replace(MODULE_PLACEHOLDER, name)
        .replace(VERSION_PLACEHOLDER, env!("CARGO_PKG_VERSION"))
}

/// Reject a name that would make a poor module directory or repository.
///
/// The name becomes the directory, the README title, the CI concurrency
/// group, and a default tag value, so it is held to the conservative
/// intersection of what all of those accept.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("module name cannot be empty".to_owned());
    }
    if name.len() > MAX_NAME_LENGTH {
        return Err(format!(
            "module name is {} characters; the limit is {MAX_NAME_LENGTH}",
            name.len()
        ));
    }

    let starts_with_letter = name
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_lowercase());
    if !starts_with_letter {
        return Err("module name must start with a lowercase ASCII letter".to_owned());
    }
    if name.ends_with('-') {
        return Err("module name cannot end with a hyphen".to_owned());
    }

    let invalid = name.chars().find(|character| {
        !character.is_ascii_lowercase() && !character.is_ascii_digit() && *character != '-'
    });
    if let Some(character) = invalid {
        return Err(format!(
            "module name contains {character:?}; use lowercase letters, digits, and hyphens"
        ));
    }

    Ok(())
}
