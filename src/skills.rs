//! Portable agent-skill installation.
//!
//! `cargo install` must never touch a user's home directory, so skill
//! installation is an explicit command. It installs only for agents that
//! are actually present, preflights every destination before writing any
//! of them, and rolls back what it created if a later write fails.

use crate::capability;
use std::path::{Path, PathBuf};

const SKILL_CONTENT: &str = include_str!("../skills/stricttf/SKILL.md");

struct Target {
    agent: &'static str,
    path: PathBuf,
}

/// Install the bundled skill for every detected agent.
///
/// Returns one human-readable notice per target, for stderr. An identical
/// existing file is accepted so the command is idempotent; a modified one
/// is refused so a user's customisation is never silently destroyed.
pub fn install_detected() -> Result<Vec<String>, String> {
    let home = capability::home_directory()
        .ok_or_else(|| "cannot determine the user home directory".to_owned())?;
    let targets = detected_targets(&home);

    if targets.is_empty() {
        return Err(
            "no supported agent installation detected; start Codex or Claude Code once, then rerun `stricttf install-skills`"
                .to_owned(),
        );
    }

    preflight(&targets)?;

    let mut created: Vec<PathBuf> = Vec::new();
    let mut messages = Vec::new();

    for target in targets {
        if capability::is_file(&target.path) {
            messages.push(format!(
                "{} skill is already current: {}",
                target.agent,
                target.path.display()
            ));
            continue;
        }

        if let Err(error) = write_skill(&target.path) {
            for path in &created {
                let _ = capability::remove_file(path);
            }
            return Err(error);
        }

        created.push(target.path.clone());
        messages.push(format!(
            "installed {} skill: {}",
            target.agent,
            target.path.display()
        ));
    }

    Ok(messages)
}

/// The skill destinations for agents detected under `home`.
///
/// Exposed so tests can assert detection against an isolated fake home
/// without writing anything.
pub fn detected_target_paths(home: &Path) -> Vec<PathBuf> {
    detected_targets(home)
        .into_iter()
        .map(|target| target.path)
        .collect()
}

fn detected_targets(home: &Path) -> Vec<Target> {
    let mut targets = Vec::new();

    if capability::is_dir(&home.join(".codex"))
        || capability::is_dir(&home.join(".agents"))
        || capability::executable_on_path("codex")
    {
        targets.push(Target {
            agent: "Codex",
            path: home
                .join(".agents")
                .join("skills")
                .join("stricttf")
                .join("SKILL.md"),
        });
    }

    if capability::is_dir(&home.join(".claude")) || capability::executable_on_path("claude") {
        targets.push(Target {
            agent: "Claude Code",
            path: home
                .join(".claude")
                .join("skills")
                .join("stricttf")
                .join("SKILL.md"),
        });
    }

    targets
}

fn preflight(targets: &[Target]) -> Result<(), String> {
    for target in targets {
        if !capability::exists(&target.path) {
            continue;
        }

        let existing = capability::read_to_string(&target.path)?;
        if existing != SKILL_CONTENT {
            return Err(format!(
                "refusing to overwrite a modified {} skill at {}; remove it explicitly and rerun the command",
                target.agent,
                target.path.display()
            ));
        }
    }

    Ok(())
}

fn write_skill(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("invalid skill destination: {}", path.display()))?;

    capability::create_dir_all(parent)?;
    capability::write_new(path, SKILL_CONTENT)
}

/// The bundled skill text, for regression tests over its contract.
pub fn bundled_skill() -> &'static str {
    SKILL_CONTENT
}
