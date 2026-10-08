//! Conservative mechanical fix application.
//!
//! Unlike a compiler, Terraform supplies no machine-applicable suggestions
//! beyond its formatter, so every fix here is either `terraform fmt`'s own
//! output or a `stricttf` rule's. That raises the bar rather than lowering
//! it: a fix is attached only when the replacement is span-exact,
//! unambiguous, and idempotent. Rules that would have to guess attach
//! nothing and leave the edit to the agent.

use crate::capability;
use crate::report::{EditSpan, Fix, Report};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// Apply every applicable fix in a report and return how many landed.
///
/// Edits are grouped per file, deduplicated, filtered to a
/// non-overlapping set, and applied back to front so earlier offsets stay
/// valid. A file is written only when at least one edit changed it.
pub fn apply(module_dir: &Path, report: &Report) -> Result<usize, String> {
    let mut by_file: BTreeMap<String, Vec<&Fix>> = BTreeMap::new();

    for diagnostic in &report.diagnostics {
        for fix in &diagnostic.fixes {
            let Some(edit) = fix.edit.as_ref() else {
                continue;
            };
            by_file.entry(edit.file.clone()).or_default().push(fix);
        }
    }

    let mut updates = Vec::new();
    let mut applied_total = 0usize;

    for (file, fixes) in by_file {
        let Some(path) = contained_path(module_dir, &file) else {
            continue; // never edit outside the module the caller named
        };
        let source = capability::read_to_string(&path)?;
        let mut updated = source.clone();

        let mut selected = select_non_overlapping(fixes);
        selected.sort_by_key(|fix| std::cmp::Reverse(byte_start(fix)));

        let mut applied_in_file = 0usize;
        for fix in selected {
            let Some(edit) = fix.edit.as_ref() else {
                continue;
            };
            validate(&updated, edit, &path)?;

            let Some(current) = updated.get(edit.byte_start..edit.byte_end) else {
                return Err(format!(
                    "invalid edit range {}..{} for {}",
                    edit.byte_start,
                    edit.byte_end,
                    path.display()
                ));
            };
            if current == fix.replace_with.as_str() {
                continue; // already applied; the fix is idempotent
            }

            updated.replace_range(edit.byte_start..edit.byte_end, &fix.replace_with);
            applied_in_file += 1;
        }

        if applied_in_file > 0 {
            applied_total += applied_in_file;
            updates.push((path, updated));
        }
    }

    for (path, content) in updates {
        capability::write(&path, &content)?;
    }

    Ok(applied_total)
}

fn byte_start(fix: &Fix) -> usize {
    fix.edit
        .as_ref()
        .map(|edit| edit.byte_start)
        .unwrap_or_default()
}

/// Keep the first deterministic candidate whenever two fixes would touch
/// the same bytes, and drop exact duplicates outright.
pub fn select_non_overlapping(fixes: Vec<&Fix>) -> Vec<&Fix> {
    let mut selected: Vec<&Fix> = Vec::new();

    for fix in fixes {
        let Some(edit) = fix.edit.as_ref() else {
            continue;
        };

        let duplicate = selected.iter().any(|existing| {
            existing
                .edit
                .as_ref()
                .is_some_and(|other| other == edit && existing.replace_with == fix.replace_with)
        });
        if duplicate {
            continue;
        }

        let overlaps = selected.iter().any(|existing| {
            existing.edit.as_ref().is_some_and(|other| {
                ranges_overlap(
                    edit.byte_start,
                    edit.byte_end,
                    other.byte_start,
                    other.byte_end,
                )
            })
        });
        if !overlaps {
            selected.push(fix);
        }
    }

    selected
}

/// Whether two byte ranges intersect, treating a zero-width insertion as
/// overlapping only when it falls strictly inside another range.
pub fn ranges_overlap(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    if left_start == left_end && right_start == right_end {
        return left_start == right_start;
    }
    if left_start == left_end {
        return left_start > right_start && left_start < right_end;
    }
    if right_start == right_end {
        return right_start > left_start && right_start < left_end;
    }
    left_start < right_end && right_start < left_end
}

fn validate(source: &str, edit: &EditSpan, path: &Path) -> Result<(), String> {
    if edit.byte_start > edit.byte_end || edit.byte_end > source.len() {
        return Err(format!(
            "edit range {}..{} is outside {}",
            edit.byte_start,
            edit.byte_end,
            path.display()
        ));
    }
    if !source.is_char_boundary(edit.byte_start) || !source.is_char_boundary(edit.byte_end) {
        return Err(format!(
            "edit range {}..{} splits UTF-8 in {}",
            edit.byte_start,
            edit.byte_end,
            path.display()
        ));
    }
    Ok(())
}

/// Resolve a module-relative path, refusing anything that could escape the
/// module directory.
pub fn contained_path(module_dir: &Path, file: &str) -> Option<PathBuf> {
    let relative = Path::new(file);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return None;
    }
    Some(module_dir.join(relative))
}
