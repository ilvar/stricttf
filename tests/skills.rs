//! Skill installation. Every test runs the binary in a subprocess with an
//! isolated fake home, so the suite can never write into the real one.

mod support;

use std::path::Path;
use std::process::Output;

const SKILL: &str = include_str!("../skills/stricttf/SKILL.md");

fn run(home: &Path) -> Output {
    std::process::Command::new(support::binary())
        .arg("install-skills")
        .env("HOME", home)
        .env("PATH", "")
        .output()
        .expect("stricttf binary should run")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_clean_report(output: &Output) {
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should carry the JSON contract");
    assert_eq!(
        report.get("ok").and_then(serde_json::Value::as_bool),
        Some(true)
    );
}

#[test]
fn detected_agents_get_the_skill_and_reinstalling_is_a_no_op() {
    let home = support::empty_directory();
    std::fs::create_dir(home.path().join(".codex")).expect("Codex marker should be created");
    std::fs::create_dir(home.path().join(".claude")).expect("Claude marker should be created");

    let first = run(home.path());
    assert!(first.status.success(), "{}", stderr(&first));
    assert_clean_report(&first);

    let codex = home.path().join(".agents/skills/stricttf/SKILL.md");
    let claude = home.path().join(".claude/skills/stricttf/SKILL.md");
    assert_eq!(
        std::fs::read_to_string(&codex).expect("Codex skill should exist"),
        SKILL
    );
    assert_eq!(
        std::fs::read_to_string(&claude).expect("Claude skill should exist"),
        SKILL
    );

    let second = run(home.path());
    assert!(second.status.success(), "{}", stderr(&second));
    assert_clean_report(&second);
    assert!(stderr(&second).contains("already current"));
    assert_eq!(
        std::fs::read_to_string(codex).expect("skill should remain"),
        SKILL
    );
    assert_eq!(
        std::fs::read_to_string(claude).expect("skill should remain"),
        SKILL
    );
}

#[test]
fn only_detected_agents_are_installed_for() {
    let home = support::empty_directory();
    std::fs::create_dir(home.path().join(".claude")).expect("Claude marker should be created");

    let output = run(home.path());
    assert!(output.status.success(), "{}", stderr(&output));

    assert!(home
        .path()
        .join(".claude/skills/stricttf/SKILL.md")
        .is_file());
    assert!(
        !home.path().join(".agents").exists(),
        "an agent that is not present must not have directories created for it"
    );
}

#[test]
fn either_codex_marker_directory_is_enough_to_detect_it() {
    for marker in [".codex", ".agents"] {
        let home = support::empty_directory();
        std::fs::create_dir(home.path().join(marker)).expect("marker should be created");

        let paths = stricttf::skills::detected_target_paths(home.path());
        assert!(
            paths
                .iter()
                .any(|path| path.ends_with(".agents/skills/stricttf/SKILL.md")),
            "{marker} should detect Codex"
        );
    }
}

#[test]
fn a_modified_skill_is_never_overwritten() {
    let home = support::empty_directory();
    std::fs::create_dir(home.path().join(".codex")).expect("Codex marker should be created");

    let destination = home.path().join(".agents/skills/stricttf/SKILL.md");
    std::fs::create_dir_all(destination.parent().expect("skill has a parent"))
        .expect("skill directory should be created");
    std::fs::write(&destination, "my customisation\n").expect("custom skill should be written");

    let output = run(home.path());
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).contains("refusing to overwrite"));
    assert_eq!(
        std::fs::read_to_string(destination).expect("custom skill should remain"),
        "my customisation\n"
    );
}

#[test]
fn one_modified_target_blocks_the_other_before_anything_is_written() {
    // Preflight is what makes this safe: a refusal must not leave a
    // half-finished installation behind.
    let home = support::empty_directory();
    std::fs::create_dir(home.path().join(".codex")).expect("Codex marker should be created");
    std::fs::create_dir(home.path().join(".claude")).expect("Claude marker should be created");

    let codex = home.path().join(".agents/skills/stricttf/SKILL.md");
    std::fs::create_dir_all(codex.parent().expect("skill has a parent"))
        .expect("skill directory should be created");
    std::fs::write(&codex, "custom\n").expect("custom skill should be written");

    let output = run(home.path());
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !home
            .path()
            .join(".claude/skills/stricttf/SKILL.md")
            .exists(),
        "no target may be written when any target is refused"
    );
}

#[test]
fn no_detected_agent_is_an_operational_failure() {
    let home = support::empty_directory();
    let output = run(home.path());

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).contains("no supported agent installation detected"));
}

#[test]
fn the_bundled_skill_carries_portable_frontmatter_and_points_at_the_manual() {
    let skill = stricttf::skills::bundled_skill();

    assert!(
        skill.starts_with("---\n"),
        "portable Agent Skills need frontmatter"
    );
    assert!(skill.contains("\nname: stricttf\n"));
    assert!(skill.contains("\ndescription: "));
    assert!(
        skill.contains("stricttf --help"),
        "the skill must defer to the manual as the current source of truth"
    );
    assert_eq!(skill, SKILL);
}

#[test]
fn the_bundled_skill_states_the_exit_code_contract_and_the_no_invention_rule() {
    // The skill is prose and wraps at a column, so assert against the
    // text with its line breaks collapsed rather than pinning a layout.
    let skill = stricttf::skills::bundled_skill()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");

    assert!(skill.contains("Never invent a fix"));
    assert!(skill.contains("Match on `code`, never on message text"));
    assert!(skill.contains("Never read `2` as a clean module."));
    assert!(skill.contains("`2` means the check did not complete"));
}
