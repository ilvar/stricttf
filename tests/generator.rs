//! `stricttf new`: the generated module is a public contract, and its
//! most important property is that it already passes the checker -- and
//! Terraform itself.

mod support;

use std::path::Path;
use stricttf::{template, Depth};

const NAME: &str = "demo-module";

fn generate(parent: &Path, name: &str) -> std::path::PathBuf {
    template::create_module(parent, name).expect("generation should succeed")
}

fn entries(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .expect("directory should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn a_generated_module_passes_its_own_checker_with_no_diagnostics_at_all() {
    let directory = support::empty_directory();
    let module = generate(directory.path(), NAME);

    let report =
        stricttf::run_check_with_depth(&module, Depth::SourceOnly).expect("check should run");

    assert!(report.ok, "generated module must be clean: {report:#?}");
    assert_eq!(
        report.warning_count, 0,
        "not even a warning: an agent starting here starts inside the subset: {report:#?}"
    );
}

#[test]
fn every_valid_name_renders_a_clean_module() {
    // The name is only ever substituted into strings and documentation,
    // so the shortest, the longest, and a digit-heavy name all render a
    // module the checker accepts unchanged.
    let longest = format!("m{}", "0".repeat(63));
    for name in ["a", "x9", "demo-module-2", longest.as_str()] {
        let directory = support::empty_directory();
        let module = generate(directory.path(), name);
        let report =
            stricttf::run_check_with_depth(&module, Depth::SourceOnly).expect("check should run");
        assert!(
            report.ok && report.warning_count == 0,
            "{name}: {report:#?}"
        );
    }
}

#[test]
fn every_declared_file_is_generated_and_nothing_else_is() {
    let directory = support::empty_directory();
    let module = generate(directory.path(), NAME);

    let mut written: Vec<String> = walkdir::WalkDir::new(&module)
        .sort_by_file_name()
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            entry
                .path()
                .strip_prefix(&module)
                .ok()
                .map(|path| path.to_string_lossy().replace('\\', "/"))
        })
        .collect();
    written.sort();

    let mut declared: Vec<String> = template::generated_paths()
        .into_iter()
        .map(str::to_owned)
        .collect();
    declared.sort();

    assert_eq!(written, declared);
}

#[test]
fn the_declared_file_list_is_exactly_the_documented_contract() {
    assert_eq!(
        template::generated_paths(),
        vec![
            ".github/workflows/ci.yml",
            ".gitignore",
            ".pre-commit-config.yaml",
            ".terraform-version",
            ".tflint.hcl",
            "AGENTS.md",
            "CLAUDE.md",
            "Makefile",
            "README.md",
            "scripts/check.sh",
            "versions.tf",
            "variables.tf",
            "main.tf",
            "outputs.tf",
            "tests/main.tftest.hcl",
        ]
    );
}

#[test]
fn the_module_name_is_substituted_everywhere_and_no_placeholder_survives() {
    let directory = support::empty_directory();
    let module = generate(directory.path(), NAME);

    for relative in template::generated_paths() {
        let contents = std::fs::read_to_string(module.join(relative))
            .expect("generated file should be readable");
        assert!(
            !contents.contains("__MODULE__") && !contents.contains("__STRICTTF_VERSION__"),
            "{relative} still contains an unsubstituted placeholder"
        );
    }

    let ci = std::fs::read_to_string(module.join(".github/workflows/ci.yml"))
        .expect("ci.yml is readable");
    assert!(
        ci.contains(&format!("--tag v{} ", env!("CARGO_PKG_VERSION"))),
        "generated CI must install the generating release: {ci}"
    );

    let readme = std::fs::read_to_string(module.join("README.md")).expect("README is readable");
    assert!(readme.starts_with("# demo-module\n"), "{readme}");
    let main = std::fs::read_to_string(module.join("main.tf")).expect("main.tf is readable");
    assert!(main.contains("module = \"demo-module\""), "{main}");
}

#[test]
fn the_terraform_version_is_pinned_in_step_with_ci() {
    let pinned = template::rendered_file(".terraform-version", NAME)
        .expect(".terraform-version is a generated file");
    assert_eq!(pinned, "1.16.5\n");

    let workflow =
        template::rendered_file(".github/workflows/ci.yml", NAME).expect("ci.yml is generated");
    assert!(
        workflow.contains(&format!("TERRAFORM_VERSION: {}", pinned.trim())),
        "CI must pin the same Terraform as .terraform-version"
    );
}

#[test]
fn the_generated_module_needs_no_provider_and_so_no_lock_file() {
    // The scaffold has to work offline: no required_providers, nothing
    // for `terraform init` to download, nothing for a lock file to pin.
    for relative in template::generated_paths() {
        if !relative.ends_with(".tf") {
            continue;
        }
        let contents = template::rendered_file(relative, NAME).expect("tf file has contents");
        for line in contents.lines().map(str::trim_start) {
            assert!(
                !line.starts_with("required_providers"),
                "{relative} declares a provider"
            );
            assert!(
                !line.starts_with("provider \""),
                "{relative} configures a provider"
            );
        }
    }
}

#[test]
fn generation_is_byte_for_byte_deterministic() {
    let first = support::empty_directory();
    let second = support::empty_directory();
    let one = generate(first.path(), NAME);
    let two = generate(second.path(), NAME);

    for relative in template::generated_paths() {
        assert_eq!(
            std::fs::read_to_string(one.join(relative)).expect("file should be readable"),
            std::fs::read_to_string(two.join(relative)).expect("file should be readable"),
            "{relative} differs between two generations"
        );
    }
}

#[test]
fn generated_files_match_their_rendered_source_of_truth() {
    let directory = support::empty_directory();
    let module = generate(directory.path(), NAME);

    for relative in template::generated_paths() {
        let expected = template::rendered_file(relative, NAME)
            .expect("every declared path has rendered contents");
        assert_eq!(
            std::fs::read_to_string(module.join(relative)).expect("file should be readable"),
            expected,
            "{relative} does not match its template"
        );
    }
    assert_eq!(template::rendered_file("not/generated.tf", NAME), None);
}

#[test]
fn generated_files_satisfy_the_hygiene_hooks_the_module_ships_with() {
    // The generated .pre-commit-config.yaml runs end-of-file-fixer,
    // trailing-whitespace, and mixed-line-ending. A module whose very
    // first `pre-commit run` rewrites the files it was just given is a bad
    // first impression and a confusing diff.
    for relative in template::generated_paths() {
        let contents = template::rendered_file(relative, NAME).expect("every path has contents");

        assert!(
            !contents.contains('\r'),
            "{relative} must use LF line endings"
        );
        assert!(
            contents.ends_with('\n'),
            "{relative} must end with a newline"
        );
        assert!(
            !contents.ends_with("\n\n"),
            "{relative} must end with exactly one newline"
        );
        for (index, line) in contents.lines().enumerate() {
            assert!(
                line.trim_end() == line,
                "{relative}:{} has trailing whitespace",
                index + 1
            );
        }
    }
}

#[test]
fn the_makefile_recipes_are_indented_with_tabs() {
    // make refuses space-indented recipes; an editor "fixing" the
    // template would break every target at once.
    let makefile = template::rendered_file("Makefile", NAME).expect("Makefile is generated");
    let recipe = makefile
        .lines()
        .find(|line| line.contains("stricttf check ."))
        .expect("the Makefile runs stricttf");
    assert!(recipe.starts_with('\t'), "{recipe:?}");
}

#[test]
fn the_check_script_runs_the_whole_gate_cheapest_first() {
    let script = template::rendered_file("scripts/check.sh", NAME).expect("check.sh is generated");
    let stages = [
        "stricttf check .",
        "terraform fmt -check -recursive",
        "terraform init -backend=false -input=false",
        "terraform validate",
        "terraform test",
        "tflint --init",
        "all checks passed",
    ];
    let positions: Vec<usize> = stages
        .iter()
        .map(|stage| {
            script
                .find(stage)
                .unwrap_or_else(|| panic!("check.sh must run {stage}"))
        })
        .collect();
    let mut sorted = positions.clone();
    sorted.sort_unstable();
    assert_eq!(positions, sorted, "stages must run in gate order");
    assert!(
        script.contains("tflint SKIPPED"),
        "a missing tflint is announced"
    );
}

#[test]
fn the_generated_check_script_is_executable() {
    let directory = support::empty_directory();
    let module = generate(directory.path(), NAME);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(module.join("scripts/check.sh"))
            .expect("script should exist")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o111,
            0o111,
            "a check script nobody can run is not a gate"
        );
    }
    #[cfg(not(unix))]
    assert!(module.join("scripts/check.sh").is_file());
}

#[test]
fn an_existing_destination_is_refused_without_being_touched() {
    let directory = support::empty_directory();
    let occupied = directory.path().join(NAME);
    std::fs::create_dir(&occupied).expect("directory should be created");
    std::fs::write(occupied.join("keep.txt"), "keep me").expect("file should be written");

    let error = template::create_module(directory.path(), NAME)
        .expect_err("an occupied destination must be refused");
    assert!(error.contains("destination already exists"), "{error}");
    assert_eq!(
        std::fs::read_to_string(occupied.join("keep.txt")).expect("file should be readable"),
        "keep me"
    );
    assert_eq!(entries(directory.path()), vec![NAME.to_owned()]);
}

#[test]
fn an_existing_staging_path_is_refused_without_being_touched() {
    let directory = support::empty_directory();
    let staging = directory.path().join(".demo-module.stricttf-tmp");
    std::fs::create_dir(&staging).expect("directory should be created");
    std::fs::write(staging.join("keep.txt"), "keep me").expect("file should be written");

    let error = template::create_module(directory.path(), NAME)
        .expect_err("an occupied staging path must be refused");
    assert!(error.contains("staging path already exists"), "{error}");
    assert_eq!(
        std::fs::read_to_string(staging.join("keep.txt")).expect("file should be readable"),
        "keep me"
    );
    assert!(!directory.path().join(NAME).exists());
}

#[test]
fn a_successful_generation_leaves_no_staging_directory_behind() {
    let directory = support::empty_directory();
    generate(directory.path(), NAME);

    assert_eq!(entries(directory.path()), vec![NAME.to_owned()]);
}

#[test]
fn an_invalid_name_creates_nothing_at_all() {
    let directory = support::empty_directory();
    template::create_module(directory.path(), "Bad_Name").expect_err("invalid name is refused");

    assert!(entries(directory.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn a_failed_generation_leaves_nothing_behind() {
    use std::os::unix::fs::PermissionsExt;

    let directory = support::empty_directory();
    let parent = directory.path().join("locked");
    std::fs::create_dir(&parent).expect("directory should be created");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555))
        .expect("permissions should be set");

    // Root ignores directory permissions, so the failure cannot be staged.
    let writable_anyway = std::fs::write(parent.join("probe"), "").is_ok();
    let result = template::create_module(&parent, NAME);
    let left_behind = entries(&parent);

    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
        .expect("permissions should be restored");

    if writable_anyway {
        eprintln!("SKIPPED: directory permissions are not enforced for this user");
        return;
    }
    let error = result.expect_err("an unwritable parent must fail generation");
    assert!(!error.is_empty());
    assert!(left_behind.is_empty(), "left behind: {left_behind:?}");
}

#[test]
fn invalid_module_names_are_refused_with_a_reason() {
    let too_long = "a".repeat(65);
    for (name, reason) in [
        ("", "empty"),
        ("Demo", "lowercase"),
        ("9lives", "lowercase"),
        ("-demo", "lowercase"),
        ("demo_module", "hyphens"),
        ("demo module", "hyphens"),
        ("demo.module", "hyphens"),
        ("démo", "hyphens"),
        ("demo-", "hyphen"),
        (too_long.as_str(), "limit"),
    ] {
        let error = template::validate_name(name).expect_err("name should be refused");
        assert!(
            error.contains(reason),
            "refusal of {name:?} should mention {reason}, said: {error}"
        );
    }
}

#[test]
fn valid_module_names_are_accepted() {
    let longest = "a".repeat(64);
    for name in [
        "a",
        "demo",
        "demo-module",
        "demo-module-2",
        "x9",
        longest.as_str(),
    ] {
        assert!(
            template::validate_name(name).is_ok(),
            "{name} should be accepted"
        );
    }
}

/// Run one Terraform command in `module`, failing with its full output.
fn terraform(module: &Path, data_dir: &Path, arguments: &[&str]) {
    let output = std::process::Command::new("terraform")
        .args(arguments)
        .current_dir(module)
        .env("TF_IN_AUTOMATION", "1")
        .env("TF_DATA_DIR", data_dir)
        .env("CHECKPOINT_DISABLE", "1")
        .output()
        .expect("terraform should run");
    assert!(
        output.status.success(),
        "terraform {} failed:\nstdout:\n{}\nstderr:\n{}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_generated_module_passes_terraform_fmt_init_validate_and_test() {
    let available = std::process::Command::new("terraform")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success());
    if !available {
        assert!(
            std::env::var("STRICTTF_REQUIRE_TERRAFORM").as_deref() != Ok("1"),
            "STRICTTF_REQUIRE_TERRAFORM=1 but no terraform binary is on PATH"
        );
        eprintln!(
            "SKIPPED: terraform is not on PATH; the generated module was not run through \
             fmt, init, validate, or test (set STRICTTF_REQUIRE_TERRAFORM=1 to make this fatal)"
        );
        return;
    }

    let directory = support::empty_directory();
    let module = generate(directory.path(), NAME);
    let data_dir = directory.path().join("terraform-data");

    terraform(
        &module,
        &data_dir,
        &["fmt", "-check", "-recursive", "-diff"],
    );
    terraform(
        &module,
        &data_dir,
        &["init", "-backend=false", "-input=false", "-no-color"],
    );
    terraform(&module, &data_dir, &["validate", "-no-color"]);
    terraform(&module, &data_dir, &["test", "-no-color"]);

    assert!(
        !module.join(".terraform.lock.hcl").exists(),
        "a provider-free module must not need a lock file"
    );
}
