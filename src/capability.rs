//! Every filesystem and process effect in `stricttf` lives here.
//!
//! Keeping side effects behind one narrow, explicitly marked boundary is
//! the same discipline `stricttf` enforces on the modules it checks, and
//! it is what makes the rest of the crate pure and exhaustively testable
//! without touching a disk or spawning a binary.

use std::path::{Path, PathBuf};

/// The captured result of running an external tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    pub status: Option<i32>,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// One external-tool invocation. Environment entries are added to the
/// inherited environment; `stdin`, when present, is written in full and
/// then closed.
#[derive(Debug, Clone, Copy)]
pub struct Invocation<'a> {
    pub program: &'a str,
    pub arguments: &'a [String],
    pub working_dir: &'a Path,
    pub environment: &'a [(String, String)],
    pub stdin: Option<&'a str>,
}

// strictrs: capability
mod effects {
    use std::fs;
    use std::io::ErrorKind;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    pub fn read_to_string(path: &Path) -> Result<String, String> {
        fs::read_to_string(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))
    }

    pub fn write(path: &Path, contents: &str) -> Result<(), String> {
        fs::write(path, contents)
            .map_err(|error| format!("failed to write {}: {error}", path.display()))
    }

    pub fn create_dir_all(path: &Path) -> Result<(), String> {
        fs::create_dir_all(path)
            .map_err(|error| format!("failed to create {}: {error}", path.display()))
    }

    pub fn rename(from: &Path, to: &Path) -> Result<(), String> {
        fs::rename(from, to).map_err(|error| {
            format!(
                "failed to move {} to {}: {error}",
                from.display(),
                to.display()
            )
        })
    }

    pub fn remove_dir_all(path: &Path) -> Result<(), String> {
        match fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("failed to remove {}: {error}", path.display())),
        }
    }

    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    pub fn is_file(path: &Path) -> bool {
        path.is_file()
    }

    pub fn remove_file(path: &Path) -> Result<(), String> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("failed to remove {}: {error}", path.display())),
        }
    }

    /// Create a file that must not already exist, so two installations
    /// racing on the same path cannot silently clobber each other.
    pub fn write_new(path: &Path, contents: &str) -> Result<(), String> {
        use std::io::Write;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| format!("failed to create {}: {error}", path.display()))?;

        if let Err(error) = file.write_all(contents.as_bytes()) {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(format!("failed to write {}: {error}", path.display()));
        }
        Ok(())
    }

    pub fn is_dir(path: &Path) -> bool {
        path.is_dir()
    }

    #[cfg(unix)]
    pub fn is_executable(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;

        fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o111 == 0o111)
    }

    /// Without an execute bit to inspect, the closest honest answer is
    /// whether the path is a file at all.
    #[cfg(not(unix))]
    pub fn is_executable(path: &Path) -> bool {
        path.is_file()
    }

    pub fn set_executable(path: &Path) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(0o755);
            fs::set_permissions(path, permissions)
                .map_err(|error| format!("failed to chmod {}: {error}", path.display()))
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(())
        }
    }

    /// A directory under the system temp root that persists between runs.
    ///
    /// Terraform's working data (`.terraform`) is kept here, keyed by
    /// module, so a check never writes into the module it inspects and a
    /// re-check does not download every provider again.
    pub fn cache_dir(key: &str) -> Result<PathBuf, String> {
        let path = std::env::temp_dir().join("stricttf").join(key);
        fs::create_dir_all(&path)
            .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
        Ok(path)
    }

    pub fn canonicalize(path: &Path) -> Result<PathBuf, String> {
        fs::canonicalize(path)
            .map_err(|error| format!("failed to resolve {}: {error}", path.display()))
    }

    pub fn home_directory() -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }

    pub fn path_entries() -> Vec<PathBuf> {
        std::env::var_os("PATH")
            .map(|value| std::env::split_paths(&value).collect())
            .unwrap_or_default()
    }

    pub fn run(invocation: &super::Invocation<'_>) -> Result<super::ToolOutput, String> {
        use std::io::Write;
        use std::process::Stdio;

        let program = invocation.program;
        let mut command = Command::new(program);
        command
            .args(invocation.arguments)
            .current_dir(invocation.working_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(if invocation.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        for (key, value) in invocation.environment {
            command.env(key, value);
        }

        let mut child = command
            .spawn()
            .map_err(|error| format!("failed to execute {program}: {error}"))?;

        // Feed stdin from a thread so a tool that writes before it has
        // read everything can never deadlock against a full pipe.
        let feeder = match (invocation.stdin, child.stdin.take()) {
            (Some(input), Some(mut pipe)) => {
                let input = input.to_owned();
                Some(std::thread::spawn(move || pipe.write_all(input.as_bytes())))
            }
            _other => None,
        };

        let output = child
            .wait_with_output()
            .map_err(|error| format!("failed to wait for {program}: {error}"))?;
        if let Some(feeder) = feeder {
            match feeder.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    return Err(format!("failed to write stdin of {program}: {error}"))
                }
                Err(_panic) => return Err(format!("stdin writer for {program} panicked")),
            }
        }

        Ok(super::ToolOutput {
            status: output.status.code(),
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Read a UTF-8 file, reporting the path in any error.
pub fn read_to_string(path: &Path) -> Result<String, String> {
    effects::read_to_string(path)
}

/// Write a UTF-8 file, creating no parent directories implicitly.
pub fn write(path: &Path, contents: &str) -> Result<(), String> {
    effects::write(path, contents)
}

/// Create a directory and every missing ancestor.
pub fn create_dir_all(path: &Path) -> Result<(), String> {
    effects::create_dir_all(path)
}

/// Move a path, used to publish a fully staged project atomically.
pub fn rename(from: &Path, to: &Path) -> Result<(), String> {
    effects::rename(from, to)
}

/// Remove a directory tree, treating an absent path as success.
pub fn remove_dir_all(path: &Path) -> Result<(), String> {
    effects::remove_dir_all(path)
}

/// Whether a path exists.
pub fn exists(path: &Path) -> bool {
    effects::exists(path)
}

/// Whether a path is a directory.
pub fn is_dir(path: &Path) -> bool {
    effects::is_dir(path)
}

/// Whether a path is a regular file.
pub fn is_file(path: &Path) -> bool {
    effects::is_file(path)
}

/// Remove a file, treating an absent path as success.
pub fn remove_file(path: &Path) -> Result<(), String> {
    effects::remove_file(path)
}

/// Create a file, failing if it already exists.
pub fn write_new(path: &Path, contents: &str) -> Result<(), String> {
    effects::write_new(path, contents)
}

/// Mark a generated script executable on Unix; a no-op elsewhere.
pub fn set_executable(path: &Path) -> Result<(), String> {
    effects::set_executable(path)
}

/// Whether every class may execute a path. On non-Unix targets, where
/// there is no execute bit, this reports whether the path is a file.
pub fn is_executable(path: &Path) -> bool {
    effects::is_executable(path)
}

/// The current user's home directory, if `HOME` is set.
pub fn home_directory() -> Option<PathBuf> {
    effects::home_directory()
}

/// A persistent cache directory outside the module, created on demand.
pub fn cache_dir(key: &str) -> Result<PathBuf, String> {
    effects::cache_dir(key)
}

/// Resolve a path to its absolute, symlink-free form.
pub fn canonicalize(path: &Path) -> Result<PathBuf, String> {
    effects::canonicalize(path)
}

/// Whether an executable of this name is present on `PATH`.
pub fn executable_on_path(name: &str) -> bool {
    effects::path_entries()
        .into_iter()
        .any(|entry| effects::is_file(&entry.join(name)))
}

/// Run an external tool with no stdin and no extra environment.
pub fn run(program: &str, arguments: &[String], working_dir: &Path) -> Result<ToolOutput, String> {
    effects::run(&Invocation {
        program,
        arguments,
        working_dir,
        environment: &[],
        stdin: None,
    })
}

/// Run an external tool as fully described by `invocation`.
pub fn run_with(invocation: &Invocation<'_>) -> Result<ToolOutput, String> {
    effects::run(invocation)
}

/// The regular files directly inside `directory`, not descending into
/// subdirectories, in a deterministic order.
///
/// Symbolic links are followed, because Terraform loads a symlinked
/// `versions.tf` exactly like a regular one; skipping it would report the
/// constraints it declares as missing.
pub fn list_files(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    for entry in walkdir::WalkDir::new(directory)
        .min_depth(1)
        .max_depth(1)
        .follow_links(true)
        .sort_by_file_name()
    {
        let entry =
            entry.map_err(|error| format!("failed to list {}: {error}", directory.display()))?;
        if entry.file_type().is_file() {
            found.push(entry.path().to_path_buf());
        }
    }
    found.sort();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::{
        create_dir_all, executable_on_path, exists, is_dir, is_executable, is_file, list_files,
        read_to_string, remove_dir_all, remove_file, rename, run, run_with, set_executable, write,
        write_new, Invocation,
    };
    use std::path::Path;

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp directory should be created")
    }

    #[test]
    fn a_read_error_names_the_path_it_failed_on() {
        let directory = temp();
        let missing = directory.path().join("absent.yaml");

        let error = read_to_string(&missing).expect_err("a missing file must fail");
        assert!(error.contains("absent.yaml"), "{error}");
        assert!(error.starts_with("failed to read"), "{error}");
    }

    #[test]
    fn writing_creates_and_replaces_but_write_new_refuses_to_replace() {
        let directory = temp();
        let path = directory.path().join("file.yaml");

        write(&path, "first").expect("write should succeed");
        assert_eq!(
            read_to_string(&path).expect("file should be readable"),
            "first"
        );

        write(&path, "second").expect("write should replace");
        assert_eq!(
            read_to_string(&path).expect("file should be readable"),
            "second"
        );

        let error = write_new(&path, "third").expect_err("write_new must not clobber");
        assert!(error.contains("file.yaml"), "{error}");
        assert_eq!(
            read_to_string(&path).expect("file should be readable"),
            "second",
            "a refused write must leave the file untouched"
        );
    }

    #[test]
    fn write_new_creates_a_file_that_did_not_exist() {
        let directory = temp();
        let path = directory.path().join("fresh.yaml");

        write_new(&path, "contents").expect("write_new should create");
        assert_eq!(
            read_to_string(&path).expect("file should be readable"),
            "contents"
        );
    }

    #[test]
    fn directory_creation_is_recursive_and_idempotent() {
        let directory = temp();
        let nested = directory.path().join("a/b/c");

        create_dir_all(&nested).expect("nested creation should succeed");
        assert!(is_dir(&nested));
        create_dir_all(&nested).expect("re-creating an existing directory is not an error");
    }

    #[test]
    fn removal_treats_an_absent_path_as_success() {
        let directory = temp();

        remove_dir_all(&directory.path().join("never-existed")).expect("absent is success");
        remove_file(&directory.path().join("never-existed.yaml")).expect("absent is success");
    }

    #[test]
    fn removal_deletes_what_is_there() {
        let directory = temp();
        let tree = directory.path().join("tree");
        create_dir_all(&tree.join("inner")).expect("tree should be created");
        write(&tree.join("inner/file.yaml"), "x").expect("file should be written");
        let loose = directory.path().join("loose.yaml");
        write(&loose, "x").expect("file should be written");

        remove_dir_all(&tree).expect("tree should be removed");
        remove_file(&loose).expect("file should be removed");
        assert!(!exists(&tree));
        assert!(!exists(&loose));
    }

    #[test]
    fn renaming_moves_a_whole_tree_and_reports_both_paths_on_failure() {
        let directory = temp();
        let from = directory.path().join("staging");
        create_dir_all(&from).expect("staging should be created");
        write(&from.join("file.yaml"), "x").expect("file should be written");
        let to = directory.path().join("published");

        rename(&from, &to).expect("rename should succeed");
        assert!(!exists(&from));
        assert_eq!(
            read_to_string(&to.join("file.yaml")).expect("file should move"),
            "x"
        );

        let error = rename(&directory.path().join("absent"), &to)
            .expect_err("renaming a missing path must fail");
        assert!(
            error.contains("absent") && error.contains("published"),
            "{error}"
        );
    }

    #[test]
    fn path_predicates_distinguish_files_directories_and_nothing() {
        let directory = temp();
        let file = directory.path().join("file.yaml");
        write(&file, "x").expect("file should be written");

        assert!(exists(&file) && is_file(&file) && !is_dir(&file));
        assert!(exists(directory.path()) && is_dir(directory.path()) && !is_file(directory.path()));

        let absent = directory.path().join("absent");
        assert!(!exists(&absent) && !is_file(&absent) && !is_dir(&absent));
    }

    #[test]
    fn a_generated_script_can_be_made_executable() {
        let directory = temp();
        let script = directory.path().join("check.sh");
        write(&script, "#!/bin/sh\n").expect("script should be written");

        assert!(!is_executable(&script) || cfg!(not(unix)));
        set_executable(&script).expect("chmod should succeed");
        assert!(is_executable(&script));
    }

    #[test]
    fn listing_files_stays_in_one_directory_and_sorts_stably() {
        let directory = temp();
        create_dir_all(&directory.path().join("nested")).expect("directory should be created");
        for relative in ["b.tf", "a.tf", "c.tfvars", "nested/d.tf"] {
            write(&directory.path().join(relative), "x").expect("file should be written");
        }

        let found = list_files(directory.path()).expect("listing should succeed");
        let names: Vec<String> = found
            .iter()
            .filter_map(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .collect();

        assert_eq!(names, vec!["a.tf", "b.tf", "c.tfvars"]);
    }

    #[test]
    fn listing_an_absent_directory_fails_rather_than_returning_nothing() {
        let directory = temp();
        let error = list_files(&directory.path().join("absent"))
            .expect_err("a listing that cannot start is not an empty result");
        assert!(error.contains("failed to list"), "{error}");
    }

    #[test]
    fn stdin_and_environment_reach_the_tool() {
        let directory = temp();
        let arguments = ["-c".to_owned(), "printf \"$GREETING:\"; cat".to_owned()];
        let environment = [("GREETING".to_owned(), "hello".to_owned())];

        let output = run_with(&Invocation {
            program: "sh",
            arguments: &arguments,
            working_dir: directory.path(),
            environment: &environment,
            stdin: Some("from stdin"),
        })
        .expect("sh should run");

        assert!(output.success);
        assert_eq!(output.stdout, "hello:from stdin");
    }

    #[test]
    fn running_a_tool_captures_its_status_and_streams() {
        let directory = temp();

        let output = run(
            "sh",
            &[
                "-c".to_owned(),
                "printf out; printf err >&2; exit 3".to_owned(),
            ],
            directory.path(),
        )
        .expect("sh should run");

        assert!(!output.success);
        assert_eq!(output.status, Some(3));
        assert_eq!(output.stdout, "out");
        assert_eq!(output.stderr, "err");
    }

    #[test]
    fn running_a_tool_uses_the_requested_working_directory() {
        let directory = temp();
        write(&directory.path().join("marker.yaml"), "x").expect("file should be written");

        let output = run("ls", &[], directory.path()).expect("ls should run");

        assert!(output.success);
        assert!(output.stdout.contains("marker.yaml"));
    }

    #[test]
    fn a_missing_executable_is_an_error_naming_the_program() {
        let directory = temp();
        let error = run("stricttf-no-such-tool", &[], directory.path())
            .expect_err("a missing program must fail");
        assert!(error.contains("stricttf-no-such-tool"), "{error}");
    }

    #[test]
    fn executable_lookup_answers_from_the_current_path() {
        // `sh` is present on every platform this crate targets; a name
        // this improbable is not.
        assert!(executable_on_path("sh") || !Path::new("/bin/sh").exists());
        assert!(!executable_on_path("stricttf-no-such-tool"));
    }
}
