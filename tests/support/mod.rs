//! Shared test helpers.
//!
//! Fixtures are copied into a temporary directory *under their own name*
//! before use, because several rules compare the module's declared name
//! against its directory name. Copying into a randomly named temp root
//! would change what is under test.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub struct ModuleFixture {
    directory: tempfile::TempDir,
    module: PathBuf,
}

impl ModuleFixture {
    /// The module root inside the temporary copy.
    pub fn path(&self) -> &Path {
        &self.module
    }

    /// The temporary root containing the module directory.
    pub fn parent(&self) -> &Path {
        self.directory.path()
    }

    pub fn read(&self, relative: &str) -> String {
        std::fs::read_to_string(self.module.join(relative))
            .expect("fixture file should be readable")
    }

    pub fn write(&self, relative: &str, contents: &str) {
        let path = self.module.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("fixture directory should be created");
        }
        std::fs::write(path, contents).expect("fixture file should be written");
    }
}

/// Copy `fixtures/<name>` into a temporary directory, preserving the
/// module directory's name.
pub fn module_fixture(name: &str) -> ModuleFixture {
    let source_root = fixture_root().join(name);
    let directory = tempfile::tempdir().expect("temp fixture directory should be created");
    let module = directory.path().join(name);

    for entry in walkdir::WalkDir::new(&source_root).sort_by_file_name() {
        let entry = entry.expect("fixture should be readable");
        if !entry.file_type().is_file() {
            continue;
        }

        let relative = entry
            .path()
            .strip_prefix(&source_root)
            .expect("fixture file should be below the fixture root");
        let destination = module.join(relative);

        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).expect("fixture directory should be created");
        }
        std::fs::copy(entry.path(), destination).expect("fixture file should be copied");
    }

    std::fs::create_dir_all(&module).expect("module directory should exist");
    ModuleFixture { directory, module }
}

/// An empty temporary directory, for generation tests.
pub fn empty_directory() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp directory should be created")
}

pub fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

pub fn fixture_text(relative: &str) -> String {
    std::fs::read_to_string(fixture_root().join(relative)).expect("fixture should be readable")
}

/// Every diagnostic code in a report, in report order.
pub fn codes(report: &stricttf::report::Report) -> Vec<String> {
    report
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

/// Whether a report contains a code at all.
pub fn has_code(report: &stricttf::report::Report, code: &str) -> bool {
    codes(report).iter().any(|found| found == code)
}

/// The path to the built `stricttf` binary under test.
pub fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path should be known");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join(format!("stricttf{}", std::env::consts::EXE_SUFFIX))
}

/// Run the built binary and capture its output.
pub fn run_binary(arguments: &[&str], working_dir: &Path) -> std::process::Output {
    std::process::Command::new(binary())
        .args(arguments)
        .current_dir(working_dir)
        .output()
        .expect("stricttf binary should run")
}

/// Check in-memory sources at source-only depth: every layer that needs
/// no Terraform binary.
pub fn check_files(configuration: &[(&str, &str)]) -> stricttf::report::Report {
    let sources = stricttf::ModuleSources {
        configuration: configuration
            .iter()
            .map(|(path, text)| stricttf::hcl::SourceFile {
                path: (*path).to_owned(),
                text: (*text).to_owned(),
            })
            .collect(),
        ..stricttf::ModuleSources::default()
    };
    let (diagnostics, _checkable) = stricttf::check_sources(&sources);
    stricttf::report::Report::build(diagnostics)
}

/// The diagnostics in a report carrying one code.
pub fn with_code<'a>(
    report: &'a stricttf::report::Report,
    code: &str,
) -> Vec<&'a stricttf::report::Diagnostic> {
    report
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == code)
        .collect()
}
