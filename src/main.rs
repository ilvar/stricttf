//! `stricttf` command-line entry point.
//!
//! stdout carries exactly one JSON document per operational invocation.
//! `--help` is the only plain-text stdout mode. Everything meant for a
//! human -- operational failures, installation notices -- goes to stderr,
//! so a caller can pipe stdout into a parser unconditionally.

use std::env;
use std::path::Path;
use stricttf::report::Report;
use stricttf::Depth;

const AGENT_HELP: &str = include_str!("help.txt");
const USAGE: &str = "usage: stricttf [--help] | stricttf [check|fix] [path] [--source-only] | stricttf new <name> | stricttf install-skills";

/// The process exit status is the only process-level effect this binary
/// has, so it lives behind an explicit capability boundary like every
/// other effect in the crate.
// strictrs: capability
mod exit {
    use std::process::ExitCode;

    /// The status type `main` returns.
    pub type Status = ExitCode;

    /// An invocation or operational failure, as distinct from a module
    /// that simply has diagnostics.
    pub const OPERATIONAL: u8 = 2;

    /// Error diagnostics remain.
    pub const DIAGNOSTICS: u8 = 1;

    pub fn success() -> Status {
        ExitCode::SUCCESS
    }

    pub fn failure(code: u8) -> Status {
        ExitCode::from(code)
    }
}

fn main() -> exit::Status {
    let arguments: Vec<String> = env::args().skip(1).collect();

    let operation = match parse(&arguments) {
        Ok(operation) => operation,
        Err(error) => {
            eprintln!("{error}");
            eprintln!("{USAGE}");
            return exit::failure(exit::OPERATIONAL);
        }
    };

    match operation {
        Operation::Help => {
            print!("{AGENT_HELP}");
            exit::success()
        }
        Operation::Check(path, depth) => {
            emit_result(stricttf::run_check_with_depth(Path::new(&path), depth))
        }
        Operation::Fix(path, depth) => emit_result(stricttf::run_fix_with_limit(
            Path::new(&path),
            depth,
            stricttf::DEFAULT_MAX_FIX_ITERATIONS,
        )),
        Operation::New(name) => match stricttf::template::create_module(Path::new("."), &name) {
            Ok(_destination) => emit_report(&Report::clean()),
            Err(error) => {
                eprintln!("{error}");
                exit::failure(exit::OPERATIONAL)
            }
        },
        Operation::InstallSkills => match stricttf::skills::install_detected() {
            Ok(messages) => {
                for message in messages {
                    eprintln!("{message}");
                }
                emit_report(&Report::clean())
            }
            Err(error) => {
                eprintln!("{error}");
                exit::failure(exit::OPERATIONAL)
            }
        },
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Operation {
    Help,
    Check(String, Depth),
    Fix(String, Depth),
    New(String),
    InstallSkills,
}

/// Parse an argument list into exactly one operation.
///
/// A bare path is treated as `check` so the tool is usable without
/// remembering a subcommand, and any help alias wins over everything else
/// on the line.
fn parse(arguments: &[String]) -> Result<Operation, String> {
    if arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), "-h" | "--help" | "help"))
    {
        return Ok(Operation::Help);
    }

    let mut depth = Depth::Full;
    let mut positional: Vec<&str> = Vec::new();

    for argument in arguments {
        match argument.as_str() {
            "--source-only" => depth = Depth::SourceOnly,
            flag if flag.starts_with('-') => return Err(format!("unknown option: {flag}")),
            value => positional.push(value),
        }
    }

    let (command, rest) = match positional.split_first() {
        None => return Ok(Operation::Check(".".to_owned(), depth)),
        Some((command, rest)) => (*command, rest),
    };

    let operation = match command {
        "check" | "fix" => {
            let path = match rest.split_first() {
                None => ".".to_owned(),
                Some((path, [])) => (*path).to_owned(),
                Some(_more) => return Err("too many arguments".to_owned()),
            };
            if command == "check" {
                Operation::Check(path, depth)
            } else {
                Operation::Fix(path, depth)
            }
        }
        "new" => match rest.split_first() {
            None => return Err("new requires a module name".to_owned()),
            Some((name, [])) => Operation::New((*name).to_owned()),
            Some(_more) => return Err("too many arguments".to_owned()),
        },
        "install-skills" => {
            if !rest.is_empty() {
                return Err("install-skills does not accept arguments".to_owned());
            }
            Operation::InstallSkills
        }
        path => {
            if !rest.is_empty() {
                return Err("too many arguments".to_owned());
            }
            Operation::Check(path.to_owned(), depth)
        }
    };

    Ok(operation)
}

fn emit_result(result: Result<Report, String>) -> exit::Status {
    match result {
        Ok(report) => emit_report(&report),
        Err(error) => {
            eprintln!("{error}");
            exit::failure(exit::OPERATIONAL)
        }
    }
}

fn emit_report(report: &Report) -> exit::Status {
    match serde_json::to_string_pretty(report) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("failed to serialize report: {error}");
            return exit::failure(exit::OPERATIONAL);
        }
    }

    if report.ok {
        exit::success()
    } else {
        exit::failure(exit::DIAGNOSTICS)
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, Operation};
    use stricttf::Depth;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn no_arguments_checks_the_current_directory() {
        assert_eq!(
            parse(&arguments(&[])),
            Ok(Operation::Check(".".to_owned(), Depth::Full))
        );
    }

    #[test]
    fn a_bare_path_is_a_check() {
        assert_eq!(
            parse(&arguments(&["modules/network"])),
            Ok(Operation::Check("modules/network".to_owned(), Depth::Full))
        );
    }

    #[test]
    fn source_only_applies_before_and_after_the_path() {
        let expected = Operation::Check("module".to_owned(), Depth::SourceOnly);
        assert_eq!(
            parse(&arguments(&["check", "module", "--source-only"])),
            Ok(expected)
        );
        assert_eq!(
            parse(&arguments(&["--source-only", "check", "module"])),
            Ok(Operation::Check("module".to_owned(), Depth::SourceOnly))
        );
    }

    #[test]
    fn every_help_alias_wins_over_other_arguments() {
        for alias in ["-h", "--help", "help"] {
            assert_eq!(parse(&arguments(&[alias])), Ok(Operation::Help));
            assert_eq!(
                parse(&arguments(&["check", ".", alias])),
                Ok(Operation::Help)
            );
            assert_eq!(parse(&arguments(&["new", alias])), Ok(Operation::Help));
        }
    }

    #[test]
    fn unknown_options_and_extra_arguments_are_rejected() {
        assert!(parse(&arguments(&["--nope"])).is_err());
        assert!(parse(&arguments(&["check", "a", "b"])).is_err());
        assert!(parse(&arguments(&["new"])).is_err());
        assert!(parse(&arguments(&["install-skills", "extra"])).is_err());
    }
}
