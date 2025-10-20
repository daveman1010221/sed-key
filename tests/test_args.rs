use clap::Parser;
use sed_key::args::{Cli, Command};

#[test]
fn parses_unlock_command_with_key() {
    let cli = Cli::parse_from(["sed-key", "unlock", "/dev/nvme0", "secret"]);

    match cli.command {
        Command::Unlock { device, key } => {
            assert_eq!(device, "/dev/nvme0");
            assert_eq!(key.as_deref(), Some("secret"));
        }
        _ => panic!("wrong subcommand parsed"),
    }
}

#[test]
fn parses_status_command() {
    let cli = Cli::parse_from(["sed-key", "status", "/dev/nvme0n1"]);

    match cli.command {
        Command::Status { device } => assert_eq!(device, "/dev/nvme0n1"),
        _ => panic!("expected Status variant"),
    }
}

#[test]
fn parses_docs_command() {
    let cli = Cli::parse_from(["sed-key", "docs"]);

    match cli.command {
        Command::Docs => {}
        _ => panic!("expected Docs variant"),
    }
}
