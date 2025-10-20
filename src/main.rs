//! # sed-key
//!
//! `sed-key` is a Rust command-line tool for locking, unlocking, and querying the
//! lock state of NVMe Self-Encrypting Drives (SED) using the TCG OPAL protocol
//! under Linux.
//!
//! ## Usage
//!
//! ```text
//! sed-key status /dev/nvme0n1
//! sed-key unlock /dev/nvme0n1 mypassword
//! sed-key lock /dev/nvme0n1 mypassword
//! ```
//!
//! See the [README on GitHub](https://github.com/daveman1010221/sed-key)
//! for installation and full usage instructions.

#![doc = include_str!("../README.md")]

mod args;

use anyhow::Result;
use args::{Cli, Command};
use clap::{CommandFactory, Parser};
use sed_key::{do_lock, do_status, do_unlock};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Docs => {
            Cli::command().print_help()?;
            println!();
        }
        Command::Unlock { device, key } => {
            do_unlock(device, key)?;
        }
        Command::Lock { device, key } => {
            do_lock(device, key)?;
        }
        Command::Status { device } => {
            // delegate to actions.rs helper
            do_status(device)?;
        }
    }
    Ok(())
}
