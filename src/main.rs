mod args;
mod opal;
mod actions;

use anyhow::Result;
use args::{Cli, Command};
use clap::{Parser, CommandFactory};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Docs => {
            Cli::command().print_help()?;
            println!();
        }
        Command::Unlock { device, key } => {
            actions::do_unlock(device, key)?;
        }
        Command::Lock { device, key } => {
            actions::do_lock(device, key)?;
        }
        Command::Status { device } => {
            // query lock state without changing it
            let locked = opal::device_locked(&device)?;
            if locked {
                println!("{device}: Locked");
            } else {
                println!("{device}: Unlocked");
            }
        }
    }
    Ok(())
}
