use clap::{Parser, Subcommand};

/// Simple OPAL lock/unlock tool
#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print help
    Docs,
    /// Unlock a device
    Unlock {
        /// Device path, e.g. /dev/nvme0
        device: String,
        /// Optional key file or '-' for stdin; if omitted, use env
        key: Option<String>,
    },
    /// Lock a device
    Lock {
        /// Device path
        device: String,
        /// Optional key file or '-' for stdin; if omitted, use env
        key: Option<String>,
    },
}
