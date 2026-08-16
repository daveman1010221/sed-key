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
    /// Query lock state without changing it
    Status {
        /// Device path, e.g. /dev/nvme0n1
        device: String,
    },
    /// Take ownership of an unowned/reverted drive, setting a new SID
    Initialize {
        /// Device path
        device: String,
        /// New key: file path, '-' for stdin, or literal string; if omitted, use env
        key: Option<String>,
    },
    /// Activate the Locking SP's global range using the SID set by `initialize`
    Activate {
        /// Device path
        device: String,
        /// SID password: file path, '-' for stdin, or literal string; if omitted, use env
        key: Option<String>,
    },
    /// Set up the global locking range's RLE/WLE flags (after activate)
    LrSetup {
        /// Device path
        device: String,
        /// Admin1 password: file path, '-' for stdin, or literal string; if omitted, use env
        key: Option<String>,
    },
}
