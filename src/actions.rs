use crate::opal;
use anyhow::{anyhow, Result};
use std::fs;
use std::io::{self, Read};

/// Read the key from stdin, file, or env var.
fn read_key_arg(key_arg: Option<String>) -> Result<String> {
    if let Some(arg) = key_arg {
        if arg == "-" {
            // Read *all* of stdin (not just one line)
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            return Ok(buf.trim_end_matches(|c| c == '\n' || c == '\r').to_string());
        } else {
            // Treat as filename
            let s = fs::read_to_string(&arg)?;
            return Ok(s.trim_end_matches(|c| c == '\n' || c == '\r').to_string());
        }
    }

    if let Ok(k) = std::env::var("SED_KEY") {
        return Ok(k.trim_end_matches(|c| c == '\n' || c == '\r').to_string());
    }

    Err(anyhow!("No key provided (stdin, file, or SED_KEY env var)"))
}

pub fn do_unlock(device: String, key_arg: Option<String>) -> Result<()> {
    let key = read_key_arg(key_arg)?;
    if !opal::is_opal_device(&device)? {
        return Err(anyhow!("{} does not support OPAL locking", device));
    }
    opal::unlock_device(&device, &key)
}

pub fn do_lock(device: String, key_arg: Option<String>) -> Result<()> {
    let key = read_key_arg(key_arg)?;
    if !opal::is_opal_device(&device)? {
        return Err(anyhow!("{} does not support OPAL locking", device));
    }
    opal::lock_device(&device, &key)
}

/// Query lock status (new action)
pub fn do_status(device: String) -> Result<()> {
    if !opal::is_opal_device(&device)? {
        return Err(anyhow!("{} does not support OPAL locking", device));
    }
    let locked = opal::device_locked(&device)?; // you’ll implement this in opal.rs
    println!(
        "{} is currently {}",
        device,
        if locked { "LOCKED" } else { "UNLOCKED" }
    );
    Ok(())
}
