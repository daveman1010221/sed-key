pub mod opal;

use anyhow::{Result, anyhow};
use std::fs;
use std::io::{self, Read};

/// Read the key from stdin, file, or env var.
fn read_key_arg(key_arg: Option<String>) -> Result<String> {
    if let Some(arg) = key_arg {
        if arg == "-" {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            return Ok(buf.trim_end_matches(['\n', '\r']).to_string());
        } else {
            let s = fs::read_to_string(&arg)?;
            return Ok(s.trim_end_matches(['\n', '\r']).to_string());
        }
    }

    if let Ok(k) = std::env::var("SED_KEY") {
        return Ok(k.trim_end_matches(['\n', '\r']).to_string());
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

    // Get discovery data and parse actual feature flags
    let locked = opal::device_locked(&device)?;
    let features = opal::get_locking_features(&device)?; // new helper (see below)

    opal::print_locking_features(features);

    println!(
        "{} is currently {}",
        device,
        if locked { "LOCKED" } else { "UNLOCKED" }
    );

    Ok(())
}
