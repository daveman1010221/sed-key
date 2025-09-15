use crate::opal;
use anyhow::{anyhow, Result};
use std::fs;

fn read_key_arg(key_arg: Option<String>) -> Result<String> {
    if let Some(arg) = key_arg {
        if arg == "-" {
            // read from stdin
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf)?;
            return Ok(buf.trim().to_string());
        } else {
            // treat as filename
            let s = fs::read_to_string(&arg)?;
            return Ok(s.lines().next().unwrap_or("").trim().to_string());
        }
    }
    if let Ok(k) = std::env::var("SED_KEY") {
        return Ok(k.trim().to_string());
    }
    Err(anyhow!("No key provided"))
}

pub fn do_unlock(device: String, key_arg: Option<String>) -> Result<()> {
    let key = read_key_arg(key_arg)?;
    if !opal::is_opal_device(&device)? {
        return Err(anyhow!("Device is not OPAL capable"));
    }
    opal::unlock_device(&device, &key)
}

pub fn do_lock(device: String, key_arg: Option<String>) -> Result<()> {
    let key = read_key_arg(key_arg)?;
    if !opal::is_opal_device(&device)? {
        return Err(anyhow!("Device is not OPAL capable"));
    }
    opal::lock_device(&device, &key)
}
