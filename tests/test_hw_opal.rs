// tests/hw_opal.rs
#![cfg(feature = "real-hardware")] // compile this file only with the feature

use anyhow::{Result, bail};
use sed_key::{do_lock, do_status, do_unlock};
use std::fs;

fn test_dev() -> Result<String> {
    let dev = std::env::var("SED_KEY_TEST_DEV")
        .map_err(|_| anyhow::anyhow!("Set SED_KEY_TEST_DEV=/dev/nvmeX or /dev/nvmeXnY"))?;
    // refuse obviously dangerous things
    if dev == "/dev/nvme0n1" {
        bail!("Refusing to touch {}", dev);
    }
    // refuse mounted devices
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    if mounts.contains(&dev) {
        bail!("{} appears mounted; aborting", dev);
    }
    Ok(dev)
}

fn test_pw() -> Result<String> {
    Ok(std::env::var("SED_KEY_TEST_PW")
        .map_err(|_| anyhow::anyhow!("Set SED_KEY_TEST_PW=<password>"))?)
}

#[test]
#[ignore] // require -- --ignored
fn hw_status_smoke() -> Result<()> {
    let dev = test_dev()?;
    do_status(dev)?;
    Ok(())
}

#[test]
#[ignore] // require -- --ignored
fn hw_lock_unlock_roundtrip() -> Result<()> {
    let dev = test_dev()?;
    let pw = test_pw()?;

    // unlock (idempotent-ish if already unlocked)
    do_unlock(dev.clone(), Some(pw.clone()))?;
    do_status(dev.clone())?; // should print UNLOCKED

    // lock
    do_lock(dev.clone(), Some(pw.clone()))?;
    do_status(dev.clone())?; // should print LOCKED

    // unlock again so you don’t strand the device
    do_unlock(dev.clone(), Some(pw.clone()))?;
    do_status(dev)?;
    Ok(())
}
