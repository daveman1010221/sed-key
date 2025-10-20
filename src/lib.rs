//! sed-key library entry point.

pub mod args;
pub mod opal;

use anyhow::{Result, anyhow};
use once_cell::sync::OnceCell;
use std::{
    fs,
    io::{self, Read},
};

//
// ─── BACKEND SELECTION ───────────────────────────────────────────────────────
//

// Make trait object usable in a static: must be Sync.
trait OpalBackend: Sync {
    fn is_opal_device(&self, dev: &str) -> Result<bool>;
    fn unlock_device(&self, dev: &str, pw: &str) -> Result<()>;
    fn lock_device(&self, dev: &str, pw: &str) -> Result<()>;
    fn device_locked(&self, dev: &str) -> Result<bool>;
    fn get_locking_features(&self, dev: &str) -> Result<u16>;
    fn print_locking_features(&self, f: u16);
}

struct RealBackend;

impl OpalBackend for RealBackend {
    fn is_opal_device(&self, dev: &str) -> Result<bool> {
        opal::is_opal_device(dev)
    }
    fn unlock_device(&self, dev: &str, pw: &str) -> Result<()> {
        opal::unlock_device(dev, pw)
    }
    fn lock_device(&self, dev: &str, pw: &str) -> Result<()> {
        opal::lock_device(dev, pw)
    }
    fn device_locked(&self, dev: &str) -> Result<bool> {
        opal::device_locked(dev)
    }
    fn get_locking_features(&self, dev: &str) -> Result<u16> {
        opal::get_locking_features(dev)
    }
    fn print_locking_features(&self, f: u16) {
        opal::print_locking_features(f)
    }
}

// Global selector
static BACKEND: OnceCell<&'static (dyn OpalBackend + Sync)> = OnceCell::new();
static REAL: RealBackend = RealBackend;

fn backend() -> &'static (dyn OpalBackend + Sync) {
    *BACKEND.get_or_init(|| &REAL as &(dyn OpalBackend + Sync))
}

/// Switch the library to a built-in mock backend.
///
/// This is intended for tests/integration tests to avoid touching real
/// hardware or blocking on stdin. It’s a no-op if the backend was already set.
pub fn use_mock_backend() {
    static MOCK: BuiltinMockBackend = BuiltinMockBackend;
    BACKEND.get_or_init(|| &MOCK);
}

// Simple built-in mock backend (always compiled; tiny and harmless)
struct BuiltinMockBackend;

impl OpalBackend for BuiltinMockBackend {
    fn is_opal_device(&self, dev: &str) -> Result<bool> {
        // simulate only nvme-like device nodes as valid
        if dev.starts_with("/dev/nvme") {
            Ok(true)
        } else {
            Err(anyhow!("{} does not support OPAL locking", dev))
        }
    }

    fn unlock_device(&self, dev: &str, pw: &str) -> Result<()> {
        if pw.is_empty() {
            return Err(anyhow!("empty password"));
        }
        if !dev.starts_with("/dev/nvme") {
            return Err(anyhow!("invalid device"));
        }
        Ok(())
    }

    fn lock_device(&self, dev: &str, pw: &str) -> Result<()> {
        if pw.is_empty() {
            return Err(anyhow!("empty password"));
        }
        if !dev.starts_with("/dev/nvme") {
            return Err(anyhow!("invalid device"));
        }
        Ok(())
    }

    fn device_locked(&self, dev: &str) -> Result<bool> {
        if !dev.starts_with("/dev/nvme") {
            return Err(anyhow!("invalid device"));
        }
        // flip between locked/unlocked for realism, but deterministic
        Ok(dev.ends_with('0'))
    }

    fn get_locking_features(&self, _dev: &str) -> Result<u16> {
        // pretend it supports all standard bits
        Ok(0x001F)
    }

    fn print_locking_features(&self, f: u16) {
        println!("[mock] Locking features: 0x{:04x}", f);
    }
}

//
// ─── KEY READING (REAL LOGIC) ────────────────────────────────────────────────
//

fn read_key_arg(key_arg: Option<String>) -> Result<String> {
    if let Some(arg) = key_arg {
        if arg == "-" {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            return Ok(buf.trim_end_matches(['\n', '\r']).to_string());
        } else if fs::metadata(&arg).is_ok() {
            let s = fs::read_to_string(&arg)?;
            return Ok(s.trim_end_matches(['\n', '\r']).to_string());
        } else {
            return Ok(arg);
        }
    }

    if let Ok(k) = std::env::var("SED_KEY") {
        return Ok(k.trim_end_matches(['\n', '\r']).to_string());
    }

    Err(anyhow!("No key provided (stdin, file, or SED_KEY env var)"))
}

//
// ─── PUBLIC API ──────────────────────────────────────────────────────────────
//

pub fn do_unlock(device: String, key_arg: Option<String>) -> Result<()> {
    let key = read_key_arg(key_arg)?;
    if !backend().is_opal_device(&device)? {
        return Err(anyhow!("{device} does not support OPAL locking"));
    }
    backend().unlock_device(&device, &key)
}

pub fn do_lock(device: String, key_arg: Option<String>) -> Result<()> {
    let key = read_key_arg(key_arg)?;
    if !backend().is_opal_device(&device)? {
        return Err(anyhow!("{device} does not support OPAL locking"));
    }
    backend().lock_device(&device, &key)
}

pub fn do_status(device: String) -> Result<()> {
    if !backend().is_opal_device(&device)? {
        return Err(anyhow!("{device} does not support OPAL locking"));
    }
    let locked = backend().device_locked(&device)?;
    let features = backend().get_locking_features(&device)?;
    backend().print_locking_features(features);
    println!(
        "{} is currently {}",
        device,
        if locked { "LOCKED" } else { "UNLOCKED" }
    );
    Ok(())
}
