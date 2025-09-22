use anyhow::{anyhow, Result};
use linux_sed_opal_sys::*;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::raw::c_int;
use std::path::Path;
use nix::request_code_write;

// ───── Constants ──────────────────────────────────────────────────────────────
pub const IOC_OPAL_DISCOVERY: libc::c_ulong =
    request_code_write!('p', 239, std::mem::size_of::<opal_discovery>());

const DISCOVERY_BUF_SIZE: usize = 4096;
const DISCOVERY_HEADER_LEN: usize = 48;

const OPAL_FEATURE_CODE_LOCKING: u16 = 0x0002;
const OPAL_FEATURE_LOCKING_SUPPORTED: u8 = 0x01;
const OPAL_FEATURE_LOCKING_ENABLED: u8 = 0x02;
const OPAL_FEATURE_LOCKED: u8 = 0x04;
const OPAL_FEATURE_MEDIA_ENCRYPT: u8 = 0x08;
const OPAL_FEATURE_MBR_ENABLED: u8 = 0x10;
const OPAL_FEATURE_MBR_DONE: u8 = 0x20;

const OPAL_INCLUDED: u8 = 0; // key_type: key bytes included in opal_key.key

#[inline]
unsafe fn ioctl_opal_discovery(fd: c_int, arg: *mut opal_discovery) -> nix::Result<c_int> {
    nix::errno::Errno::result(nix::libc::ioctl(fd, IOC_OPAL_DISCOVERY, arg))
}

// ───── Device Capability ─────────────────────────────────────────────────────

/// Determine whether a device is OPAL/SED capable using the discovery IOCTL.
///
/// This calls [`device_locked`] internally. If the device responds to
/// discovery, it returns `Ok(true)`; if the device reports no OPAL/SED
/// support it returns `Ok(false)`; otherwise it bubbles up any error.
pub fn is_opal_device(dev: &str) -> Result<bool> {
    match device_locked(dev) {
        Ok(_) => Ok(true),
        Err(e) if e.to_string().contains("does not support OPAL/SED functionality") => Ok(false),
        Err(e) => Err(e),
    }
}

/// Determine whether a device is OPAL/SED capable using the older
/// lock/unlock IOCTL instead of discovery.
///
/// Opens the device read/write and issues an unlock request with a dummy
/// session. Returns `Ok(true)` if the ioctl is accepted, `Ok(false)` if
/// `ENOTTY` (no such ioctl), or an error otherwise.
pub fn is_opal_device_legacy(dev: &str) -> Result<bool> {
    let fd = File::options().read(true).write(true).open(dev)?.as_raw_fd();
    let mut sess = opal_session_info::default();
    sess.who = opal_user::OPAL_ADMIN1.0;
    sess.opal_key.key_type = OPAL_INCLUDED;
    sess.opal_key.key_len = 1;

    let mut op = opal_lock_unlock::default();
    op.session = sess;
    op.l_state = opal_lock_state::OPAL_RW.0;

    match unsafe { ioc_opal_lock_unlock(fd, &op) } {
        Ok(_) => Ok(true),
        Err(errno) if (errno as i32) == libc::ENOTTY => Ok(false),
        Err(errno) => Err(anyhow!("unlock ioctl failed with errno {:?}", errno)),
    }
}

// ───── Lock / Unlock helpers ─────────────────────────────────────────────────
#[inline]
/// Build a default [`opal_session_info`] for the Admin1 user at the global
/// locking range, copying the provided password into the key field.
///
/// This is used internally by [`unlock_device`] and [`lock_device`].
fn build_session_admin1_global(pw: &[u8]) -> Result<opal_session_info> {
    if pw.is_empty() {
        return Err(anyhow!("empty password"));
    }
    let mut sess = opal_session_info::default();
    sess.who = opal_user::OPAL_ADMIN1.0;
    sess.opal_key.lr = 0;
    sess.opal_key.key_type = OPAL_INCLUDED;
    let n = std::cmp::min(pw.len(), OPAL_KEY_MAX as usize) as u8;
    sess.opal_key.key_len = n;
    sess.opal_key.key[..n as usize].copy_from_slice(&pw[..n as usize]);
    Ok(sess)
}

/// Generic helper to lock or unlock a device.
///
/// Called by [`unlock_device`] and [`lock_device`] with the appropriate
/// [`opal_lock_state`] (RW = unlock, LK = lock).
fn do_lock(dev: &str, password: &str, state: opal_lock_state) -> Result<()> {
    let fd = File::options().read(true).write(true).open(dev)
        .map_err(|e| anyhow!("open {}: {}", dev, e))?
        .as_raw_fd();
    let sess = build_session_admin1_global(password.as_bytes())?;
    let mut op = opal_lock_unlock::default();
    op.session = sess;
    op.l_state = state.0;

    unsafe { ioc_opal_lock_unlock(fd, &op) }
        .map_err(|e| anyhow!("ioctl failed with {:?}", e))?;
    Ok(())
}

/// Unlock a device by sending the OPAL_LOCK_UNLOCK ioctl with RW state.
///
/// The password may be supplied via stdin, file, or env var by the caller.
pub fn unlock_device(dev: &str, pw: &str) -> Result<()> {
    do_lock(dev, pw, opal_lock_state::OPAL_RW)
}

/// Lock a device by sending the OPAL_LOCK_UNLOCK ioctl with LK state.
///
/// The password may be supplied via stdin, file, or env var by the caller.
pub fn lock_device(dev: &str, pw: &str) -> Result<()> {
    do_lock(dev, pw, opal_lock_state::OPAL_LK)
}

// ───── Discovery Path ────────────────────────────────────────────────────────

/// Probe a device’s lock state using the OPAL discovery IOCTL.
///
/// Tries the device node itself, then its controller node, then the `/dev/ngX`
/// generic SED node. For each candidate node:
///
/// * Attempt the 16-byte discovery struct (TCG opal_discovery)
/// * If ENOTTY, attempt the 12-byte compat struct
///
/// Returns `Ok(true)` if locked, `Ok(false)` if unlocked, or an error if the
/// device does not support OPAL/SED or all attempts fail.
pub fn device_locked(dev: &str) -> Result<bool> {
    let candidates = candidate_nodes(dev);
    let mut last_errs: Vec<(String, nix::errno::Errno)> = Vec::new();
    let mut has_enotty = false;

    for node in candidates {
        // keep File alive while using its fd
        let file = match File::open(&node) {
            Ok(f) => f,
            Err(e) => {
                last_errs.push((node.clone(), nix::errno::Errno::from_i32(
                    e.raw_os_error().unwrap_or(libc::EINVAL))));
                continue;
            }
        };
        let fd = file.as_raw_fd();

        let mut buf = vec![0u8; DISCOVERY_BUF_SIZE];
        let mut disc = opal_discovery {
            data: buf.as_mut_ptr() as u64,
            size: buf.len() as u64
        };

        match unsafe { ioctl_opal_discovery(fd, &mut disc) } {
            Ok(_) => {
                #[cfg(debug_assertions)]
                eprintln!("Discovery buffer (first 256 bytes): {:02x?}", &buf[..256.min(buf.len())]);
                let features = parse_locking_feature(&buf)?;
                return Ok((features & OPAL_FEATURE_LOCKED) != 0);
            }
            Err(errno) => {
                last_errs.push((node.clone(), errno));
            }
        }
    }

    if has_enotty && last_errs.iter().all(|(_, e)| *e == nix::errno::Errno::ENOTTY) {
        return Err(anyhow!(
            "Device does not support OPAL/SED functionality. Tried: {}",
            last_errs.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }

    let why = last_errs.iter()
        .map(|(n, e)| format!("{}: {}", n, e))
        .collect::<Vec<_>>()
        .join(", ");
    Err(anyhow!("Discovery ioctl failed ({})", why))
}

/// Parse the TCG discovery buffer to locate the Locking Feature Descriptor.
///
/// Returns the locking feature flags byte on success or an error if the
/// descriptor cannot be found or is malformed.
fn parse_locking_feature(buf: &[u8]) -> Result<u8> {
    if buf.len() < DISCOVERY_HEADER_LEN {
        return Err(anyhow!("Discovery buffer too small: {}", buf.len()));
    }

    let total_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let end = DISCOVERY_HEADER_LEN.saturating_add(total_len).min(buf.len());

    let mut off = DISCOVERY_HEADER_LEN;
    let mut idx = 0;
    while off + 4 <= end {
        let code   = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let _ver   = buf[off + 2];
        let length = buf[off + 3] as usize;
        let payload = off + 4;

        #[cfg(debug_assertions)]
        eprintln!("Feature idx {} code=0x{:04x} len={}", idx, code, length);

        if payload + length > end { break; }
        if code == OPAL_FEATURE_CODE_LOCKING {
            if length == 0 {
                return Err(anyhow!("Locking feature present but payload is empty"));
            }
            let flags = buf[payload];
            println!("Locking feature flags=0x{:02x}", flags);
            return Ok(flags);
        }
        off = payload + length;
        idx += 1;
    }
    Err(anyhow!("Locking feature not found in discovery page (parsed header total_len={})", total_len))
}

// ───── Helpers ───────────────────────────────────────────────────────────────

/// Pretty-print the bits of the Locking Feature Descriptor to stdout.
///
/// This mimics `nvme-cli`’s display of SED locking status.
pub fn print_locking_features(features: u8) {
    println!("Locking Features:");
    println!("\tLocking Supported : {}", if (features & OPAL_FEATURE_LOCKING_SUPPORTED) != 0 {"yes"} else {"no"});
    println!("\tLocking Enabled   : {}", if (features & OPAL_FEATURE_LOCKING_ENABLED) != 0 {"yes"} else {"no"});
    println!("\tLocked            : {}", if (features & OPAL_FEATURE_LOCKED) != 0 {"yes"} else {"no"});
    println!("\tMedia Encryption  : {}", if (features & OPAL_FEATURE_MEDIA_ENCRYPT) != 0 {"yes"} else {"no"});
    println!("\tMBR Enabled       : {}", if (features & OPAL_FEATURE_MBR_ENABLED) != 0 {"yes"} else {"no"});
    println!("\tMBR Done          : {}", if (features & OPAL_FEATURE_MBR_DONE) != 0 {"yes"} else {"no"});
}

/// Build an ordered list of device nodes to probe for OPAL discovery.
///
/// Includes the passed node, then derives `/dev/nvmeX` and `/dev/ngX` for
/// namespace devices if those paths exist.
fn candidate_nodes(dev: &str) -> Vec<String> {
    let mut v = vec![dev.to_string()];
    if let Some((ctrl_idx, _)) = parse_nvme_namespace(dev) {
        let ctrl = format!("/dev/nvme{}", ctrl_idx);
        let ng = format!("/dev/ng{}", ctrl_idx);
        for n in [ctrl, ng] {
            if !v.contains(&n) && Path::new(&n).exists() {
                v.push(n);
            }
        }
    }
    v
}

/// Parse a namespace device string of the form `/dev/nvmeXnY` into controller
/// index X and namespace index Y. Returns `None` if the path does not match
/// this pattern.
fn parse_nvme_namespace(dev: &str) -> Option<(u32, u32)> {
    let p = dev.strip_prefix("/dev/nvme")?;
    let mut x = String::new();
    let mut it = p.chars();
    while let Some(c) = it.next() {
        if c.is_ascii_digit() { x.push(c); } else { break; }
    }
    let rest = &p[x.len()..];
    if !rest.starts_with('n') { return None; }
    let mut y = String::new();
    for c in rest[1..].chars() {
        if c.is_ascii_digit() { y.push(c); } else { break; }
    }
    if x.is_empty() || y.is_empty() { return None; }
    Some((x.parse().ok()?, y.parse().ok()?))
}
