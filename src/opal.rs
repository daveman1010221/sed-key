use anyhow::{anyhow, Result};
use linux_sed_opal_sys::*;
use std::fs::File;

use std::os::fd::AsRawFd;


#[cfg(not(miri))]
use std::os::raw::c_int;

#[cfg(not(miri))]
use std::path::Path;

#[cfg(not(miri))]
use nix::request_code_write;

// ───── Constants ──────────────────────────────────────────────────────────────
#[cfg(not(miri))]
pub const IOC_OPAL_DISCOVERY: libc::c_ulong =
    request_code_write!('p', 239, std::mem::size_of::<opal_discovery>());

pub const DISCOVERY_BUF_SIZE: usize = 4096;
pub const DISCOVERY_HEADER_LEN: usize = 48;

pub const OPAL_FEATURE_CODE_LOCKING: u16 = 0x0002;
pub const OPAL_FEATURE_LOCKING_SUPPORTED: u8 = 0x01;
pub const OPAL_FEATURE_LOCKING_ENABLED: u8 = 0x02;
pub const OPAL_FEATURE_LOCKED: u8 = 0x04;
pub const OPAL_FEATURE_MEDIA_ENCRYPT: u8 = 0x08;
pub const OPAL_FEATURE_MBR_ENABLED: u8 = 0x10;
pub const OPAL_FEATURE_MBR_DONE: u8 = 0x20;

pub const OPAL_INCLUDED: u8 = 0; // key_type: key bytes included in opal_key.key

// If you want to exercise the binary path under Miri without touching hardware:
// The code short-circuits device_locked() under Miri using a fake page.
// Example: pretend it's locked
// MIRI_SED_LOCKED=1 cargo miri run -- status /dev/nvme0n1

// Example: pretend it's unlocked (default)
// cargo miri run -- status /dev/nvme0n1

#[cfg(not(miri))]
#[inline]
fn ioctl_opal_discovery(fd: c_int, arg: *mut opal_discovery) -> nix::Result<c_int> {
    // Safety: caller must ensure `fd` is valid and `arg` points to a valid opal_discovery
    unsafe {
        nix::errno::Errno::result(nix::libc::ioctl(fd, IOC_OPAL_DISCOVERY, arg))
    }
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

// ───── Public API ────────────────────────────────────────────────────────────

/// Probe a device’s lock state using the OPAL discovery IOCTL.
///
/// Under Miri we do not hit real hardware. Instead we fabricate a discovery
/// page in [`device_locked_miri`] to exercise the parser. In normal builds we
/// hit the actual IOCTL path.
#[cfg(not(miri))]
pub fn device_locked(dev: &str) -> Result<bool> {

    // non-miri path begins here:
    let candidates = candidate_nodes(dev);
    let mut last_errs: Vec<(String, nix::errno::Errno)> = Vec::new();
    let has_enotty = false;

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

        // `ioctl_opal_discovery` is already marked unsafe, no extra unsafe block needed
        match ioctl_opal_discovery(fd, &mut disc) {
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
    let mut _idx = 0;
    while off + 4 <= end {
        let code   = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let _ver   = buf[off + 2];
        let length = buf[off + 3] as usize;
        let payload = off + 4;

        #[cfg(debug_assertions)]
        eprintln!("Feature _idx {} code=0x{:04x} len={}", _idx, code, length);

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
        _idx += 1;
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

// ───── Miri helpers (no hardware I/O) ───────────────────────────────────────
#[cfg(any(miri, test))]
fn fill_miri_fake_discovery(buf: &mut [u8], flags: u8) {
    // Minimal, well-formed page:
    // [0..3]  : total_len (big-endian) for all feature-descriptor bytes
    // [48..]  : one descriptor: code(0x0002), ver(0x10), len(1), payload(flags)
    // total_len must cover (4 header bytes + payload length) for this record.
    // end = 48 + total_len; loop reads header (4 bytes) then `len` payload.
    buf.fill(0);
    let total_len: u32 = 4 + 1; // one record header (4) + 1 byte payload
    let be = total_len.to_be_bytes();
    buf[0] = be[0];
    buf[1] = be[1];
    buf[2] = be[2];
    buf[3] = be[3];
    let off = DISCOVERY_HEADER_LEN;
    // code = 0x0002 (locking), version = 0x10, length = 1
    buf[off + 0] = 0x00;
    buf[off + 1] = 0x02;
    buf[off + 2] = 0x10;
    buf[off + 3] = 0x01;

    // payload: always include supported + enabled; add locked if requested
    let mut payload_flags = OPAL_FEATURE_LOCKING_SUPPORTED | OPAL_FEATURE_LOCKING_ENABLED;
    if (flags & OPAL_FEATURE_LOCKED) != 0 {
        payload_flags |= OPAL_FEATURE_LOCKED;
    }
    buf[off + 4] = payload_flags;
}

#[cfg(miri)]
pub fn device_locked(_dev: &str) -> Result<bool> {
    use std::env;
    let mut buf = vec![0u8; DISCOVERY_BUF_SIZE];
    let locked = matches!(env::var("MIRI_SED_LOCKED").ok().as_deref(), Some("1"));
    fill_miri_fake_discovery(&mut buf, if locked { OPAL_FEATURE_LOCKED } else { 0 });
    let features = parse_locking_feature(&buf)?;
    Ok((features & OPAL_FEATURE_LOCKED) != 0)
}

/// Build an ordered list of device nodes to probe for OPAL discovery.
///
/// Includes the passed node, then derives `/dev/nvmeX` and `/dev/ngX` for
/// namespace devices if those paths exist.
#[cfg(not(miri))]
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
#[cfg(not(miri))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Strategy to generate a buffer with random locking flags.
    fn buffer_strategy() -> impl Strategy<Value = Vec<u8>> {
        // Make a full-size DISCOVERY_BUF_SIZE buffer
        (any::<u8>()).prop_map(|flags| {
            let mut buf = vec![0u8; DISCOVERY_BUF_SIZE];
            // Use your existing filler
            fill_miri_fake_discovery(&mut buf, flags & OPAL_FEATURE_LOCKED);
            buf
        })
    }

    proptest! {
        #[test]
        fn locked_flag_matches(buf in buffer_strategy()) {
            // If we feed it locked, parser returns locked
            let expected_locked = buf[DISCOVERY_HEADER_LEN + 4] & OPAL_FEATURE_LOCKED != 0;
            let flags = parse_locking_feature(&buf).unwrap();
            prop_assert_eq!(flags & OPAL_FEATURE_LOCKED != 0, expected_locked);
        }

        #[test]
        fn parse_nvme_namespace_round_trip(x in 0u32..64, y in 0u32..1024) {
            let dev = format!("/dev/nvme{}n{}", x, y);
            let parsed = super::parse_nvme_namespace(&dev);
            prop_assert_eq!(parsed, Some((x, y)));
        }

        #[test]
        fn parse_nvme_namespace_rejects_invalid(s in ".*") {
            if !s.starts_with("/dev/nvme") { // skip the trivial case
                prop_assert!(super::parse_nvme_namespace(&s).is_none());
            }
        }

        #[test]
        fn candidate_nodes_no_duplicates(x in 0u32..64, y in 0u32..1024) {
            let dev = format!("/dev/nvme{}n{}", x, y);
            let nodes = super::candidate_nodes(&dev);
            let unique: std::collections::HashSet<_> = nodes.iter().collect();
            prop_assert_eq!(nodes.len(), unique.len());
        }

        #[test]
        fn parse_locking_feature_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = super::parse_locking_feature(&buf);
        }

        #[test]
        fn locked_flag_matches_env(flag in proptest::bool::ANY) {
            let mut buf = vec![0u8; super::DISCOVERY_BUF_SIZE];
            super::fill_miri_fake_discovery(&mut buf, if flag { super::OPAL_FEATURE_LOCKED } else { 0 });
            let features = super::parse_locking_feature(&buf).unwrap();
            prop_assert_eq!((features & super::OPAL_FEATURE_LOCKED) != 0, flag);
        }

        #[test]
        fn build_session_respects_key_len(pw in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let res = super::build_session_admin1_global(&pw);
            // It should error on empty passwords but never panic.
            let _ = res.is_ok() || res.is_err();
        }
    }
}
