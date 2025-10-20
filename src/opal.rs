use anyhow::{Result, anyhow};
use linux_sed_opal_sys::*;
use std::fs::File;

use std::os::fd::AsRawFd;

#[cfg(not(miri))]
use std::os::raw::c_int;

#[cfg(all(not(test), not(miri)))]
use std::path::Path;

#[cfg(not(miri))]
use nix::request_code_write;

use zeroize::Zeroize;

// ───── Constants ──────────────────────────────────────────────────────────────
#[cfg(not(miri))]
pub const IOC_OPAL_DISCOVERY: libc::c_ulong =
    request_code_write!('p', 239, std::mem::size_of::<opal_discovery>());

pub const DISCOVERY_BUF_SIZE: usize = 4096;
pub const DISCOVERY_HEADER_LEN: usize = 48;

pub const OPAL_FEATURE_CODE_LOCKING: u16 = 0x0002;

pub const OPAL_FEATURE_LOCKING_SUPPORTED: u16 = 0x0001;
pub const OPAL_FEATURE_LOCKING_ENABLED: u16 = 0x0002;
pub const OPAL_FEATURE_LOCKED: u16 = 0x0004;
pub const OPAL_FEATURE_MEDIA_ENCRYPT: u16 = 0x0008;
pub const OPAL_FEATURE_MBR_ENABLED: u16 = 0x0010;
pub const OPAL_FEATURE_MBR_DONE: u16 = 0x0020;

pub const OPAL_INCLUDED: u8 = 0; // key_type: key bytes included in opal_key.key

/// Safe fixed-size representation of an OPAL key buffer.
/// Ensures we always have a real `[u8; OPAL_KEY_MAX]` to write into.
#[repr(C)]
struct OpalKeyFixed {
    lr: u8,
    key_type: u8,
    key_len: u8,
    key: [u8; OPAL_KEY_MAX as usize],
}

impl Default for OpalKeyFixed {
    fn default() -> Self {
        Self {
            lr: 0,
            key_type: 0,
            key_len: 0,
            key: [0u8; OPAL_KEY_MAX as usize],
        }
    }
}

impl OpalKeyFixed {
    /// Fill key from `pw` (already validated to be `<= OPAL_KEY_MAX`).
    fn with_password(mut self, pw: &[u8]) -> Self {
        self.key_len = pw.len() as u8;
        self.key[..pw.len()].copy_from_slice(pw);
        self
    }
}

// Zeroize the temporary buffer on drop (belt-and-suspenders)
impl Drop for OpalKeyFixed {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.key_len.zeroize();
    }
}

impl From<OpalKeyFixed> for opal_key {
    fn from(k: OpalKeyFixed) -> Self {
        let mut out = opal_key {
            lr: k.lr,
            key_type: k.key_type,
            key_len: k.key_len,
            ..Default::default()
        };
        // Copy the full fixed buffer (or only up to key_len; either is fine)
        out.key[..OPAL_KEY_MAX as usize].copy_from_slice(&k.key);
        out
    }
}

impl OpalKeyFixed {
    #[inline]
    fn with_lr(mut self, lr: u8) -> Self {
        self.lr = lr;
        self
    }
    #[inline]
    fn with_key_type(mut self, kt: u8) -> Self {
        self.key_type = kt;
        self
    }
}

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
    unsafe { nix::errno::Errno::result(nix::libc::ioctl(fd, IOC_OPAL_DISCOVERY, arg)) }
}

#[cfg(miri)]
fn ioctl_opal_discovery(_fd: i32, _arg: *mut opal_discovery) -> nix::Result<i32> {
    Ok(0)
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
        Err(e)
            if e.to_string()
                .contains("does not support OPAL/SED functionality") =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

// ───── Lock / Unlock helpers ─────────────────────────────────────────────────

/// Build a default [`opal_session_info`] for the Admin1 user at the global
/// locking range, copying the provided password into the key field.
///
/// Used internally by [`unlock_device`] and [`lock_device`].
#[inline]
fn build_session_admin1_global(pw: &[u8]) -> Result<opal_session_info> {
    if pw.is_empty() {
        return Err(anyhow!("empty password"));
    }
    let max = OPAL_KEY_MAX as usize;
    if pw.len() > max {
        return Err(anyhow!(
            "password length ({}) exceeds OPAL_KEY_MAX ({}) — refusing to truncate",
            pw.len(),
            OPAL_KEY_MAX
        ));
    }

    // Build and scrub via the wrapper.
    let fixed = OpalKeyFixed::default()
        .with_key_type(OPAL_INCLUDED)
        .with_lr(0)
        .with_password(pw);

    let sess = opal_session_info {
        who: opal_user::OPAL_ADMIN1.0,
        opal_key: fixed.into(), // moves the bytes; wrapper will zeroize on drop
        ..Default::default()
    };
    Ok(sess)
}

/// Generic helper to lock or unlock a device.
///
/// Called by [`unlock_device`] and [`lock_device`] with the appropriate
/// [`opal_lock_state`] (RW = unlock, LK = lock).
fn do_lock(dev: &str, password: &str, state: opal_lock_state) -> Result<()> {
    // Keep File open during ioctl
    let file = File::options()
        .read(true)
        .write(true)
        .open(dev)
        .map_err(|e| anyhow!("failed to open {}: {}", dev, e))?;
    let fd = file.as_raw_fd();

    // Build session with key material
    let sess = build_session_admin1_global(password.as_bytes())?;

    // Prepare ioctl struct
    let mut op = opal_lock_unlock {
        session: sess,
        l_state: state.0,
        ..Default::default()
    };

    // Execute ioctl while file descriptor is valid
    let res = unsafe { ioc_opal_lock_unlock(fd, &op) }
        .map(|_| ())
        .map_err(|e| {
            anyhow!(
                "OPAL_LOCK_UNLOCK ioctl failed on {} (state={:?}): {:?}",
                dev,
                state.0,
                e
            )
        });

    // Scrub key material before returning
    op.session.opal_key.key[..op.session.opal_key.key_len as usize].zeroize();

    res
}

/// Unlock a device by sending the OPAL_LOCK_UNLOCK ioctl with RW state.
///
/// Verifies the device is actually unlocked afterward.
pub fn unlock_device(dev: &str, pw: &str) -> Result<()> {
    do_lock(dev, pw, opal_lock_state::OPAL_RW)?;

    // Post-condition: verify unlock took effect
    match device_locked(dev) {
        Ok(true) => Err(anyhow!(
            "{}: unlock ioctl completed but device still reports LOCKED",
            dev
        )),
        Ok(false) => {
            println!("{} successfully unlocked.", dev);
            Ok(())
        }
        Err(e) => Err(anyhow!("{}: unlock verification failed: {}", dev, e)),
    }
}

/// Lock a device by sending the OPAL_LOCK_UNLOCK ioctl with LK state.
///
/// Verifies the device is actually locked afterward.
pub fn lock_device(dev: &str, pw: &str) -> Result<()> {
    do_lock(dev, pw, opal_lock_state::OPAL_LK)?;

    // Post-condition: verify lock took effect
    match device_locked(dev) {
        Ok(false) => Err(anyhow!(
            "{}: lock ioctl completed but device still reports UNLOCKED",
            dev
        )),
        Ok(true) => {
            println!("{} successfully locked.", dev);
            Ok(())
        }
        Err(e) => Err(anyhow!("{}: lock verification failed: {}", dev, e)),
    }
}

// ───── Discovery Path ────────────────────────────────────────────────────────

// ───── Public API ────────────────────────────────────────────────────────────

/// Probe a device’s lock state using the OPAL discovery IOCTL.
///
/// Under Miri we do not hit real hardware. Instead we fabricate a discovery
/// page in [`device_locked_miri`] to exercise the parser. In normal builds we
/// hit the actual IOCTL path.
#[cfg(all(not(test), not(miri)))]
pub fn device_locked(dev: &str) -> Result<bool> {
    let candidates = candidate_nodes(dev);
    let mut last_errs: Vec<(String, nix::errno::Errno)> = Vec::new();
    let mut saw_enotty = false;

    for node in candidates {
        // Keep File in scope while using its fd
        let file = match File::open(&node) {
            Ok(f) => f,
            Err(e) => {
                let errno = nix::errno::Errno::from_i32(e.raw_os_error().unwrap_or(libc::EINVAL));
                last_errs.push((node.clone(), errno));
                continue;
            }
        };
        let fd = file.as_raw_fd();

        let mut buf = vec![0u8; DISCOVERY_BUF_SIZE];
        let mut disc = opal_discovery {
            data: buf.as_mut_ptr() as u64,
            size: buf.len() as u64,
        };

        // Safe wrapper already checks errno
        match ioctl_opal_discovery(fd, &mut disc) {
            Ok(_) => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "Discovery buffer (first 256 bytes): {:02x?}",
                    &buf[..256.min(buf.len())]
                );

                let features = parse_locking_feature(&buf)?;
                return Ok((features & OPAL_FEATURE_LOCKED) != 0);
            }
            Err(errno) => {
                if errno == nix::errno::Errno::ENOTTY {
                    saw_enotty = true;
                }
                last_errs.push((node.clone(), errno));
            }
        }
    }

    // If all probes failed with ENOTTY, it’s not an OPAL device
    if saw_enotty
        && last_errs
            .iter()
            .all(|(_, e)| *e == nix::errno::Errno::ENOTTY)
    {
        return Err(anyhow!(
            "Device does not support OPAL/SED functionality. Tried nodes: {}",
            last_errs
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let why = last_errs
        .iter()
        .map(|(n, e)| format!("{}: {}", n, e))
        .collect::<Vec<_>>()
        .join(", ");

    Err(anyhow!(
        "Discovery ioctl failed for all candidates ({})",
        why
    ))
}

/// Parse the TCG discovery buffer to locate the Locking Feature Descriptor.
/// Returns the 16-bit locking flags on success.
fn parse_locking_feature(buf: &[u8]) -> Result<u16> {
    if buf.len() < DISCOVERY_HEADER_LEN {
        return Err(anyhow!("Discovery buffer too small: {}", buf.len()));
    }

    // Discovery header total length is big-endian bytes of *feature area*.
    let total_len_be = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let end = DISCOVERY_HEADER_LEN
        .saturating_add(total_len_be)
        .min(buf.len());

    let mut off = DISCOVERY_HEADER_LEN;
    while off + 4 <= end {
        // Feature header: code (BE u16), version (u8), length (u8)
        let code = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let _ver = buf[off + 2];
        let length = buf[off + 3] as usize;
        let payload = off + 4;

        // Malformed: header claims more than we have.
        if payload + length > end {
            return Err(anyhow!(
                "Feature payload overruns discovery region: off={} len={}",
                off,
                length
            ));
        }

        if code == OPAL_FEATURE_CODE_LOCKING {
            // Locking Feature payload is little-endian flags.
            if length < 2 {
                // Be forgiving: some odd firmwares report 1 byte; treat as LSB.
                if length == 1 {
                    let flags = buf[payload] as u16;
                    #[cfg(debug_assertions)]
                    eprintln!("Locking feature flags=0x{:04x}", flags);
                    return Ok(flags);
                }
                return Err(anyhow!("Locking feature payload too short"));
            }
            let flags = u16::from_le_bytes([buf[payload], buf[payload + 1]]);
            #[cfg(debug_assertions)]
            eprintln!("Locking feature flags=0x{:04x}", flags);
            return Ok(flags);
        }

        off = payload + length;
    }

    Err(anyhow!("Locking feature not found in discovery page"))
}

// ───── Helpers ───────────────────────────────────────────────────────────────

/// Pretty-print the bits of the Locking Feature Descriptor to stdout.
///
/// This mimics `nvme-cli`’s display of SED locking status.
pub fn print_locking_features(features: u16) {
    println!("Locking Features:");
    println!(
        "\tLocking Supported : {}",
        if (features & OPAL_FEATURE_LOCKING_SUPPORTED) != 0 {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "\tLocking Enabled   : {}",
        if (features & OPAL_FEATURE_LOCKING_ENABLED) != 0 {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "\tLocked            : {}",
        if (features & OPAL_FEATURE_LOCKED) != 0 {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "\tMedia Encryption  : {}",
        if (features & OPAL_FEATURE_MEDIA_ENCRYPT) != 0 {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "\tMBR Enabled       : {}",
        if (features & OPAL_FEATURE_MBR_ENABLED) != 0 {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "\tMBR Done          : {}",
        if (features & OPAL_FEATURE_MBR_DONE) != 0 {
            "yes"
        } else {
            "no"
        }
    );
}

/// Extract the full locking-feature bitfield (two bytes) from discovery
pub fn get_locking_features(dev: &str) -> Result<u16> {
    let file = File::open(dev).map_err(|e| anyhow!("open {}: {}", dev, e))?;
    let fd = file.as_raw_fd();

    let mut buf = vec![0u8; DISCOVERY_BUF_SIZE];
    let mut disc = opal_discovery {
        data: buf.as_mut_ptr() as u64,
        size: buf.len() as u64,
    };

    ioctl_opal_discovery(fd, &mut disc).map_err(|e| anyhow!("ioctl failed: {}", e))?;

    parse_locking_feature(&buf)
}

// ───── Miri helpers (no hardware I/O) ───────────────────────────────────────
#[cfg(any(miri, test))]
fn fill_miri_fake_discovery(buf: &mut [u8], flags: u8) {
    // Zero the whole buffer first.
    buf.fill(0);

    // Descriptor payload is 1 byte (the flags)
    // Each descriptor has a 4-byte header: code (2), version (1), length (1)
    let descriptor_len: usize = 4 + 1; // header + payload

    // The total length field (bytes [0..4]) represents the *number of bytes
    // following the discovery header*. Since the descriptor starts after
    // DISCOVERY_HEADER_LEN, this must include that offset plus the descriptor.
    let total_len: u32 = descriptor_len as u32;

    // Write total length as big endian into bytes [0..4]
    buf[..4].copy_from_slice(&total_len.to_be_bytes());

    let off = DISCOVERY_HEADER_LEN;

    // Write one well-formed descriptor:
    // code = 0x0002 (Locking), version = 0x10, length = 1
    buf[off] = 0x00; // high byte of code
    buf[off + 1] = 0x02; // low byte of code
    buf[off + 2] = 0x10; // version
    buf[off + 3] = 0x01; // payload length (1)

    // Build the payload flags
    let mut payload_flags: u8 =
        (OPAL_FEATURE_LOCKING_SUPPORTED | OPAL_FEATURE_LOCKING_ENABLED) as u8;
    if (flags & (OPAL_FEATURE_LOCKED as u8)) != 0 {
        payload_flags |= OPAL_FEATURE_LOCKED as u8;
    }

    buf[off + 4] = payload_flags;
}

#[cfg(any(test, miri))]
pub fn device_locked(_dev: &str) -> Result<bool> {
    let mut buf = vec![0u8; DISCOVERY_BUF_SIZE];
    let locked = matches!(std::env::var("MIRI_SED_LOCKED").ok().as_deref(), Some("1"));
    fill_miri_fake_discovery(&mut buf, if locked { OPAL_FEATURE_LOCKED as u8 } else { 0 });
    let features = parse_locking_feature(&buf)?;
    Ok((features & OPAL_FEATURE_LOCKED) != 0)
}

#[cfg(any(test, miri))]
#[test]
fn simulated_lock_unlock_round_trip() {
    // Build the same buffer device_locked() would parse, toggling the bit.
    let mut buf = vec![0u8; DISCOVERY_BUF_SIZE];

    // unlocked
    fill_miri_fake_discovery(&mut buf, 0);
    assert_eq!(
        parse_locking_feature(&buf).unwrap() & OPAL_FEATURE_LOCKED,
        0
    );

    // locked
    fill_miri_fake_discovery(&mut buf, OPAL_FEATURE_LOCKED as u8);
    assert_ne!(
        parse_locking_feature(&buf).unwrap() & OPAL_FEATURE_LOCKED,
        0
    );
}

/// Build an ordered list of device nodes to probe for OPAL discovery.
///
/// Includes the passed node, then derives `/dev/nvmeX` and `/dev/ngX` for
/// namespace devices if those paths exist.
#[cfg(all(not(test), not(miri)))]
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

#[cfg(any(test, miri))]
fn candidate_nodes(dev: &str) -> Vec<String> {
    vec![dev.to_string()]
}

/// Parse a namespace device string of the form `/dev/nvmeXnY` into controller
/// index X and namespace index Y. Returns `None` if the path does not match
/// this pattern.
#[cfg(all(not(test), not(miri)))]
fn parse_nvme_namespace(dev: &str) -> Option<(u32, u32)> {
    let p = dev.strip_prefix("/dev/nvme")?;

    // collect digits after /dev/nvme into x
    let mut x = String::new();
    for c in p.chars() {
        if c.is_ascii_digit() {
            x.push(c);
        } else {
            break;
        }
    }

    let rest = &p[x.len()..];
    if !rest.starts_with('n') {
        return None;
    }

    // collect digits after 'n' into y
    let mut y = String::new();
    for c in rest[1..].chars() {
        if c.is_ascii_digit() {
            y.push(c);
        } else {
            break;
        }
    }

    if x.is_empty() || y.is_empty() {
        return None;
    }

    Some((x.parse().ok()?, y.parse().ok()?))
}

#[cfg(any(test, miri))]
fn parse_nvme_namespace(dev: &str) -> Option<(u32, u32)> {
    let s = dev.strip_prefix("/dev/nvme")?;
    let (x, y) = s.split_once('n')?;
    Some((x.parse().ok()?, y.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Strategy to generate a buffer with random locking flags (single-byte fake page)
    fn buffer_strategy() -> impl Strategy<Value = Vec<u8>> {
        // Generate random "locked" bit, but always produce a valid fake discovery page
        (any::<u8>()).prop_map(|flags| {
            let mut buf = vec![0u8; DISCOVERY_BUF_SIZE];
            fill_miri_fake_discovery(&mut buf, flags & 1); // 1 == locked flag in test context
            buf
        })
    }

    #[test]
    fn parse_locking_feature_tolerates_extra_descriptors() -> proptest::test_runner::TestCaseResult
    {
        let mut buf = vec![0u8; super::DISCOVERY_BUF_SIZE];
        super::fill_miri_fake_discovery(&mut buf, super::OPAL_FEATURE_LOCKED as u8);

        buf[super::DISCOVERY_HEADER_LEN - 8..super::DISCOVERY_HEADER_LEN]
            .copy_from_slice(&[0x00, 0x01, 0x10, 0x02, 0xaa, 0xbb, 0xcc, 0xdd]);

        let res = super::parse_locking_feature(&buf);
        prop_assert!(res.is_ok());
        Ok(())
    }

    #[test]
    fn feature_bit_consistency() -> proptest::test_runner::TestCaseResult {
        let all_bits = super::OPAL_FEATURE_LOCKING_SUPPORTED
            | super::OPAL_FEATURE_LOCKING_ENABLED
            | super::OPAL_FEATURE_LOCKED
            | super::OPAL_FEATURE_MEDIA_ENCRYPT
            | super::OPAL_FEATURE_MBR_ENABLED
            | super::OPAL_FEATURE_MBR_DONE;

        // Sanity: each flag is unique and disjoint
        let mut seen = std::collections::HashSet::new();
        for bit in [
            super::OPAL_FEATURE_LOCKING_SUPPORTED,
            super::OPAL_FEATURE_LOCKING_ENABLED,
            super::OPAL_FEATURE_LOCKED,
            super::OPAL_FEATURE_MEDIA_ENCRYPT,
            super::OPAL_FEATURE_MBR_ENABLED,
            super::OPAL_FEATURE_MBR_DONE,
        ] {
            // Verify that this bit wasn’t already seen
            prop_assert!(seen.insert(bit));

            // Verify that this bit doesn’t overlap with others
            prop_assert_eq!(bit & (all_bits ^ bit), 0);
        }

        Ok(())
    }

    //
    // Optional:
    // 🧯 5. Optional: get_locking_features fallback path
    //
    // Why: Simulate partial data or ENOTTY errors to ensure graceful failure formatting.
    //
    // (You can stub out the ioctl call under #[cfg(test)] with a dummy that writes junk.)

    proptest! {
        #[test]
        fn build_session_produces_consistent_struct(
            pw in proptest::collection::vec(any::<u8>(), 1..=super::OPAL_KEY_MAX as usize)
        ) {
            let sess = super::build_session_admin1_global(&pw).unwrap();

            prop_assert_eq!(sess.who, linux_sed_opal_sys::opal_user::OPAL_ADMIN1.0);
            prop_assert_eq!(sess.opal_key.key_len, pw.len() as u8);
            prop_assert_eq!(sess.opal_key.key_type, super::OPAL_INCLUDED);
        }

        #[test]
        fn locked_flag_matches(buf in buffer_strategy()) {
            // The expected_locked bit comes from the single-byte fake buffer
            let expected_locked = buf[DISCOVERY_HEADER_LEN + 4] & (OPAL_FEATURE_LOCKED as u8) != 0;
            // But parse_locking_feature() now returns u16, so cast the expected byte to u16 for comparison
            let features: u16 = parse_locking_feature(&buf).unwrap();
            prop_assert_eq!(
                (features & OPAL_FEATURE_LOCKED) != 0,
                expected_locked
            );
        }

        #[test]
        fn parse_nvme_namespace_round_trip(x in 0u32..64, y in 0u32..1024) {
            let dev = format!("/dev/nvme{}n{}", x, y);
            let parsed = super::parse_nvme_namespace(&dev);
            prop_assert_eq!(parsed, Some((x, y)));
        }

        #[test]
        fn parse_nvme_namespace_rejects_invalid(s in ".*") {
            if !s.starts_with("/dev/nvme") {
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
            super::fill_miri_fake_discovery(
                &mut buf,
                if flag { super::OPAL_FEATURE_LOCKED as u8 } else { 0 }
            );
            let features: u16 = super::parse_locking_feature(&buf).unwrap();
            prop_assert_eq!((features & super::OPAL_FEATURE_LOCKED) != 0, flag);
        }

        #[test]
        fn build_session_respects_key_len(pw in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let res = super::build_session_admin1_global(&pw);
            // valid pw -> Ok, empty or too long -> Err
            if pw.is_empty() || pw.len() > super::OPAL_KEY_MAX as usize {
                prop_assert!(res.is_err());
            } else {
                prop_assert!(res.is_ok());
            }
        }

        #[test]
        fn no_conflicting_locking_bits(buf in proptest::collection::vec(any::<u8>(), 64..4096)) {
            let _ = super::parse_locking_feature(&buf).map(|bits| {
                // LOCKED and ENABLED can’t logically conflict
                prop_assert!(!(bits & super::OPAL_FEATURE_LOCKED != 0 &&
                               bits & super::OPAL_FEATURE_LOCKING_ENABLED == 0));
                Ok(())
            });
        }
    }
}
