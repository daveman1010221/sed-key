use anyhow::{anyhow, Result};
use linux_sed_opal_sys::*;
use std::fs::File;
use std::os::fd::AsRawFd;

const OPAL_INCLUDED: u8 = 0; // key_type: key bytes included in opal_key.key

/// Check if device is OPAL-capable
/// Returns:
/// - Ok(true): ioctl succeeded (OPAL support present)
/// - Ok(false): ioctl not supported (definitely not OPAL)
/// - Err(...): ioctl supported but failed in some other way
pub fn is_opal_device(dev: &str) -> Result<bool> {
    let f = File::options().read(true).write(true).open(dev)?;
    let fd = f.as_raw_fd();

    // Minimal but valid structure: non-zero key_len avoids EINVAL-as-probe.
    let mut sess = opal_session_info::default();
    sess.sum = 0;
    sess.who = opal_user::OPAL_ADMIN1.0;
    sess.opal_key.lr = 0;
    sess.opal_key.key_type = OPAL_INCLUDED;
    sess.opal_key.key_len = 1;
    sess.opal_key.key[0] = 0;

    let mut op = opal_lock_unlock::default();
    op.session = sess;
    op.l_state = opal_lock_state::OPAL_RW.0;
    op.flags = 0;

    match unsafe { ioc_opal_lock_unlock(fd, &op) } {
        Ok(_) => Ok(true), // ioctl succeeded → OPAL capable
        Err(errno) => {
            let code: i32 = errno as i32;
            if code == libc::ENOTTY {
                Ok(false) // ioctl not supported → not OPAL
            } else {
                Err(anyhow!("unlock ioctl failed with errno {:?}", errno))
            }
        }
    }
}

#[inline]
fn build_session_admin1_global(pw: &[u8]) -> Result<opal_session_info> {
    if pw.is_empty() {
        return Err(anyhow!("empty password"));
    }
    let mut sess = opal_session_info::default();
    sess.sum = 0;
    sess.who = opal_user::OPAL_ADMIN1.0;
    sess.opal_key.lr = 0; // LR0 = global
    sess.opal_key.key_type = OPAL_INCLUDED;
    let n = std::cmp::min(pw.len(), OPAL_KEY_MAX as usize) as u8;
    sess.opal_key.key_len = n;
    sess.opal_key.key[..n as usize].copy_from_slice(&pw[..n as usize]);
    Ok(sess)
}

/// Unlock
pub fn unlock_device(dev: &str, password: &str) -> Result<()> {

    let f = File::options().read(true).write(true).open(dev)
        .map_err(|e| anyhow!("open {}: {}", dev, e))?;

    let fd = f.as_raw_fd();

    // Build opal_session_info from the password
    let sess = build_session_admin1_global(password.as_bytes())?;

    let mut op = opal_lock_unlock::default();
    op.session = sess;
    op.l_state = opal_lock_state::OPAL_RW.0; // unlock = RW
    op.flags = 0;

    unsafe { ioc_opal_lock_unlock(fd, &op) }
        .map_err(|e| anyhow!("unlock ioctl failed with {:?}", e))?;

    Ok(())
}

/// Lock
pub fn lock_device(dev: &str, password: &str) -> Result<()> {

    let f = File::options().read(true).write(true).open(dev)
        .map_err(|e| anyhow!("open {}: {}", dev, e))?;

    let fd = f.as_raw_fd();

    // Build opal_session_info from the password
    let sess = build_session_admin1_global(password.as_bytes())?;

    let mut op = opal_lock_unlock::default();
    op.session = sess;
    op.l_state = opal_lock_state::OPAL_LK.0; // lock
    op.flags = 0; // set to opal_lock_flags::OPAL_SAVE_FOR_LOCK.0 if you *want* persistence

    unsafe { ioc_opal_lock_unlock(fd, &op) }
        .map_err(|e| anyhow!("lock ioctl failed with {:?}", e))?;

    Ok(())
}
