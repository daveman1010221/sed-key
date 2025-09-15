use anyhow::{anyhow, Result};
use linux_sed_opal_sys::*;
use std::fs::File;
use std::os::fd::AsRawFd;

/// Check if device is OPAL-capable
/// Returns:
/// - Ok(true): ioctl succeeded (OPAL support present)
/// - Ok(false): ioctl not supported (definitely not OPAL)
/// - Err(...): ioctl supported but failed in some other way
pub fn is_opal_device(dev: &str) -> Result<bool> {
    let f = File::options().read(true).write(true).open(dev)?;
    let fd = f.as_raw_fd();

    // Prepare a minimal OPAL session
    let sess = opal_session_info {
        sum: 0,
        who: opal_user::OPAL_ADMIN1.0,
        opal_key: Default::default(),
    };

    let mut lock = opal_lock_unlock {
        session: sess,
        l_state: opal_lock_state::OPAL_RW.0,
        flags: 0,
        __align: [0u8; 2],
    };

    match unsafe { ioc_opal_lock_unlock(fd, &lock) } {
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

/// Unlock
pub fn unlock_device(dev: &str, password: &str) -> Result<()> {
    let f = File::options().read(true).write(true).open(dev)?;
    let fd = f.as_raw_fd();

    // Build opal_key from password
    let mut key: opal_key = unsafe { std::mem::zeroed() };
    let pw_bytes = password.as_bytes();
    if pw_bytes.len() > key.key.len() {
        return Err(anyhow!("Password too long for OPAL key buffer"));
    }
    key.key_len = pw_bytes.len() as u8;
    key.key[..pw_bytes.len()].copy_from_slice(pw_bytes);

    // Build opal_session_info
    let mut sess: opal_session_info = unsafe { std::mem::zeroed() };
    sess.sum = 0; // 0 = not single-user mode
    sess.who = opal_user::OPAL_ADMIN1.0; // Admin1 user ID
    sess.opal_key = key;

    // Build opal_lock_unlock
    let mut lock: opal_lock_unlock = unsafe { std::mem::zeroed() };
    lock.session = sess;
    lock.l_state = opal_lock_state::OPAL_RW.0; // RW = unlock
    lock.flags = 0;

    unsafe { ioc_opal_lock_unlock(fd, &lock) }
        .map_err(|e| anyhow!("ioc_opal_lock_unlock: {e}"))?;

    Ok(())
}

/// Lock
pub fn lock_device(dev: &str, password: &str) -> Result<()> {
    let f = File::options().read(true).write(true).open(dev)?;
    let fd = f.as_raw_fd();

    // Build opal_key
    let mut key: opal_key = unsafe { std::mem::zeroed() };
    let pw_bytes = password.as_bytes();
    key.key_len = pw_bytes.len() as u8;
    key.key[..pw_bytes.len()].copy_from_slice(pw_bytes);

    // Build opal_session_info
    let mut sess: opal_session_info = unsafe { std::mem::zeroed() };
    sess.sum = 0;
    sess.who = opal_user::OPAL_ADMIN1.0; // Admin1
    sess.opal_key = key;

    // Build opal_lock_unlock for locked state
    let mut lock: opal_lock_unlock = unsafe { std::mem::zeroed() };
    lock.session = sess;
    lock.l_state = opal_lock_state::OPAL_LK.0; // LK = locked
    lock.flags = 0;

    unsafe { ioc_opal_lock_unlock(fd, &lock) }
        .map_err(|e| anyhow!("ioc_opal_lock_unlock: {e}"))?;

    Ok(())
}
