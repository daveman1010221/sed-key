#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]

mod bindings;
pub use bindings::*;

use nix::ioctl_write_ptr;

#[cfg(any(feature = "linux_6_1", feature = "linux_6_4"))]
use nix::ioctl_read_buf;

ioctl_write_ptr!(ioc_opal_save, b'p', 220, opal_lock_unlock);
ioctl_write_ptr!(ioc_opal_lock_unlock, b'p', 221, opal_lock_unlock);
ioctl_write_ptr!(ioc_opal_take_ownership, b'p', 222, opal_key);
ioctl_write_ptr!(ioc_opal_activate_lsp, b'p', 223, opal_lr_act);
ioctl_write_ptr!(ioc_opal_set_pw, b'p', 224, opal_new_pw);
ioctl_write_ptr!(ioc_opal_activate_usr, b'p', 225, opal_session_info);
ioctl_write_ptr!(ioc_opal_revert_tpr, b'p', 226, opal_key);
ioctl_write_ptr!(ioc_opal_lr_setup, b'p', 227, opal_user_lr_setup);
ioctl_write_ptr!(ioc_opal_add_usr_to_lr, b'p', 228, opal_lock_unlock);
ioctl_write_ptr!(ioc_opal_enable_disable_mbr, b'p', 229, opal_mbr_data);
ioctl_write_ptr!(ioc_opal_erase_lr, b'p', 230, opal_session_info);
ioctl_write_ptr!(ioc_opal_secure_erase_lr, b'p', 231, opal_session_info);
ioctl_write_ptr!(ioc_opal_psid_revert_tpr, b'p', 232, opal_key);
ioctl_write_ptr!(ioc_opal_mbr_done, b'p', 233, opal_mbr_done);
ioctl_write_ptr!(ioc_opal_write_shadow_mbr, b'p', 234, opal_shadow_mbr);
ioctl_write_ptr!(ioc_opal_generic_table_rw, b'p', 235, opal_read_write_table);

#[cfg(feature = "linux_6_1")]
ioctl_read_buf!(ioc_opal_get_status, b'p', 236, opal_status);

cfg_if::cfg_if! {
    if #[cfg(feature="linux_6_4")] {
        ioctl_write_ptr!(ioc_opal_get_lr_status, b'p', 237, opal_lr_status);
        ioctl_read_buf!(ioc_opal_get_geometry, b'p', 238, opal_geometry);
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature="linux_6_6")] {
        ioctl_write_ptr!(ioc_opal_discovery, b'p', 239, opal_discovery);
        ioctl_write_ptr!(ioc_opal_revert_lsp, b'p', 240, opal_revert_lsp);
    }
}
// ─────────────────────────────────────────────────────────────
// Trait and enum wrappers for Rust-friendly usage
// ─────────────────────────────────────────────────────────────

use core::mem::zeroed;

macro_rules! impl_default_zeroed {
    ($($t:ty),+ $(,)?) => {
        $(
            impl Default for $t {
                fn default() -> Self { unsafe { zeroed() } }
            }
        )+
    };
}

impl_default_zeroed!(
    opal_key,
    opal_session_info,
    opal_lock_unlock,
    opal_new_pw,
    opal_user_lr_setup,
    opal_lr_act,
    opal_mbr_data,
    opal_mbr_done,
    opal_shadow_mbr,
    opal_read_write_table,
    opal_status,
    opal_geometry,
    opal_discovery,
    opal_revert_lsp,
    opal_lr_status,
);

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OpalUser {
    Admin1 = opal_user_OPAL_ADMIN1,
    User1 = opal_user_OPAL_USER1,
    User2 = opal_user_OPAL_USER2,
    User3 = opal_user_OPAL_USER3,
    User4 = opal_user_OPAL_USER4,
    User5 = opal_user_OPAL_USER5,
    User6 = opal_user_OPAL_USER6,
    User7 = opal_user_OPAL_USER7,
    User8 = opal_user_OPAL_USER8,
    User9 = opal_user_OPAL_USER9,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OpalLockState {
    Ro = opal_lock_state_OPAL_RO,
    Rw = opal_lock_state_OPAL_RW,
    Lk = opal_lock_state_OPAL_LK,
}

