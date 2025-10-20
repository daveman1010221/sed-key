use proptest::prelude::*;
use sed_key::{do_lock, do_status, do_unlock, use_mock_backend};

proptest! {
    // Reasonable limit so proptests finish quickly
    // #![proptest_config(ProptestConfig {
    //     cases: 64,
    //     max_shrink_time: 0,
    //     .. ProptestConfig::default()
    // })]

    #[test]
    fn do_unlock_handles_various_inputs(
        dev_idx in 0u8..16,
        pw in proptest::string::string_regex(r"[A-Za-z0-9_!@#\$%\^&\*]{0,32}").unwrap(),
    ) {
        use_mock_backend();
        let dev = format!("/dev/nvme{}", dev_idx);

        let key = if pw.is_empty() { None } else { Some(pw.clone()) };
        let result = do_unlock(dev.clone(), key.clone());

        if key.is_none() {
            prop_assert!(result.is_err());
        } else {
            prop_assert!(result.is_ok());
        }
    }

    #[test]
    fn unlock_then_lock_is_idempotent(
        dev_idx in 0u8..16,
        pw in proptest::string::string_regex(r"[A-Za-z0-9_!@#\$%\^&\*]{1,32}").unwrap(),
    ) {
        use_mock_backend();
        let dev = format!("/dev/nvme{}", dev_idx);

        prop_assert!(do_unlock(dev.clone(), Some(pw.clone())).is_ok());
        prop_assert!(do_lock(dev.clone(), Some(pw.clone())).is_ok());
        prop_assert!(do_unlock(dev, Some(pw)).is_ok());
    }

    #[test]
    fn do_lock_and_status_always_succeed(
        dev_idx in 0u8..16,
        pw in proptest::string::string_regex(r"[A-Za-z0-9_!@#\$%\^&\*]{1,32}").unwrap(),
    ) {
        use_mock_backend();
        let dev = format!("/dev/nvme{}", dev_idx);

        prop_assert!(do_lock(dev.clone(), Some(pw.clone())).is_ok());
        prop_assert!(do_status(dev).is_ok());
    }

    #[test]
    fn status_never_panics(dev_idx in 0u8..16) {
        use_mock_backend();
        let dev = format!("/dev/nvme{}", dev_idx);
        let _ = do_status(dev);
    }

    #[test]
    fn empty_password_always_fails(dev_idx in 0u8..16) {
        use_mock_backend();
        let dev = format!("/dev/nvme{}", dev_idx);
        prop_assert!(do_unlock(dev, Some(String::new())).is_err());
    }
}
