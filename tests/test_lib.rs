use sed_key::{do_lock, do_status, do_unlock, use_mock_backend};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn unlock_succeeds_under_mock() {
    use_mock_backend();
    assert!(do_unlock("/dev/nvme0".into(), Some("pw".into())).is_ok());
}

#[test]
fn lock_succeeds_under_mock() {
    use_mock_backend();
    assert!(do_lock("/dev/nvme0".into(), Some("pw".into())).is_ok());
}

#[test]
fn status_succeeds_under_mock() {
    use_mock_backend();
    assert!(do_status("/dev/nvme0".into()).is_ok());
}

#[test]
fn unlock_reads_password_literal() {
    use_mock_backend();
    assert!(do_unlock("/dev/nvme0".into(), Some("literalpw".into())).is_ok());
}

#[test]
fn unlock_reads_password_from_file() {
    use_mock_backend();
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "filepass").unwrap();
    let path = tmp.path().display().to_string();
    assert!(do_unlock("/dev/nvme0".into(), Some(path)).is_ok());
}

#[test]
fn unlock_fails_when_no_key_is_provided() {
    use_mock_backend();
    // Still errors before backend is used (read_key_arg enforces "some key")
    assert!(do_unlock("/dev/nvme0".into(), None).is_err());
}
