// tests/cli.rs
use assert_cmd::Command;

#[test]
fn prints_help() {
    let mut cmd = Command::cargo_bin("sed-key").unwrap();
    cmd.arg("docs").assert().success();
}

#[test]
fn rejects_missing_device() {
    let mut cmd = Command::cargo_bin("sed-key").unwrap();
    cmd.arg("status").assert().failure();
}
