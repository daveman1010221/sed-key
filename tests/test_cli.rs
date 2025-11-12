// tests/test_cli.rs
use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn prints_help() {
    let exe = assert_cmd::cargo::cargo_bin!("sed-key");
    Command::new(exe).arg("--help").assert().success();
}

#[test]
fn rejects_missing_device() {
    let exe = assert_cmd::cargo::cargo_bin!("sed-key");
    Command::new(exe).arg("status").assert().failure();
}
