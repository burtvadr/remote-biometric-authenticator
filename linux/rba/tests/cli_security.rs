//! CLI regressions that do not require a daemon or real credentials.
use std::process::Command;

#[test]
fn pairing_code_argument_is_not_supported() {
    let result = Command::new(env!("CARGO_BIN_EXE_rba"))
        .args(["pair", "--code", "000000"])
        .output()
        .expect("run CLI");
    assert_eq!(result.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("unknown option"));
    assert!(!stderr.contains("000000"));
}
