use assert_cmd::Command;
use predicates::prelude::*;

const REAL_DEVICE_PRIVATE_HEX: &str = "18469d6140447f77de13cd8d761e605431f52269fbff43b0925752ed9e6745435dc6a86d2568af8b70d3365db3f88234760c8ecc645ce469829bc45b65f1d5d5";
const REAL_DEVICE_PUBLIC_HEX: &str =
    "4852B69364572B52EFA1B6BB3E6D0ABED4F389A1CBFBB60A9BBA2CCE649CAF0E";

#[test]
fn generates_key_pair_without_prefix() {
    Command::cargo_bin("meshcore-key-finder")
        .unwrap()
        .arg("-j")
        .arg("1")
        .assert()
        .success()
        .stderr(predicate::str::contains("Generating random key pair"))
        .stdout(predicate::str::contains("Public key:"))
        .stdout(predicate::str::contains("Private key:"));
}

#[test]
fn rejects_invalid_prefix() {
    Command::cargo_bin("meshcore-key-finder")
        .unwrap()
        .arg("GHIJ")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("Error:"));
}

#[test]
fn validates_known_private_key() {
    Command::cargo_bin("meshcore-key-finder")
        .unwrap()
        .arg("--validate")
        .arg(REAL_DEVICE_PRIVATE_HEX)
        .assert()
        .success()
        .stdout(predicate::str::contains("Valid MeshCore private key"))
        .stdout(predicate::str::contains(REAL_DEVICE_PUBLIC_HEX));
}
