use std::{
    path::PathBuf,
    process::{Command, Output},
};
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aegis"))
        .current_dir(root())
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn command_exit_contract() {
    assert_eq!(run(&["inspect", "fixtures/clean"]).status.code(), Some(0));
    assert_eq!(
        run(&[
            "verify",
            "fixtures/clean",
            "--trust-store",
            "fixtures/demo-trust-store.json"
        ])
        .status
        .code(),
        Some(0)
    );
    assert_eq!(run(&["verify", "fixtures/clean"]).status.code(), Some(1));
    assert_eq!(
        run(&[
            "verify",
            "fixtures/tampered",
            "--trust-store",
            "fixtures/demo-trust-store.json"
        ])
        .status
        .code(),
        Some(2)
    );
    assert_eq!(
        run(&[
            "map",
            "fixtures/clean",
            "--trust-store",
            "fixtures/demo-trust-store.json"
        ])
        .status
        .code(),
        Some(1)
    );
    assert_eq!(run(&["inspect", "does-not-exist"]).status.code(), Some(3));
    assert_eq!(
        run(&["verify", "fixtures/partial", "--strict"])
            .status
            .code(),
        Some(1)
    );
}
#[test]
fn schemas_and_json_are_machine_readable() {
    for name in ["evidence", "mapping", "report", "request", "trust-store"] {
        let out = run(&["schema", name]);
        assert!(out.status.success());
        let schema: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(schema["type"], "object");
    }
    let out = run(&[
        "verify",
        "fixtures/clean",
        "--trust-store",
        "fixtures/demo-trust-store.json",
        "--json",
    ]);
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["summary"]["valid"], 10);
    assert!(run(&["inspect", "fixtures/clean", "--quiet"])
        .stdout
        .is_empty());
}
#[test]
fn report_cannot_overwrite_inputs() {
    let before = std::fs::read(root().join("fixtures/clean/inventory.cdx.json")).unwrap();
    let output = run(&[
        "report",
        "fixtures/clean",
        "-o",
        "fixtures/clean/inventory.cdx.json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        before,
        std::fs::read(root().join("fixtures/clean/inventory.cdx.json")).unwrap()
    );
}
