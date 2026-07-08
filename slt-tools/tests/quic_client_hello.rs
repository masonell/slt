use std::process::Command;

#[test]
fn quic_client_hello_rejects_invalid_alpn() {
    let output = Command::new(env!("CARGO_BIN_EXE_quic_client_hello"))
        .args(["127.0.0.1:9", "--alpn", &"a".repeat(256)])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
