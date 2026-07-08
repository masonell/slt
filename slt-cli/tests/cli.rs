use std::fs;
use std::process::Command;

use slt_core::config::ClientConfig;
use tempfile::TempDir;

fn slt() -> Command {
    Command::new(env!("CARGO_BIN_EXE_slt"))
}

fn write_server_config(dir: &TempDir, port: u16) -> std::path::PathBuf {
    let path = dir.path().join("server.toml");
    let config = format!(
        r#"
server_secret = {{ hex = "0000000000000000000000000000000000000000000000000000000000000001" }}
clients = []

[network]
listen_tcp = "0.0.0.0:{port}"
listen_udp = "0.0.0.0:{port}"
nginx_tcp_upstream = "127.0.0.1:8080"
nginx_udp_upstream = "127.0.0.1:8080"

[tls.tls_cert]
pem = '''-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA test
-----END CERTIFICATE-----'''

[tls.tls_key]
file = "server-key.pem"

[tun]
tun_name = "tun0"
tun_mtu = 1280
tun_ipv4 = "10.10.0.1"
tun_prefix = 24

[timing]
ping_min = "10s"
ping_max = "30s"
auth_timeout = "10s"
idle_timeout = "60s"
metrics_interval = "5m"
"#
    );
    fs::write(&path, config).unwrap();
    path
}

#[test]
fn add_client_command_writes_server_listen_port_to_client_config() {
    let config_dir = TempDir::new().unwrap();
    let output_dir = TempDir::new().unwrap();
    let server_config = write_server_config(&config_dir, 8443);

    let output = slt()
        .args([
            "--quiet",
            "add-client",
            "--config",
            server_config.to_str().unwrap(),
            "--output-dir",
            output_dir.path().to_str().unwrap(),
            "--domain",
            "vpn.example.com",
            "--ip",
            "10.10.0.100",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let client_path = fs::read_dir(output_dir.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let client_toml = fs::read_to_string(client_path).unwrap();
    let client_config = ClientConfig::from_toml_str(&client_toml).unwrap();

    assert_eq!(client_config.network.port, 8443);
}

#[cfg(target_os = "linux")]
#[test]
fn net_down_masquerade_validates_config_before_commands() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("invalid.toml");
    let bin_dir = dir.path().join("bin");
    let log_path = dir.path().join("commands.log");

    fs::write(
        &config_path,
        r#"[tun]
tun_name = ""
tun_mtu = 1406
tun_ipv4 = "10.20.0.17"
tun_prefix = 24
"#,
    )
    .unwrap();

    fs::create_dir(&bin_dir).unwrap();
    for name in ["ip", "nft"] {
        let path = bin_dir.join(name);
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s %s\\n' \"{name}\" \"$*\" >> '{}'\nexit 0\n",
                log_path.display()
            ),
        )
        .unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    let output = slt()
        .args([
            "--quiet",
            "net",
            "down",
            "--config",
            config_path.to_str().unwrap(),
            "--masquerade",
        ])
        .env("PATH", &bin_dir)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid [tun]"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!log_path.exists());
}
