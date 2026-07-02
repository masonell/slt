//! Linux network setup command.

use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use slt_core::types::TunConfig;

const NFT_TABLE: &str = "slt";

#[derive(Debug, Deserialize)]
struct TunConfigFile {
    tun: TunConfig,
}

/// Create and configure the TUN interface from a config file's `[tun]` section.
///
/// # Errors
///
/// Returns an error if the config cannot be read or parsed, or if any network
/// setup command fails.
pub fn up(
    config_path: &Path,
    user: Option<&str>,
    group: Option<&str>,
    ipv4_forward: bool,
    masquerade: bool,
    quiet: bool,
) -> Result<()> {
    let tun = load_tun_config(config_path)?;
    delete_tun_if_exists(&tun.tun_name);
    add_tun(&tun.tun_name, user, group)?;
    run_command(
        "ip",
        &[
            "addr".to_string(),
            "replace".to_string(),
            tun_addr_cidr(&tun),
            "dev".to_string(),
            tun.tun_name.clone(),
        ],
    )?;
    run_command(
        "ip",
        &[
            "link".to_string(),
            "set".to_string(),
            "dev".to_string(),
            tun.tun_name.clone(),
            "mtu".to_string(),
            tun.tun_mtu.to_string(),
        ],
    )?;
    run_command(
        "ip",
        &[
            "link".to_string(),
            "set".to_string(),
            "dev".to_string(),
            tun.tun_name.clone(),
            "up".to_string(),
        ],
    )?;

    if ipv4_forward {
        run_command("sysctl", &sysctl_ipv4_forward_args(quiet))?;
    }

    if masquerade {
        replace_nft_table(&tun)?;
    }

    if !quiet {
        println!(
            "slt net: {} up ({}, mtu {})",
            tun.tun_name,
            tun_addr_cidr(&tun),
            tun.tun_mtu
        );
    }

    Ok(())
}

/// Remove the TUN interface from a config file's `[tun]` section.
///
/// # Errors
///
/// Returns an error if the config cannot be read or parsed.
pub fn down(config_path: &Path, masquerade: bool, quiet: bool) -> Result<()> {
    if masquerade {
        delete_nft_table_if_exists();
    }

    let tun = load_tun_config(config_path)?;
    run_command_ignore_error(
        "ip",
        &[
            "link".to_string(),
            "set".to_string(),
            "dev".to_string(),
            tun.tun_name.clone(),
            "down".to_string(),
        ],
    );
    delete_tun_if_exists(&tun.tun_name);

    if !quiet {
        println!("slt net: {} down", tun.tun_name);
    }

    Ok(())
}

fn load_tun_config(path: &Path) -> Result<TunConfig> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let config: TunConfigFile = toml::from_str(&contents)
        .with_context(|| format!("failed to parse [tun] from {}", path.display()))?;
    config
        .tun
        .validate()
        .with_context(|| format!("invalid [tun] in {}", path.display()))?;
    Ok(config.tun)
}

fn add_tun(name: &str, user: Option<&str>, group: Option<&str>) -> Result<()> {
    let mut args = vec![
        "tuntap".to_string(),
        "add".to_string(),
        "dev".to_string(),
        name.to_string(),
        "mode".to_string(),
        "tun".to_string(),
    ];
    if let Some(user) = user {
        args.push("user".to_string());
        args.push(user.to_string());
    }
    if let Some(group) = group {
        args.push("group".to_string());
        args.push(group.to_string());
    }
    run_command("ip", &args)
}

fn delete_tun_if_exists(name: &str) {
    run_command_ignore_error(
        "ip",
        &[
            "tuntap".to_string(),
            "del".to_string(),
            "dev".to_string(),
            name.to_string(),
            "mode".to_string(),
            "tun".to_string(),
        ],
    );
}

fn replace_nft_table(tun: &TunConfig) -> Result<()> {
    delete_nft_table_if_exists();

    let quoted_tun_name = nft_string_literal(&tun.tun_name)?;
    let rules = format!(
        r"table inet {NFT_TABLE} {{
    chain slt_forward {{
        type filter hook forward priority 0; policy accept;
        iifname {quoted_tun_name} accept
        oifname {quoted_tun_name} accept
    }}
    chain slt_postrouting {{
        type nat hook postrouting priority 100; policy accept;
        ip saddr {} masquerade
    }}
}}
",
        tun_subnet_cidr(tun),
    );

    run_command_with_stdin("nft", &["-f".to_string(), "-".to_string()], &rules)
}

fn delete_nft_table_if_exists() {
    run_command_ignore_error(
        "nft",
        &[
            "delete".to_string(),
            "table".to_string(),
            "inet".to_string(),
            NFT_TABLE.to_string(),
        ],
    );
}

fn run_command(program: &str, args: &[String]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to execute {}", display_command(program, args)))?;
    if !status.success() {
        bail!(
            "{} failed with status {status}",
            display_command(program, args)
        );
    }
    Ok(())
}

fn sysctl_ipv4_forward_args(quiet: bool) -> Vec<String> {
    let mut args = Vec::with_capacity(3);
    if quiet {
        args.push("-q".to_string());
    }
    args.push("-w".to_string());
    args.push("net.ipv4.ip_forward=1".to_string());
    args
}

fn run_command_with_stdin(program: &str, args: &[String], stdin: &str) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute {}", display_command(program, args)))?;

    let mut child_stdin = child.stdin.take().context("failed to open child stdin")?;
    child_stdin.write_all(stdin.as_bytes()).with_context(|| {
        format!(
            "failed to write rules to {}",
            display_command(program, args)
        )
    })?;
    drop(child_stdin);

    let status = child
        .wait()
        .with_context(|| format!("failed to wait for {}", display_command(program, args)))?;
    if !status.success() {
        bail!(
            "{} failed with status {status}",
            display_command(program, args)
        );
    }
    Ok(())
}

fn run_command_ignore_error(program: &str, args: &[String]) {
    let _ = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn display_command(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

fn tun_addr_cidr(tun: &TunConfig) -> String {
    format!("{}/{}", tun.tun_ipv4, tun.tun_prefix)
}

fn tun_subnet_cidr(tun: &TunConfig) -> String {
    format!(
        "{}/{}",
        ipv4_network_addr(tun.tun_ipv4, tun.tun_prefix),
        tun.tun_prefix
    )
}

fn ipv4_network_addr(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let raw = u32::from(addr);
    let mask = u32::MAX << (32 - u32::from(prefix));
    Ipv4Addr::from(raw & mask)
}

fn nft_string_literal(value: &str) -> Result<String> {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for ch in value.chars() {
        match ch {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            _ if ch.is_control() => bail!("nftables string contains a control character"),
            _ => quoted.push(ch),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    fn write_temp_file(contents: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents).unwrap();
        file
    }

    #[test]
    fn loads_shared_tun_section() {
        let file = write_temp_file(
            br#"[tun]
tun_name = "tun9"
tun_mtu = 1406
tun_ipv4 = "10.20.0.17"
tun_prefix = 24
"#,
        );

        let tun = load_tun_config(file.path()).unwrap();

        assert_eq!(tun.tun_name, "tun9");
        assert_eq!(tun.tun_mtu, 1406);
        assert_eq!(tun.tun_ipv4, Ipv4Addr::new(10, 20, 0, 17));
        assert_eq!(tun.tun_prefix, 24);
    }

    #[test]
    fn rejects_invalid_tun_section() {
        let file = write_temp_file(
            br#"[tun]
tun_name = ""
tun_mtu = 1406
tun_ipv4 = "10.20.0.17"
tun_prefix = 24
"#,
        );

        let err = load_tun_config(file.path()).unwrap_err();

        assert!(err.to_string().contains("invalid [tun]"));
    }

    #[test]
    fn formats_tun_address_cidr() {
        let tun = TunConfig {
            tun_name: "tun0".to_string(),
            tun_mtu: 1406,
            tun_ipv4: Ipv4Addr::new(10, 20, 0, 17),
            tun_prefix: 24,
        };

        assert_eq!(tun_addr_cidr(&tun), "10.20.0.17/24");
    }

    #[test]
    fn formats_tun_subnet_cidr() {
        let tun = TunConfig {
            tun_name: "tun0".to_string(),
            tun_mtu: 1406,
            tun_ipv4: Ipv4Addr::new(10, 20, 0, 17),
            tun_prefix: 24,
        };

        assert_eq!(tun_subnet_cidr(&tun), "10.20.0.0/24");
    }

    #[test]
    fn quotes_nft_string_literal() {
        assert_eq!(nft_string_literal(r#"tun"0\"#).unwrap(), r#""tun\"0\\""#);
    }

    #[test]
    fn rejects_control_chars_in_nft_string_literal() {
        let err = nft_string_literal("tun\n0").unwrap_err();

        assert!(
            err.to_string()
                .contains("nftables string contains a control character")
        );
    }

    #[test]
    fn quiet_sysctl_args_suppress_output() {
        assert_eq!(
            sysctl_ipv4_forward_args(true),
            vec!["-q", "-w", "net.ipv4.ip_forward=1"]
        );
        assert_eq!(
            sysctl_ipv4_forward_args(false),
            vec!["-w", "net.ipv4.ip_forward=1"]
        );
    }

    #[test]
    fn run_command_with_stdin_closes_pipe_before_waiting() {
        let args = vec![
            "1".to_string(),
            "sh".to_string(),
            "-c".to_string(),
            "cat >/dev/null".to_string(),
        ];

        run_command_with_stdin("timeout", &args, "rules\n").unwrap();
    }
}
