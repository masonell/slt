//! Configuration fixtures for testing.
//!
//! Provides `ClientConfig` builders with sensible defaults.

use std::net::Ipv4Addr;
use std::time::Duration;

use slt_core::config::ClientConfig;
use slt_core::types::{
    ClientId, ClientIdentity, ClientNetworkConfig, ClientTimingConfig, ClientTlsConfig,
    PrivKeyEd25519, SharedSecret, TlsMaterial, TunConfig,
};

/// Create a test `ClientConfig` with default values.
///
/// Uses:
/// - Client ID: `[0x11; 16]`
/// - IPv4: `10.10.0.2`
/// - Private key: `[0x33; 32]`
#[must_use]
#[allow(dead_code)]
pub fn test_config() -> ClientConfig {
    test_config_with_identity(
        ClientId([0x11; 16]),
        Ipv4Addr::new(10, 10, 0, 2),
        PrivKeyEd25519([0x33; 32]),
    )
}

/// Create a test config with custom client ID, IPv4, and private key.
#[must_use]
pub fn test_config_with_identity(
    client_id: ClientId,
    ipv4: Ipv4Addr,
    privkey: PrivKeyEd25519,
) -> ClientConfig {
    ClientConfig {
        network: ClientNetworkConfig {
            hostname: "example.com".to_string(),
            port: 443,
            ip: None,
        },
        tls: ClientTlsConfig {
            tls_ca: TlsMaterial::Pem(String::new()),
            quic_ca: None,
        },
        identity: ClientIdentity {
            client_id,
            shared_secret: SharedSecret([0x22; 32]),
            assigned_ipv4: ipv4,
            privkey_ed25519: privkey,
        },
        tun: TunConfig {
            tun_name: "tun0".to_string(),
            tun_mtu: 1280,
        },
        enable_upgrade: false,
        timing: default_timing(),
    }
}

/// Create a test config with custom timing.
#[must_use]
#[allow(dead_code)]
pub fn test_config_with_timing(timing: ClientTimingConfig) -> ClientConfig {
    let mut config = test_config();
    config.timing = timing;
    config
}

/// Default timing configuration for tests.
#[must_use]
pub fn default_timing() -> ClientTimingConfig {
    ClientTimingConfig {
        ping_min: Duration::from_secs(10),
        ping_max: Duration::from_secs(20),
        auth_timeout: Duration::from_secs(10),
        register_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(60),
        reconnect_min: Duration::from_millis(200),
        reconnect_max: Duration::from_secs(5),
    }
}
