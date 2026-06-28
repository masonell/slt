use slt_core::config::ClientConfig;

use crate::runtime::observer::ClientEvent;
use crate::transport::socket_protector::SocketKind;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SltInteropError {
    #[error("invalid config: {detail}")]
    InvalidConfig { detail: String },
    #[error("invalid argument: {detail}")]
    InvalidArgument { detail: String },
    #[error("session start failed: {detail}")]
    SessionStart { detail: String },
    #[error("platform callback failed: {detail}")]
    Platform { detail: String },
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ClientConfigSummary {
    pub assigned_ipv4: String,
    pub tun_mtu: i32,
    pub server_host: String,
    pub server_port: i32,
    pub client_id: String,
}

impl TryFrom<&ClientConfig> for ClientConfigSummary {
    type Error = SltInteropError;

    fn try_from(config: &ClientConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            assigned_ipv4: config.identity.assigned_ipv4.to_string(),
            tun_mtu: i32::from(config.tun.tun_mtu),
            server_host: config.network.hostname.clone(),
            server_port: i32::from(config.network.port),
            client_id: config.identity.client_id.to_string(),
        })
    }
}

#[uniffi::export(with_foreign)]
pub trait PlatformServices: Send + Sync {
    fn protect_socket(&self, fd: i32, kind: SocketKind) -> bool;

    fn resolve_host(&self, hostname: String) -> Result<Vec<String>, SltInteropError>;
}

/// Foreign callback delivering typed [`ClientEvent`]s from the Rust runtime.
///
/// The event payload is the runtime-owned `ClientEvent` (`handle`, monotonic
/// `seq`, active transport, and a typed `kind`). Kotlin implementations should
/// marshal delivery to the UI/service thread and reject stale events by
/// `handle` / `seq`.
#[uniffi::export(with_foreign)]
pub trait NativeSessionCallback: Send + Sync {
    fn on_event(&self, event: ClientEvent);
}

#[uniffi::export]
pub fn validate_client_config(config_toml: &str) -> Result<ClientConfigSummary, SltInteropError> {
    let config =
        ClientConfig::from_toml_str(config_toml).map_err(|err| SltInteropError::InvalidConfig {
            detail: err.to_string(),
        })?;
    ClientConfigSummary::try_from(&config)
}

#[uniffi::export]
pub fn init_log_sink(file_path: &str) -> bool {
    super::logging::init(file_path)
}

#[uniffi::export]
pub fn start_session(
    config_toml: String,
    tun_fd: i32,
    mtu: i32,
    platform_services: std::sync::Arc<dyn PlatformServices>,
    callback: std::sync::Arc<dyn NativeSessionCallback>,
) -> Result<std::sync::Arc<super::session::NativeSession>, SltInteropError> {
    super::session::start_session(config_toml, tun_fd, mtu, platform_services, callback)
}
