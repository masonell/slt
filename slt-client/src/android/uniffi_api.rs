use slt_core::config::ClientConfig;

use crate::runtime::observer::ClientEvent;
use crate::transport::socket_protector::SocketKind;

/// Errors returned through the Android UniFFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SltInteropError {
    /// The supplied client configuration could not be parsed or validated.
    #[error("invalid config: {detail}")]
    InvalidConfig {
        /// Human-readable error detail safe to report to Android.
        detail: String,
    },
    /// A caller supplied an argument that cannot be used by the native runtime.
    #[error("invalid argument: {detail}")]
    InvalidArgument {
        /// Human-readable error detail safe to report to Android.
        detail: String,
    },
    /// The native VPN session failed to start.
    #[error("session start failed: {detail}")]
    SessionStart {
        /// Human-readable error detail safe to report to Android.
        detail: String,
    },
    /// An Android platform callback failed or returned unusable data.
    #[error("platform callback failed: {detail}")]
    Platform {
        /// Human-readable error detail safe to report to Android.
        detail: String,
    },
}

/// Parsed client configuration details exposed to Android before starting a session.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ClientConfigSummary {
    /// IPv4 address assigned to the client tunnel interface.
    pub assigned_ipv4: String,
    /// Tunnel MTU configured for the client.
    pub tun_mtu: i32,
    /// Server hostname from the client network configuration.
    pub server_host: String,
    /// Server TCP/UDP port from the client network configuration.
    pub server_port: i32,
    /// Client identity identifier from the client configuration.
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

/// Android-provided services required by the native transport runtime.
#[uniffi::export(with_foreign)]
pub trait PlatformServices: Send + Sync {
    /// Protect an already-created transport socket before Rust connects or sends.
    ///
    /// The runtime invokes this callback synchronously on the socket setup path.
    /// Android implementations must return promptly and must not block
    /// indefinitely. The implementation should only perform the local
    /// `VpnService.protect(fd)` call and bind the socket to the currently
    /// selected underlying network. Blocking host lookup belongs in
    /// [`Self::resolve_host`], which the runtime invokes on a blocking worker.
    fn protect_socket(&self, fd: i32, kind: SocketKind) -> bool;

    /// Resolve `hostname` through the active Android underlying network.
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
    /// Deliver a native runtime event to the Android session owner.
    fn on_event(&self, event: ClientEvent);
}

/// Parse and validate a client TOML configuration for Android UI previews.
#[uniffi::export]
pub fn validate_client_config(config_toml: &str) -> Result<ClientConfigSummary, SltInteropError> {
    let config =
        ClientConfig::from_toml_str(config_toml).map_err(|err| SltInteropError::InvalidConfig {
            detail: err.to_string(),
        })?;
    ClientConfigSummary::try_from(&config)
}

/// Initialize file-backed native logging for the Android process.
#[uniffi::export]
pub fn init_log_sink(file_path: &str) -> bool {
    super::logging::init(file_path)
}

/// Start a native VPN session using a protected TUN file descriptor.
#[uniffi::export]
pub fn start_session(
    config_toml: &str,
    tun_fd: i32,
    mtu: i32,
    platform_services: std::sync::Arc<dyn PlatformServices>,
    callback: std::sync::Arc<dyn NativeSessionCallback>,
) -> Result<std::sync::Arc<super::session::NativeSession>, SltInteropError> {
    super::session::start_session(config_toml, tun_fd, mtu, platform_services, callback)
}
