use slt_core::config::ClientConfig;

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

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum SocketKind {
    Tcp,
    Udp,
}

impl From<crate::transport::socket_protector::SocketKind> for SocketKind {
    fn from(kind: crate::transport::socket_protector::SocketKind) -> Self {
        match kind {
            crate::transport::socket_protector::SocketKind::Tcp => Self::Tcp,
            crate::transport::socket_protector::SocketKind::Udp => Self::Udp,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum NativeEventKind {
    Starting,
    Ready,
    Stopping,
    Stopped,
    Error,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct NativeEvent {
    pub session_handle: i64,
    pub seq: i64,
    pub kind: NativeEventKind,
    pub detail: Option<String>,
}

#[uniffi::export(with_foreign)]
pub trait PlatformServices: Send + Sync {
    fn protect_socket(&self, fd: i32, kind: SocketKind) -> bool;

    fn resolve_host(&self, hostname: String) -> Result<Vec<String>, SltInteropError>;
}

#[uniffi::export(with_foreign)]
pub trait NativeSessionCallback: Send + Sync {
    fn on_event(&self, event: NativeEvent);
}

#[uniffi::export]
pub fn validate_client_config(config_toml: String) -> Result<ClientConfigSummary, SltInteropError> {
    let config = ClientConfig::from_toml_str(&config_toml).map_err(|err| {
        SltInteropError::InvalidConfig {
            detail: err.to_string(),
        }
    })?;
    ClientConfigSummary::try_from(&config)
}

#[uniffi::export]
pub fn init_log_sink(file_path: String) -> bool {
    super::logging::init(&file_path)
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
