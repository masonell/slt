use slt_core::config::ClientConfig;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SltInteropError {
    #[error("invalid config: {detail}")]
    InvalidConfig { detail: String },
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

#[uniffi::export]
pub fn validate_client_config(config_toml: String) -> Result<ClientConfigSummary, SltInteropError> {
    let config = ClientConfig::from_toml_str(&config_toml).map_err(|err| {
        SltInteropError::InvalidConfig {
            detail: err.to_string(),
        }
    })?;
    ClientConfigSummary::try_from(&config)
}
