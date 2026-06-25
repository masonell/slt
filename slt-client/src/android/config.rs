use jni::JNIEnv;
use jni::objects::JString;
use slt_core::config::ClientConfig;

pub(super) fn validate_client_config(
    env: &mut JNIEnv<'_>,
    config_toml: &JString<'_>,
) -> Result<String, String> {
    let raw_config: String = env
        .get_string(config_toml)
        .map_err(|err| format!("read config TOML from JNI: {err}"))?
        .into();
    let config = ClientConfig::from_toml_str(&raw_config)
        .map_err(|err| format!("validate client config: {err}"))?;
    Ok(client_config_summary_json(&config))
}

fn client_config_summary_json(config: &ClientConfig) -> String {
    format!(
        r#"{{"assignedIpv4":"{}","tunMtu":{},"serverHost":"{}","serverPort":{},"clientId":"{}"}}"#,
        json_escape(&config.identity.assigned_ipv4.to_string()),
        config.tun.tun_mtu,
        json_escape(&config.network.hostname),
        config.network.port,
        json_escape(&config.identity.client_id.to_string()),
    )
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
