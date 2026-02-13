//! Common types used across the codebase.

pub mod cid;
pub mod client_config;
pub mod client_id;
pub mod ed25519;
pub mod serde;
pub mod server_config;
pub mod shared_secret;
pub mod tls_material;
pub mod tun_config;

pub use cid::{Cid, CidPrefix, MAX_DCID_LEN, QUIC_DCID_PREFIX_LEN};
pub use client_config::{ClientIdentity, ClientNetworkConfig, ClientTimingConfig, ClientTlsConfig};
pub use client_id::ClientId;
pub use ed25519::{PrivKeyEd25519, PubKeyEd25519};
pub use server_config::{ServerClient, ServerNetworkConfig, ServerTimingConfig, ServerTlsConfig};
pub use shared_secret::SharedSecret;
pub use tls_material::TlsMaterial;
pub use tun_config::TunConfig;
