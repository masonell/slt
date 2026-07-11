//! Static transport and direction rules for protocol messages.

use super::MessageType;

/// Endpoint that sent a protocol message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSender {
    /// The VPN client sent the message.
    Client,
    /// The VPN server sent the message.
    Server,
}

/// Returns whether a message type may be sent over UDP-QSP by `sender`.
///
/// This enforces the transport and direction rules shared by both endpoints.
/// Stateful checks, such as matching an active UDP upgrade identifier, remain
/// the responsibility of the endpoint session state machine.
#[must_use]
pub const fn is_message_allowed_on_udp_qsp(
    message_type: MessageType,
    sender: MessageSender,
) -> bool {
    match sender {
        MessageSender::Client => match message_type {
            MessageType::Ping
            | MessageType::Pong
            | MessageType::Close
            | MessageType::Data
            | MessageType::UpgradeProbe => true,
            MessageType::Auth
            | MessageType::AuthOk
            | MessageType::AuthFail
            | MessageType::RegisterCid
            | MessageType::RegisterOk
            | MessageType::RegisterFail
            | MessageType::UpgradeProbeAck
            | MessageType::UdpReady
            | MessageType::SwitchToUdp
            | MessageType::SwitchAck
            | MessageType::FallbackToTcp
            | MessageType::FallbackOk
            | MessageType::SwitchOk => false,
        },
        MessageSender::Server => match message_type {
            MessageType::Ping
            | MessageType::Pong
            | MessageType::Close
            | MessageType::Data
            | MessageType::UpgradeProbeAck => true,
            MessageType::Auth
            | MessageType::AuthOk
            | MessageType::AuthFail
            | MessageType::RegisterCid
            | MessageType::RegisterOk
            | MessageType::RegisterFail
            | MessageType::UpgradeProbe
            | MessageType::UdpReady
            | MessageType::SwitchToUdp
            | MessageType::SwitchAck
            | MessageType::FallbackToTcp
            | MessageType::FallbackOk
            | MessageType::SwitchOk => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_MESSAGE_TYPES: [MessageType; 18] = [
        MessageType::Auth,
        MessageType::AuthOk,
        MessageType::AuthFail,
        MessageType::RegisterCid,
        MessageType::RegisterOk,
        MessageType::RegisterFail,
        MessageType::Ping,
        MessageType::Pong,
        MessageType::Close,
        MessageType::Data,
        MessageType::UpgradeProbe,
        MessageType::UpgradeProbeAck,
        MessageType::UdpReady,
        MessageType::SwitchToUdp,
        MessageType::SwitchAck,
        MessageType::FallbackToTcp,
        MessageType::FallbackOk,
        MessageType::SwitchOk,
    ];

    fn assert_allowlist(sender: MessageSender, allowed: &[MessageType]) {
        for message_type in ALL_MESSAGE_TYPES {
            assert_eq!(
                is_message_allowed_on_udp_qsp(message_type, sender),
                allowed.contains(&message_type),
                "unexpected UDP-QSP admissibility for {sender:?} {message_type:?}",
            );
        }
    }

    #[test]
    fn client_udp_qsp_allowlist_matches_protocol() {
        assert_allowlist(
            MessageSender::Client,
            &[
                MessageType::Data,
                MessageType::Ping,
                MessageType::Pong,
                MessageType::Close,
                MessageType::UpgradeProbe,
            ],
        );
    }

    #[test]
    fn server_udp_qsp_allowlist_matches_protocol() {
        assert_allowlist(
            MessageSender::Server,
            &[
                MessageType::Data,
                MessageType::Ping,
                MessageType::Pong,
                MessageType::Close,
                MessageType::UpgradeProbeAck,
            ],
        );
    }
}
