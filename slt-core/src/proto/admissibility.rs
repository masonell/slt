//! Shared admissibility and fixed-payload validation for protocol messages.

use super::{
    AuthFailPayload, AuthOkPayload, AuthPayload, ClosePayload, FallbackOkPayload,
    FallbackToTcpPayload, Message, MessageType, PayloadError, PingPayload, PongPayload,
    RegisterFailPayload, RegisterOkPayload, SwitchAckPayload, SwitchOkPayload, SwitchToUdpPayload,
    UdpReadyPayload, UpgradeProbeAckPayload, UpgradeProbePayload,
};

/// Endpoint that sent a protocol message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSender {
    /// The VPN client sent the message.
    Client,
    /// The VPN server sent the message.
    Server,
}

/// Broad protocol phase in which a message was received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolPhase {
    /// TLS is established, but VPN authentication has not completed.
    Authentication,
    /// The VPN session is authenticated.
    Established,
}

/// Transport that carried a protocol message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageTransport {
    /// TLS-protected TCP control/data channel.
    Tcp,
    /// UDP-QSP protected data channel.
    UdpQsp,
}

/// Wire-invariant context for validating an inbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageContext {
    /// Endpoint that sent the message.
    pub sender: MessageSender,
    /// Authentication phase in which the message was received.
    pub phase: ProtocolPhase,
    /// Transport that carried the message.
    pub transport: MessageTransport,
}

impl MessageContext {
    /// Construct a message validation context.
    #[must_use]
    pub const fn new(
        sender: MessageSender,
        phase: ProtocolPhase,
        transport: MessageTransport,
    ) -> Self {
        Self {
            sender,
            phase,
            transport,
        }
    }
}

/// Failure to validate a message against shared wire-protocol invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MessageValidationError {
    /// The message type is not valid from the endpoint that sent it.
    #[error("{message_type:?} cannot be sent by {sender:?}")]
    InvalidDirection {
        /// Rejected message type.
        message_type: MessageType,
        /// Endpoint that sent the message.
        sender: MessageSender,
    },
    /// The message type is not valid in the current authentication phase.
    #[error("{message_type:?} is not valid during {phase:?}")]
    InvalidPhase {
        /// Rejected message type.
        message_type: MessageType,
        /// Phase in which the message was received.
        phase: ProtocolPhase,
    },
    /// The message type is not valid on the transport that carried it.
    #[error("{message_type:?} is not valid on {transport:?}")]
    InvalidTransport {
        /// Rejected message type.
        message_type: MessageType,
        /// Transport that carried the message.
        transport: MessageTransport,
    },
    /// A fixed-layout control payload did not match its wire schema.
    #[error("invalid {message_type:?} payload: {source}")]
    InvalidPayload {
        /// Message type whose payload was rejected.
        message_type: MessageType,
        /// Schema validation failure.
        #[source]
        source: PayloadError,
    },
}

impl MessageValidationError {
    /// Return the rejected message type.
    #[must_use]
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::InvalidDirection { message_type, .. }
            | Self::InvalidPhase { message_type, .. }
            | Self::InvalidTransport { message_type, .. }
            | Self::InvalidPayload { message_type, .. } => message_type,
        }
    }
}

/// Validate message direction, phase, transport, and fixed payload schema.
///
/// Stateful checks, such as matching an active registration or UDP upgrade
/// identifier, remain the responsibility of the endpoint session state
/// machine. `REGISTER_CID` is also decoded by the server registration handler
/// because its variable layout maps malformed fields to protocol-level
/// `REGISTER_FAIL` responses. `DATA` payload bounds are enforced while decoding
/// the message frame.
///
/// # Errors
///
/// Returns [`MessageValidationError`] when the message violates a shared
/// direction, phase, transport, or fixed-layout payload invariant.
pub fn validate_message(
    message: Message<'_>,
    context: MessageContext,
) -> Result<(), MessageValidationError> {
    validate_message_type(message.ty(), context)?;
    validate_fixed_payload(message)
}

/// Validate the direction, phase, and transport of a message type.
///
/// Use [`validate_message`] for inbound messages so fixed-layout payloads are
/// validated as well.
///
/// # Errors
///
/// Returns [`MessageValidationError`] for the first violated admissibility
/// invariant, checked in direction, phase, then transport order.
pub const fn validate_message_type(
    message_type: MessageType,
    context: MessageContext,
) -> Result<(), MessageValidationError> {
    if !is_valid_direction(message_type, context.sender) {
        return Err(MessageValidationError::InvalidDirection {
            message_type,
            sender: context.sender,
        });
    }
    if !is_valid_phase(message_type, context.phase) {
        return Err(MessageValidationError::InvalidPhase {
            message_type,
            phase: context.phase,
        });
    }
    if !is_valid_transport(message_type, context.transport) {
        return Err(MessageValidationError::InvalidTransport {
            message_type,
            transport: context.transport,
        });
    }
    Ok(())
}

const fn is_valid_direction(message_type: MessageType, sender: MessageSender) -> bool {
    match sender {
        MessageSender::Client => matches!(
            message_type,
            MessageType::Auth
                | MessageType::RegisterCid
                | MessageType::Ping
                | MessageType::Pong
                | MessageType::Close
                | MessageType::Data
                | MessageType::UpgradeProbe
                | MessageType::UdpReady
                | MessageType::SwitchAck
                | MessageType::FallbackToTcp
                | MessageType::FallbackOk
        ),
        MessageSender::Server => matches!(
            message_type,
            MessageType::AuthOk
                | MessageType::AuthFail
                | MessageType::RegisterOk
                | MessageType::RegisterFail
                | MessageType::Ping
                | MessageType::Pong
                | MessageType::Close
                | MessageType::Data
                | MessageType::UpgradeProbeAck
                | MessageType::SwitchToUdp
                | MessageType::FallbackToTcp
                | MessageType::FallbackOk
                | MessageType::SwitchOk
        ),
    }
}

const fn is_valid_phase(message_type: MessageType, phase: ProtocolPhase) -> bool {
    match phase {
        ProtocolPhase::Authentication => matches!(
            message_type,
            MessageType::Auth
                | MessageType::AuthOk
                | MessageType::AuthFail
                | MessageType::Ping
                | MessageType::Pong
                | MessageType::Close
        ),
        ProtocolPhase::Established => !matches!(
            message_type,
            MessageType::Auth | MessageType::AuthOk | MessageType::AuthFail
        ),
    }
}

const fn is_valid_transport(message_type: MessageType, transport: MessageTransport) -> bool {
    match transport {
        MessageTransport::Tcp => !matches!(
            message_type,
            MessageType::UpgradeProbe | MessageType::UpgradeProbeAck
        ),
        MessageTransport::UdpQsp => matches!(
            message_type,
            MessageType::Ping
                | MessageType::Pong
                | MessageType::Close
                | MessageType::Data
                | MessageType::UpgradeProbe
                | MessageType::UpgradeProbeAck
        ),
    }
}

fn validate_fixed_payload(message: Message<'_>) -> Result<(), MessageValidationError> {
    let message_type = message.ty();
    let result = match message {
        Message::Auth { payload } => AuthPayload::decode(payload).map(|_| ()),
        Message::AuthOk { payload } => AuthOkPayload::decode(payload).map(|_| ()),
        Message::AuthFail { payload } => AuthFailPayload::decode(payload).map(|_| ()),
        Message::RegisterCid { .. } | Message::Data { .. } => return Ok(()),
        Message::RegisterOk { payload } => RegisterOkPayload::decode(payload).map(|_| ()),
        Message::RegisterFail { payload } => RegisterFailPayload::decode(payload).map(|_| ()),
        Message::Ping { payload } => PingPayload::decode(payload).map(|_| ()),
        Message::Pong { payload } => PongPayload::decode(payload).map(|_| ()),
        Message::Close { payload } => ClosePayload::decode(payload).map(|_| ()),
        Message::UpgradeProbe { payload } => UpgradeProbePayload::decode(payload).map(|_| ()),
        Message::UpgradeProbeAck { payload } => UpgradeProbeAckPayload::decode(payload).map(|_| ()),
        Message::UdpReady { payload } => UdpReadyPayload::decode(payload).map(|_| ()),
        Message::SwitchToUdp { payload } => SwitchToUdpPayload::decode(payload).map(|_| ()),
        Message::SwitchAck { payload } => SwitchAckPayload::decode(payload).map(|_| ()),
        Message::FallbackToTcp { payload } => FallbackToTcpPayload::decode(payload).map(|_| ()),
        Message::FallbackOk { payload } => FallbackOkPayload::decode(payload).map(|_| ()),
        Message::SwitchOk { payload } => SwitchOkPayload::decode(payload).map(|_| ()),
    };

    result.map_err(|source| MessageValidationError::InvalidPayload {
        message_type,
        source,
    })
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

    fn assert_allowlist(
        allowed: &[MessageType],
        is_allowed: impl Fn(MessageType) -> bool,
        invariant: &str,
    ) {
        for message_type in ALL_MESSAGE_TYPES {
            assert_eq!(
                is_allowed(message_type),
                allowed.contains(&message_type),
                "unexpected {invariant} admissibility for {message_type:?}",
            );
        }
    }

    #[test]
    fn client_direction_allowlist_matches_protocol() {
        assert_allowlist(
            &[
                MessageType::Auth,
                MessageType::RegisterCid,
                MessageType::Ping,
                MessageType::Pong,
                MessageType::Close,
                MessageType::Data,
                MessageType::UpgradeProbe,
                MessageType::UdpReady,
                MessageType::SwitchAck,
                MessageType::FallbackToTcp,
                MessageType::FallbackOk,
            ],
            |message_type| is_valid_direction(message_type, MessageSender::Client),
            "client direction",
        );
    }

    #[test]
    fn server_direction_allowlist_matches_protocol() {
        assert_allowlist(
            &[
                MessageType::AuthOk,
                MessageType::AuthFail,
                MessageType::RegisterOk,
                MessageType::RegisterFail,
                MessageType::Ping,
                MessageType::Pong,
                MessageType::Close,
                MessageType::Data,
                MessageType::UpgradeProbeAck,
                MessageType::SwitchToUdp,
                MessageType::FallbackToTcp,
                MessageType::FallbackOk,
                MessageType::SwitchOk,
            ],
            |message_type| is_valid_direction(message_type, MessageSender::Server),
            "server direction",
        );
    }

    #[test]
    fn authentication_phase_allowlist_matches_protocol() {
        assert_allowlist(
            &[
                MessageType::Auth,
                MessageType::AuthOk,
                MessageType::AuthFail,
                MessageType::Ping,
                MessageType::Pong,
                MessageType::Close,
            ],
            |message_type| is_valid_phase(message_type, ProtocolPhase::Authentication),
            "authentication phase",
        );
    }

    #[test]
    fn established_phase_rejects_authentication_messages() {
        assert_allowlist(
            &ALL_MESSAGE_TYPES[3..],
            |message_type| is_valid_phase(message_type, ProtocolPhase::Established),
            "established phase",
        );
    }

    #[test]
    fn tcp_transport_allowlist_matches_protocol() {
        let allowed: Vec<_> = ALL_MESSAGE_TYPES
            .into_iter()
            .filter(|message_type| {
                !matches!(
                    message_type,
                    MessageType::UpgradeProbe | MessageType::UpgradeProbeAck
                )
            })
            .collect();
        assert_allowlist(
            &allowed,
            |message_type| is_valid_transport(message_type, MessageTransport::Tcp),
            "tcp transport",
        );
    }

    #[test]
    fn udp_qsp_transport_allowlist_matches_protocol() {
        assert_allowlist(
            &[
                MessageType::Ping,
                MessageType::Pong,
                MessageType::Close,
                MessageType::Data,
                MessageType::UpgradeProbe,
                MessageType::UpgradeProbeAck,
            ],
            |message_type| is_valid_transport(message_type, MessageTransport::UdpQsp),
            "udp-qsp transport",
        );
    }

    #[test]
    fn validation_reports_invariant_in_stable_order() {
        let context = MessageContext::new(
            MessageSender::Server,
            ProtocolPhase::Established,
            MessageTransport::UdpQsp,
        );
        assert!(matches!(
            validate_message_type(MessageType::Auth, context),
            Err(MessageValidationError::InvalidDirection {
                message_type: MessageType::Auth,
                sender: MessageSender::Server,
            })
        ));

        let context = MessageContext::new(
            MessageSender::Client,
            ProtocolPhase::Established,
            MessageTransport::UdpQsp,
        );
        assert!(matches!(
            validate_message_type(MessageType::Auth, context),
            Err(MessageValidationError::InvalidPhase {
                message_type: MessageType::Auth,
                phase: ProtocolPhase::Established,
            })
        ));

        let context = MessageContext::new(
            MessageSender::Client,
            ProtocolPhase::Authentication,
            MessageTransport::UdpQsp,
        );
        assert!(matches!(
            validate_message_type(MessageType::Auth, context),
            Err(MessageValidationError::InvalidTransport {
                message_type: MessageType::Auth,
                transport: MessageTransport::UdpQsp,
            })
        ));
    }

    #[test]
    fn fixed_layout_payloads_are_validated() {
        let cases = [
            Message::Auth { payload: &[] },
            Message::AuthOk { payload: &[0] },
            Message::AuthFail { payload: &[] },
            Message::RegisterOk { payload: &[] },
            Message::RegisterFail { payload: &[] },
            Message::Ping { payload: &[] },
            Message::Pong { payload: &[] },
            Message::Close { payload: &[] },
            Message::UpgradeProbe { payload: &[] },
            Message::UpgradeProbeAck { payload: &[] },
            Message::UdpReady { payload: &[] },
            Message::SwitchToUdp { payload: &[] },
            Message::SwitchAck { payload: &[] },
            Message::FallbackToTcp { payload: &[] },
            Message::FallbackOk { payload: &[] },
            Message::SwitchOk { payload: &[] },
        ];
        assert_eq!(cases.len(), ALL_MESSAGE_TYPES.len() - 2);

        for message in cases {
            let message_type = message.ty();
            let sender = if matches!(
                message_type,
                MessageType::Auth
                    | MessageType::UpgradeProbe
                    | MessageType::UdpReady
                    | MessageType::SwitchAck
            ) {
                MessageSender::Client
            } else {
                MessageSender::Server
            };
            let phase = if matches!(
                message_type,
                MessageType::Auth | MessageType::AuthOk | MessageType::AuthFail
            ) {
                ProtocolPhase::Authentication
            } else {
                ProtocolPhase::Established
            };
            let transport = if matches!(
                message_type,
                MessageType::UpgradeProbe | MessageType::UpgradeProbeAck
            ) {
                MessageTransport::UdpQsp
            } else {
                MessageTransport::Tcp
            };
            let context = MessageContext::new(sender, phase, transport);
            assert!(matches!(
                validate_message(message, context),
                Err(MessageValidationError::InvalidPayload {
                    message_type: actual,
                    ..
                }) if actual == message_type
            ));
        }
    }

    #[test]
    fn variable_payloads_remain_endpoint_validated() {
        let context = MessageContext::new(
            MessageSender::Client,
            ProtocolPhase::Established,
            MessageTransport::Tcp,
        );
        validate_message(Message::RegisterCid { payload: &[] }, context).unwrap();
        validate_message(Message::Data { packet: &[] }, context).unwrap();
    }
}
