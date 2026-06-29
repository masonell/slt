use slt_core::proto::AuthFailCode;

/// Outcome of a successfully-completed authentication phase.
///
/// Reserved for the auth loop's *decided outcomes*: the phase ran to completion
/// without a transport/decode failure (those are typed [`AuthError`](super::AuthError)
/// and surface as `Err`), and the server either authenticated the client,
/// completed normally (e.g. the client sent `CLOSE`), or rejected the client
/// on-protocol with a concrete [`AuthFailCode`] it chose to send in `AUTH_FAIL`.
///
/// Historically this enum also carried the failure variants (`Failed`,
/// `Timeout`, `ConnectionClosed`, `TlsHandshakeFailed`, `TlsHandshakeTimeout`)
/// and flattened each to an `io::Error` via `into_io_result()`, discarding the
/// structured TLS/I/O source. Phase 4 moves those onto [`AuthError`](super::AuthError),
/// which preserves the source; this enum now carries only the outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthPhaseResult {
    /// Authentication completed and a client session was created.
    Authenticated,
    /// Authentication phase ended without creating a session (for example, the
    /// client sent `CLOSE`).
    Completed,
    /// Authentication was rejected but handled on-protocol: the server sent
    /// `AUTH_FAIL` with this code. This is an `Ok` outcome of the phase (the
    /// protocol exchange completed), distinct from a transport/decode failure.
    Rejected(AuthFailCode),
}

impl AuthPhaseResult {
    /// Returns true if this outcome represents an authentication failure that
    /// should increment the auth-failures metric.
    ///
    /// Only `Rejected` counts: the failure-path conditions (timeout, disconnect,
    /// TLS fault) are now typed [`AuthError`](super::AuthError) and are counted
    /// by the handler's error path, not here.
    pub(super) const fn is_failure(self) -> bool {
        matches!(self, Self::Rejected(_))
    }

    /// Returns true if this outcome indicates a successful authentication.
    pub(super) const fn is_authenticated(self) -> bool {
        matches!(self, Self::Authenticated)
    }
}

/// Step result for auth loop iteration.
///
/// Indicates whether the auth loop should continue processing messages
/// or terminate with a final outcome. A genuine failure surfaces as
/// `Err(AuthError)` rather than a `Done` step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthStep {
    /// Continue processing auth messages.
    Continue,
    /// Auth phase is complete; return the outcome.
    Done(AuthPhaseResult),
}
