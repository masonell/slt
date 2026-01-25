//! TLS acceptor helpers.

use boring::ssl::{SslContext, SslContextBuilder, SslContextRef};

/// TLS acceptor wrapper.
#[derive(Debug)]
pub struct TlsAcceptor {
    ctx: SslContext,
}

impl TlsAcceptor {
    /// Build a TLS acceptor from a prepared context builder.
    #[must_use]
    pub fn new(builder: SslContextBuilder) -> Self {
        Self {
            ctx: builder.build(),
        }
    }

    /// Returns a shared reference to the inner SSL context.
    #[must_use]
    pub fn context(&self) -> &SslContextRef {
        &self.ctx
    }
}
