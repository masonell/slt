//! Runtime host resolution hook.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio::net::lookup_host;

/// Future returned by [`HostResolver`].
pub type HostResolverFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;

/// Runtime hook for resolving server hostnames to numeric peer addresses.
pub trait HostResolver: Send + Sync {
    /// Resolve `hostname:port` into candidate socket addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if resolution fails or yields no usable addresses.
    fn resolve<'a>(&'a self, hostname: &'a str, port: u16) -> HostResolverFuture<'a>;
}

/// Default resolver backed by Tokio/system DNS.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioHostResolver;

impl HostResolver for TokioHostResolver {
    fn resolve<'a>(&'a self, hostname: &'a str, port: u16) -> HostResolverFuture<'a> {
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = lookup_host((hostname, port)).await?.collect();
            ensure_non_empty(addrs)
        })
    }
}

/// Return `addrs` if it contains at least one address.
///
/// # Errors
///
/// Returns `NotFound` when resolution produced no addresses.
pub fn ensure_non_empty(addrs: Vec<SocketAddr>) -> io::Result<Vec<SocketAddr>> {
    if addrs.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "dns lookup returned no addresses",
        ))
    } else {
        Ok(addrs)
    }
}
