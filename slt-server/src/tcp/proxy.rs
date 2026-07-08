use std::io;
use std::net::SocketAddr;

use tokio::net::TcpStream;
use tracing::{error, trace};

/// Proxy a TCP stream to the nginx upstream.
///
/// Connects to the upstream server and performs bidirectional copying
/// of data between the inbound client stream and the upstream stream.
///
/// # Errors
///
/// Returns an error if connecting to upstream or bidirectional copy fails.
pub(super) async fn proxy_to_upstream(
    mut inbound: TcpStream,
    upstream: SocketAddr,
) -> io::Result<()> {
    trace!(upstream_addr = %upstream, "connecting to upstream");
    let mut outbound = TcpStream::connect(upstream).await?;
    trace!(upstream_addr = %upstream, "connected to upstream, starting bidirectional copy");
    let result = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
    match &result {
        Ok((bytes_inbound, bytes_outbound)) => {
            trace!(upstream_addr = %upstream, bytes_inbound = bytes_inbound, bytes_outbound = bytes_outbound, "proxy completed");
        }
        Err(e) => {
            error!(upstream_addr = %upstream, error = %e, "proxy bidirectional copy failed");
        }
    }
    result?;
    Ok(())
}
