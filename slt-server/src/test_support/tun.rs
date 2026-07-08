//! TUN device test utilities.

#![allow(dead_code)]

use std::future::Future;
use std::io;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::tun::{TunDeviceIo, TunPacketSendOutcome};

/// Null TUN device that discards all packets.
#[derive(Clone, Copy, Debug)]
pub struct NullTun;

impl TunDeviceIo for NullTun {
    fn accept_packet<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> impl Future<Output = io::Result<TunPacketSendOutcome>> + Send + 'a {
        std::future::ready(Ok(TunPacketSendOutcome::Dropped {
            bytes: packet.len(),
        }))
    }
}

/// Test TUN device that captures sent packets to a channel.
#[derive(Clone)]
pub struct TestTun {
    /// Channel to capture packets sent to TUN.
    pub tx: mpsc::Sender<Vec<u8>>,
}

impl TunDeviceIo for TestTun {
    fn accept_packet<'a>(
        &'a self,
        buf: &'a [u8],
    ) -> impl Future<Output = io::Result<TunPacketSendOutcome>> + Send + 'a {
        let tx = self.tx.clone();
        async move {
            match tx.send(buf.to_vec()).await {
                Ok(()) => Ok(TunPacketSendOutcome::Accepted),
                Err(_) => Ok(TunPacketSendOutcome::Closed),
            }
        }
    }
}

impl TestTun {
    /// Creates a new `TestTun` with a channel for capturing packets.
    ///
    /// Returns (`TestTun`, receiver for captured packets).
    pub fn new(channel_size: usize) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(channel_size);
        (Arc::new(Self { tx }), rx)
    }
}
