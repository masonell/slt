//! Shared TUN configuration and batching helpers.

use std::io;

#[cfg(target_os = "linux")]
use tun_rs::{AsyncDevice, DeviceBuilder};

/// Default channel capacity used for TUN packet queues.
pub const DEFAULT_TUN_CHANNEL_SIZE: usize = 256;
/// Maximum IPv4 packet size handled by TUN paths.
pub const MAX_TUN_PACKET_SIZE: usize = 65_535;
/// Error message used for invalid MTU values.
pub const INVALID_TUN_MTU_MESSAGE: &str = "tun mtu must be greater than zero";

/// Convert a TUN MTU value to `usize` and validate it is non-zero.
///
/// # Errors
///
/// Returns `InvalidInput` when `mtu` is zero.
pub fn tun_mtu_to_usize(mtu: u16) -> io::Result<usize> {
    if mtu == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            INVALID_TUN_MTU_MESSAGE,
        ));
    }
    Ok(usize::from(mtu))
}

/// Build an async TUN device with GRO/GSO offload enabled (Linux only).
///
/// # Errors
///
/// Returns any error from `tun-rs` device creation.
#[cfg(target_os = "linux")]
pub fn build_async_tun_device(name: &str, mtu: u16) -> io::Result<AsyncDevice> {
    DeviceBuilder::new()
        .name(name)
        .mtu(mtu)
        .offload(true)
        .build_async()
}

/// Whether Linux GRO/GSO offload is enabled by [`build_async_tun_device`].
#[must_use]
pub const fn tun_offload_enabled() -> bool {
    cfg!(target_os = "linux")
}

#[cfg(target_os = "linux")]
use tun_rs::{IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

/// Packet too large for the preallocated Linux GSO batch buffer.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketTooLarge {
    /// Attempted packet length.
    pub len: usize,
    /// Maximum allowed packet length for this batch.
    pub max: usize,
}

/// Preallocated buffers for Linux `recv_multiple` TUN reads.
#[cfg(target_os = "linux")]
pub struct LinuxRecvBatch {
    original_buffer: Vec<u8>,
    split_buffers: Vec<Vec<u8>>,
    split_sizes: Vec<usize>,
}

#[cfg(target_os = "linux")]
impl LinuxRecvBatch {
    /// Allocate receive buffers sized for GRO split output.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` when `mtu` is zero.
    pub fn new(mtu: u16) -> io::Result<Self> {
        let mtu = tun_mtu_to_usize(mtu)?;
        let min_split_buffers = (MAX_TUN_PACKET_SIZE / mtu) + 1;
        let split_buffer_count = IDEAL_BATCH_SIZE.max(min_split_buffers);

        Ok(Self {
            original_buffer: vec![0u8; VIRTIO_NET_HDR_LEN + MAX_TUN_PACKET_SIZE],
            split_buffers: (0..split_buffer_count).map(|_| vec![0u8; mtu]).collect(),
            split_sizes: vec![0usize; split_buffer_count],
        })
    }

    /// Return mutable buffer views for `recv_multiple`.
    pub fn recv_args(&mut self) -> (&mut Vec<u8>, &mut [Vec<u8>], &mut [usize]) {
        (
            &mut self.original_buffer,
            &mut self.split_buffers,
            &mut self.split_sizes,
        )
    }

    /// Return packet length for a split packet index.
    #[must_use]
    pub fn packet_len(&self, index: usize) -> usize {
        self.split_sizes[index]
    }

    /// Return a packet slice for a split packet index.
    #[must_use]
    pub fn packet(&self, index: usize) -> &[u8] {
        let size = self.packet_len(index);
        &self.split_buffers[index][..size]
    }
}

/// Reusable packet batch for Linux `send_multiple` writes.
#[cfg(target_os = "linux")]
pub struct LinuxSendBatch {
    buffers: Vec<Vec<u8>>,
    count: usize,
    payload_bytes: usize,
}

#[cfg(target_os = "linux")]
impl LinuxSendBatch {
    /// Create a batch with capacity equal to `IDEAL_BATCH_SIZE`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffers: (0..IDEAL_BATCH_SIZE)
                .map(|_| vec![0u8; VIRTIO_NET_HDR_LEN + MAX_TUN_PACKET_SIZE])
                .collect(),
            count: 0,
            payload_bytes: 0,
        }
    }

    /// Clear batch packet counters without reallocating buffers.
    pub const fn clear(&mut self) {
        self.count = 0;
        self.payload_bytes = 0;
    }

    /// Return whether the batch has reached packet capacity.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.count == self.buffers.len()
    }

    /// Return number of queued packets in this batch.
    #[must_use]
    pub const fn packet_count(&self) -> usize {
        self.count
    }

    /// Return total payload bytes queued in this batch.
    #[must_use]
    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    /// Return virtio-net header offset prepended to each packet.
    #[must_use]
    pub const fn header_offset(&self) -> usize {
        VIRTIO_NET_HDR_LEN
    }

    /// Return maximum payload length supported by each batch entry.
    #[must_use]
    pub fn max_payload_len(&self) -> usize {
        self.buffers[0]
            .capacity()
            .saturating_sub(self.header_offset())
    }

    /// Return mutable packet buffer slice containing queued packets.
    pub fn queued_buffers_mut(&mut self) -> &mut [Vec<u8>] {
        &mut self.buffers[..self.count]
    }

    /// Append one packet payload into the batch.
    ///
    /// # Errors
    ///
    /// Returns `PacketTooLarge` when the packet exceeds payload capacity.
    pub fn push_packet(&mut self, packet: &[u8]) -> Result<(), PacketTooLarge> {
        if self.is_full() {
            return Err(PacketTooLarge {
                len: packet.len(),
                max: self.max_payload_len(),
            });
        }
        let index = self.count;
        let offset = self.header_offset();
        append_packet_to_batch_buffer(&mut self.buffers[index], packet, offset)?;
        self.count += 1;
        self.payload_bytes += packet.len();
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Default for LinuxSendBatch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
fn append_packet_to_batch_buffer(
    buffer: &mut Vec<u8>,
    packet: &[u8],
    offset: usize,
) -> Result<(), PacketTooLarge> {
    let max = buffer.capacity().saturating_sub(offset);
    if packet.len() > max {
        return Err(PacketTooLarge {
            len: packet.len(),
            max,
        });
    }

    let packet_len = offset + packet.len();
    if buffer.len() != packet_len {
        buffer.resize(packet_len, 0);
    }
    buffer[offset..packet_len].copy_from_slice(packet);
    Ok(())
}
