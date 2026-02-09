use slt_core::crypto::udp_qsp::{QspSessionError, QuicQspSession, SessionIo};
use slt_core::proto::MessageType;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Client-side UDP-QSP socket I/O backed by a `tokio::net::UdpSocket`.
pub struct ClientUdpIo {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
}

impl ClientUdpIo {
    /// Create a new UDP-QSP I/O wrapper for traffic to/from `peer`.
    #[must_use]
    pub const fn new(socket: Arc<UdpSocket>, peer: SocketAddr) -> Self {
        Self { socket, peer }
    }
}

impl SessionIo for ClientUdpIo {
    async fn send<'a>(&'a mut self, bytes: &'a [u8]) -> io::Result<()> {
        let _ = self.socket.send_to(bytes, self.peer).await?;
        Ok(())
    }

    async fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> io::Result<usize> {
        loop {
            let (len, from) = self.socket.recv_from(buf).await?;
            if from == self.peer {
                return Ok(len);
            }
        }
    }
}

/// UDP-QSP transport wrapper for VPN protocol messages.
pub struct UdpQspTransport {
    session: QuicQspSession<ClientUdpIo>,
    write_buf: Vec<u8>,
    packet_buf: Vec<u8>,
}

impl UdpQspTransport {
    /// Create a new UDP-QSP transport around an established session.
    #[must_use]
    pub fn new(session: QuicQspSession<ClientUdpIo>) -> Self {
        Self {
            session,
            write_buf: Vec::new(),
            packet_buf: vec![0u8; 2048],
        }
    }

    /// Return the destination connection ID used for outbound packets.
    #[must_use]
    pub const fn dcid(&self) -> &slt_core::types::Cid {
        self.session.dcid()
    }

    /// Return the source connection ID used for inbound packets.
    #[must_use]
    pub const fn scid(&self) -> &slt_core::types::Cid {
        self.session.scid()
    }

    /// Encode and send a VPN protocol message over UDP-QSP.
    pub async fn write_message(&mut self, message: slt_core::proto::Message<'_>) -> io::Result<()> {
        self.write_buf.clear();
        slt_core::proto::encode_message(message, &mut self.write_buf)
            .map_err(crate::wire::map_frame_error)?;
        self.session
            .send(&self.write_buf)
            .await
            .map_err(map_qsp_error)
    }

    /// Receive and decode a single VPN protocol message from UDP-QSP.
    pub async fn read_next_message(
        &mut self,
        limits: slt_core::proto::MessageLimits,
    ) -> io::Result<crate::wire::OwnedMessageBuf> {
        let opened = self
            .session
            .recv(&mut self.packet_buf)
            .await
            .map_err(map_qsp_error)?;
        let payload = opened.payload;

        let Some((frame, consumed)) =
            slt_core::proto::decode_frame(payload, limits.max_frame_len).map_err(map_frame_err)?
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "udp-qsp frame incomplete",
            ));
        };
        if consumed != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "udp-qsp packet contains multiple frames",
            ));
        }
        if frame.ty == MessageType::Data && frame.payload.len() > limits.max_data_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "udp-qsp data frame too large",
            ));
        }

        Ok(crate::wire::OwnedMessageBuf::new(
            frame.ty,
            payload.to_vec(),
        ))
    }
}

fn map_qsp_error(err: QspSessionError) -> io::Error {
    match err {
        QspSessionError::Io(err) => err,
        other => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("udp-qsp error: {other:?}"),
        ),
    }
}

fn map_frame_err(err: slt_core::proto::FrameError) -> io::Error {
    crate::wire::map_frame_error(err)
}
