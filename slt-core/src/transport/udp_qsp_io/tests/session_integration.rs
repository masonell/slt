use std::io;
use std::time::Duration;

use tokio::time::timeout;

use super::super::UdpQspIo;
use super::socket_pair;
use crate::crypto::udp_qsp::{QuicQspSession, UdpQspKeys};
use crate::proto::{AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, HP_KEY_LEN};
use crate::types::Cid;

fn client_keys() -> UdpQspKeys {
    UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0x11; HP_KEY_LEN],
        [0x22; HP_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x44; AEAD_KEY_LEN],
        [0x55; AEAD_IV_LEN],
        [0x66; AEAD_IV_LEN],
    )
    .unwrap()
}

fn server_keys() -> UdpQspKeys {
    UdpQspKeys::from_packet_material(
        CipherSuite::Aes128Gcm,
        [0x22; HP_KEY_LEN],
        [0x11; HP_KEY_LEN],
        [0x44; AEAD_KEY_LEN],
        [0x33; AEAD_KEY_LEN],
        [0x66; AEAD_IV_LEN],
        [0x55; AEAD_IV_LEN],
    )
    .unwrap()
}

#[tokio::test]
async fn quic_qsp_session_roundtrips_over_udp_qsp_io() -> io::Result<()> {
    let (a, b) = socket_pair()?;
    let client_addr = a.local_addr()?;
    let server_addr = b.local_addr()?;
    let client_cid = Cid::from([0xA1; 20]);
    let server_cid = Cid::from([0xB2; 20]);
    let client_io = UdpQspIo::new(a, server_addr)?;
    let server_io = UdpQspIo::new(b, client_addr)?;
    let mut client = QuicQspSession::new(
        client_io,
        client_cid,
        server_cid,
        client_keys(),
        0,
        0,
        false,
    );
    let mut server = QuicQspSession::new(
        server_io,
        server_cid,
        client_cid,
        server_keys(),
        0,
        0,
        false,
    );
    let mut buf = [0u8; 2048];

    client.send(b"ping").await.unwrap();
    client.flush().await?;
    let opened = timeout(Duration::from_secs(1), server.recv(&mut buf))
        .await?
        .unwrap();
    assert_eq!(opened.payload, b"ping");

    server.send(b"pong").await.unwrap();
    server.flush().await?;
    let opened = timeout(Duration::from_secs(1), client.recv(&mut buf))
        .await?
        .unwrap();
    assert_eq!(opened.payload, b"pong");
    Ok(())
}
