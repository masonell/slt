use super::*;

#[test]
fn authenticator_from_config_tracks_enabled_clients() {
    let client_enabled_id = ClientId([0x01; 16]);
    let client_disabled_id = ClientId([0x02; 16]);
    let client_enabled = ServerClient {
        client_id: client_enabled_id,
        pubkey_ed25519: PubKeyEd25519([0x11; 32]),
        assigned_ipv4: Ipv4Addr::new(10, 0, 0, 1),
        enabled: true,
    };
    let client_disabled = ServerClient {
        client_id: client_disabled_id,
        pubkey_ed25519: PubKeyEd25519([0x22; 32]),
        assigned_ipv4: Ipv4Addr::new(10, 0, 0, 2),
        enabled: false,
    };

    let config = ServerConfig {
        server_secret: SharedSecret([0xAA; 32]),
        network: ServerNetworkConfig {
            listen_tcp: SocketAddr::from(([127, 0, 0, 1], 0)),
            listen_udp: SocketAddr::from(([127, 0, 0, 1], 0)),
            nginx_tcp_upstream: SocketAddr::from(([127, 0, 0, 1], 0)),
            nginx_udp_upstream: SocketAddr::from(([127, 0, 0, 1], 0)),
        },
        tls: ServerTlsConfig {
            tls_cert: TlsMaterial::File {
                file: "vendor/boring/test/cert.pem".into(),
            },
            tls_key: TlsMaterial::File {
                file: "vendor/boring/test/key.pem".into(),
            },
        },
        tun: TunConfig {
            tun_name: "test0".to_string(),
            tun_mtu: 1280,
            tun_ipv4: Ipv4Addr::new(10, 0, 0, 1),
            tun_prefix: 24,
        },
        timing: ServerTimingConfig {
            ping_min: std::time::Duration::from_secs(1),
            ping_max: std::time::Duration::from_secs(2),
            auth_timeout: std::time::Duration::from_secs(3),
            idle_timeout: std::time::Duration::from_secs(4),
            metrics_interval: std::time::Duration::from_secs(5),
            tcp_classification_timeout: std::time::Duration::from_secs(6),
        },
        transport: ServerTransportConfig::default(),
        udp_nat_max_entries: 32,
        session_queue_size: 8,
        max_auth_inflight: 128,
        tcp_connection_cap: 512,
        clients: vec![client_enabled, client_disabled],
    };

    let auth = Authenticator::from_config(&config);
    assert!(auth.is_enabled(&client_enabled_id));
    assert!(!auth.is_enabled(&client_disabled_id));
    assert!(auth.get(&client_enabled_id).is_some());
}

#[test]
fn verify_auth_accepts_valid_payload() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let client_id = ClientId([0xA1; 16]);
    let assigned_ipv4 = Ipv4Addr::new(10, 0, 0, 9);
    let challenge = [0x5A; AUTH_CHALLENGE_LEN];
    let client = make_client(client_id, &signing_key, assigned_ipv4, true);
    let authenticator = Authenticator::new([client]);

    let payload = make_payload(client_id, assigned_ipv4, challenge, &signing_key);
    let assigned = verify_auth_payload(&authenticator, &payload, &challenge).unwrap();
    assert_eq!(assigned, AssignedIp(assigned_ipv4));
}

#[test]
fn verify_auth_reports_mismatches() {
    let signing_key = SigningKey::from_bytes(&[0x55; 32]);
    let client_id = ClientId([0xB2; 16]);
    let assigned_ipv4 = Ipv4Addr::new(10, 0, 0, 10);
    let challenge = [0x6B; AUTH_CHALLENGE_LEN];
    let client = make_client(client_id, &signing_key, assigned_ipv4, true);
    let authenticator = Authenticator::new([client]);

    let wrong_ip = Ipv4Addr::new(10, 0, 0, 11);
    let payload = make_payload(client_id, wrong_ip, challenge, &signing_key);
    assert_eq!(
        verify_auth_payload(&authenticator, &payload, &challenge),
        Err(AuthFailCode::IpMismatch)
    );

    let mut wrong_challenge = challenge;
    wrong_challenge[0] ^= 0xFF;
    let payload = make_payload(client_id, assigned_ipv4, wrong_challenge, &signing_key);
    assert_eq!(
        verify_auth_payload(&authenticator, &payload, &challenge),
        Err(AuthFailCode::ChallengeInvalid)
    );
}

#[test]
fn verify_auth_reports_disabled_or_unknown() {
    let signing_key = SigningKey::from_bytes(&[0x77; 32]);
    let client_id = ClientId([0xC3; 16]);
    let assigned_ipv4 = Ipv4Addr::new(10, 0, 0, 12);
    let challenge = [0x7C; AUTH_CHALLENGE_LEN];
    let client = make_client(client_id, &signing_key, assigned_ipv4, false);
    let authenticator = Authenticator::new([client]);

    let payload = make_payload(client_id, assigned_ipv4, challenge, &signing_key);
    assert_eq!(
        verify_auth_payload(&authenticator, &payload, &challenge),
        Err(AuthFailCode::Disabled)
    );

    let unknown_id = ClientId([0xD4; 16]);
    let payload = make_payload(unknown_id, assigned_ipv4, challenge, &signing_key);
    assert_eq!(
        verify_auth_payload(&authenticator, &payload, &challenge),
        Err(AuthFailCode::UnknownClient)
    );
}

#[test]
fn verify_auth_rejects_bad_signature() {
    let signing_key = SigningKey::from_bytes(&[0x88; 32]);
    let other_key = SigningKey::from_bytes(&[0x99; 32]);
    let client_id = ClientId([0xE5; 16]);
    let assigned_ipv4 = Ipv4Addr::new(10, 0, 0, 13);
    let challenge = [0x8D; AUTH_CHALLENGE_LEN];
    let client = make_client(client_id, &signing_key, assigned_ipv4, true);
    let authenticator = Authenticator::new([client]);

    let payload = make_payload(client_id, assigned_ipv4, challenge, &other_key);
    assert_eq!(
        verify_auth_payload(&authenticator, &payload, &challenge),
        Err(AuthFailCode::BadSignature)
    );
}
