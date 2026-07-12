use super::*;

#[test]
fn tcp_is_tcp() {
    assert_eq!(ActiveTransport::Tcp, ActiveTransport::Tcp);
}

#[test]
fn udp_qsp_is_udp_qsp() {
    assert_eq!(ActiveTransport::UdpQsp, ActiveTransport::UdpQsp);
}

#[test]
fn tcp_is_not_udp_qsp() {
    assert_ne!(ActiveTransport::Tcp, ActiveTransport::UdpQsp);
}

#[test]
fn variants_are_debug_clone_copy() {
    let tcp = ActiveTransport::Tcp;
    let _tcp_copy: ActiveTransport = tcp;
    assert!(format!("{tcp:?}").contains("Tcp"));
}
