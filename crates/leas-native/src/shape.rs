use leas_proto::proto_spec::ProtocolKind;

/// How a protocol kind connects — the dispatch spine for the native core.
///
/// The uniform "dial transport → security → handshake over stream" pipeline
/// applies only to [`ConnectShape::TcpStream`]. Other shapes take their own
/// path at dispatch time and may ignore the transport seam entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectShape {
    /// Transport (tcp/ws/grpc/...) + security + handshake over a byte stream.
    TcpStream,
    /// QUIC transport (+ packet obfuscation), then protocol over a QUIC stream.
    Quic,
    /// Network-device protocol: no dial, device + own socket path.
    DeviceTunnel,
    /// Own complete state machine that ignores the transport seam.
    HandshakeOwn,
    /// No connect path exists at all (outbound-only kinds).
    NoStream,
}

/// Static per-kind classification. Every `ProtocolKind` arm must be covered;
/// the match is written exhaustively so adding a kind to the proto crate is a
/// compile error here until a shape is assigned.
#[must_use]
pub const fn connect_shape(kind: ProtocolKind) -> ConnectShape {
    use ConnectShape::{DeviceTunnel, HandshakeOwn, NoStream, Quic, TcpStream};
    match kind {
        ProtocolKind::Vmess
        | ProtocolKind::Vless
        | ProtocolKind::Shadowsocks
        | ProtocolKind::Shadowsocks2022
        | ProtocolKind::Socks
        | ProtocolKind::Http
        | ProtocolKind::Trojan
        | ProtocolKind::Naive
        | ProtocolKind::AnyTls
        | ProtocolKind::ShadowTls
        | ProtocolKind::ShadowsocksR => TcpStream,
        ProtocolKind::Hysteria2 | ProtocolKind::Hysteria | ProtocolKind::Tuic => Quic,
        ProtocolKind::WireGuard | ProtocolKind::Tailscale => DeviceTunnel,
        ProtocolKind::Ssh | ProtocolKind::Tor => HandshakeOwn,
        ProtocolKind::DokodemoDoor
        | ProtocolKind::Freedom
        | ProtocolKind::Blackhole
        | ProtocolKind::Dns
        | ProtocolKind::Loopback
        | ProtocolKind::Custom
        | ProtocolKind::Redirect
        | ProtocolKind::TProxy
        | ProtocolKind::Mixed => NoStream,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_family_is_tcp_stream() {
        for k in [
            ProtocolKind::Vmess,
            ProtocolKind::Vless,
            ProtocolKind::Shadowsocks,
            ProtocolKind::Shadowsocks2022,
            ProtocolKind::Socks,
            ProtocolKind::Http,
            ProtocolKind::Trojan,
            ProtocolKind::Naive,
            ProtocolKind::AnyTls,
            ProtocolKind::ShadowTls,
            ProtocolKind::ShadowsocksR,
        ] {
            assert_eq!(connect_shape(k), ConnectShape::TcpStream, "{k:?}");
        }
    }

    #[test]
    fn quic_family() {
        for k in [
            ProtocolKind::Hysteria2,
            ProtocolKind::Hysteria,
            ProtocolKind::Tuic,
        ] {
            assert_eq!(connect_shape(k), ConnectShape::Quic, "{k:?}");
        }
    }

    #[test]
    fn device_and_own_handshake() {
        assert_eq!(
            connect_shape(ProtocolKind::WireGuard),
            ConnectShape::DeviceTunnel
        );
        assert_eq!(
            connect_shape(ProtocolKind::Tailscale),
            ConnectShape::DeviceTunnel
        );
        assert_eq!(connect_shape(ProtocolKind::Ssh), ConnectShape::HandshakeOwn);
        assert_eq!(connect_shape(ProtocolKind::Tor), ConnectShape::HandshakeOwn);
    }

    #[test]
    fn outbound_only_kinds_have_no_stream() {
        for k in [
            ProtocolKind::DokodemoDoor,
            ProtocolKind::Freedom,
            ProtocolKind::Blackhole,
            ProtocolKind::Dns,
            ProtocolKind::Loopback,
            ProtocolKind::Custom,
            ProtocolKind::Redirect,
            ProtocolKind::TProxy,
            ProtocolKind::Mixed,
        ] {
            assert_eq!(connect_shape(k), ConnectShape::NoStream, "{k:?}");
        }
    }
}
