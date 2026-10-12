use super::{FastPingAdapter, PingCapability, PingError};
use async_trait::async_trait;
use leas_proto::ProtocolKind;
use std::time::Duration;

/// TCP handshake ping. Supports all TCP-based proxy protocols.
#[derive(Debug)]
pub struct TcpPingAdapter;

#[async_trait]
impl FastPingAdapter for TcpPingAdapter {
    fn transport(&self) -> PingCapability {
        PingCapability::Tcp
    }

    fn name(&self) -> &'static str {
        "TCP"
    }

    fn supports(&self, protocol: ProtocolKind) -> bool {
        matches!(
            protocol,
            ProtocolKind::Vmess
                | ProtocolKind::Vless
                | ProtocolKind::Shadowsocks
                | ProtocolKind::Shadowsocks2022
                | ProtocolKind::Socks
                | ProtocolKind::Http
                | ProtocolKind::Trojan
                | ProtocolKind::DokodemoDoor
                | ProtocolKind::Custom
                | ProtocolKind::Naive
                | ProtocolKind::AnyTls
                | ProtocolKind::ShadowTls
                | ProtocolKind::Tor
                | ProtocolKind::Ssh
                | ProtocolKind::ShadowsocksR
                | ProtocolKind::Redirect
                | ProtocolKind::TProxy
                | ProtocolKind::Mixed
        )
    }

    async fn ping(&self, addr: &str, port: u16, timeout: Duration) -> Result<Duration, PingError> {
        Ok(crate::speed_test::tcp_ping(addr, port, timeout).await?)
    }
}
