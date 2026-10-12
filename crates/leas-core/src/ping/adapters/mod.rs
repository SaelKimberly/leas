//! `FastPingAdapter` trait + `FastPingManager` with adapter registry.
//! Each sub-module implements the trait for one transport.

#[cfg(feature = "quic-ping")]
mod quic;
mod tcp;
mod udp;

use super::{IoFailure, PingCapability, PingError};
use leas_proto::ProtocolKind;
use std::time::Duration;

/// Transport-level ping adapter. Each impl handles one transport method
/// (TCP, UDP, QUIC) and declares which protocols it supports.
///
/// Design rule: an adapter MUST NOT support any protocol whose `address:port`
/// is not extractable from profile metadata — such protocols get no adapter
/// match, so the fast probe reports "not supported by any adapter".
#[async_trait::async_trait]
pub trait FastPingAdapter: Send + Sync + std::fmt::Debug {
    fn transport(&self) -> PingCapability;
    fn name(&self) -> &'static str;
    /// Whether this adapter can ping the given protocol kind.
    fn supports(&self, protocol: ProtocolKind) -> bool;
    /// Run a ping against `addr:port`, returning latency on success.
    async fn ping(&self, addr: &str, port: u16, timeout: Duration) -> Result<Duration, PingError>;
}

#[cfg(feature = "quic-ping")]
pub use quic::QuicPingAdapter;
pub use tcp::TcpPingAdapter;
pub use udp::UdpPingAdapter;

/// Manages a registry of `FastPingAdapters` and dispatches to the first match.
/// Built-in adapters are registered by default; new ones can be added via `register()`.
pub struct FastPingManager {
    adapters: Vec<Box<dyn FastPingAdapter>>,
    timeout: Duration,
}

impl std::fmt::Debug for FastPingManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FastPingManager")
            .field(
                "adapters",
                &self.adapters.iter().map(|a| a.name()).collect::<Vec<_>>(),
            )
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl FastPingManager {
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        let mut mgr = Self {
            adapters: Vec::new(),
            timeout,
        };
        mgr.register(Box::new(TcpPingAdapter));
        mgr.register(Box::new(UdpPingAdapter));
        #[cfg(feature = "quic-ping")]
        mgr.register(Box::new(QuicPingAdapter));
        mgr
    }

    pub fn register(&mut self, adapter: Box<dyn FastPingAdapter>) {
        self.adapters.push(adapter);
    }

    /// Find the first adapter that supports this protocol kind.
    #[must_use]
    pub fn adapter_for(&self, protocol: ProtocolKind) -> Option<&dyn FastPingAdapter> {
        self.adapters
            .iter()
            .find(|a| a.supports(protocol))
            .map(std::convert::AsRef::as_ref)
    }

    /// Capability for a protocol — for TUI indicator display.
    #[must_use]
    pub fn capability_for(&self, config_type: i32) -> PingCapability {
        let protocol = ProtocolKind::try_from_i32(config_type).unwrap_or(ProtocolKind::Custom);
        self.adapter_for(protocol)
            .map_or(PingCapability::None, FastPingAdapter::transport)
    }

    /// Run fast ping. Returns Ok(latency) or `Err(PingError::NotSupported)` if no adapter.
    pub async fn ping(
        &self,
        config_type: i32,
        addr: &str,
        port: u16,
    ) -> Result<Duration, PingError> {
        let protocol = ProtocolKind::try_from_i32(config_type).unwrap_or(ProtocolKind::Custom);
        match self.adapter_for(protocol) {
            Some(adapter) => adapter.ping(addr, port, self.timeout).await,
            None => Err(PingError::NotSupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn adapter_for_tcp_protocols() {
        let fmgr = FastPingManager::new(Duration::from_secs(5));
        for proto in &[
            ProtocolKind::Vmess,
            ProtocolKind::Vless,
            ProtocolKind::Shadowsocks,
            ProtocolKind::Socks,
            ProtocolKind::Http,
            ProtocolKind::Trojan,
        ] {
            let adapter = fmgr.adapter_for(*proto);
            assert!(adapter.is_some(), "no adapter for {proto:?}");
            assert_eq!(adapter.unwrap().transport(), PingCapability::Tcp);
        }
    }

    #[test]
    fn adapter_for_udp_protocols() {
        let fmgr = FastPingManager::new(Duration::from_secs(5));
        // WireGuard is UDP-only (not in TcpPingAdapter)
        let adapter = fmgr.adapter_for(ProtocolKind::WireGuard);
        assert!(adapter.is_some(), "no adapter for WireGuard");
        assert_eq!(adapter.unwrap().transport(), PingCapability::Udp);
    }

    #[test]
    fn adapter_for_unsupported_returns_none() {
        let fmgr = FastPingManager::new(Duration::from_secs(5));
        // Freedom, Blackhole, Dns, Loopback, Tailscale have no adapters
        assert!(fmgr.adapter_for(ProtocolKind::Freedom).is_none());
    }

    #[test]
    fn capability_matches_adapter() {
        let fmgr = FastPingManager::new(Duration::from_secs(5));
        // config_type 0 -> ProtocolKind::Custom -> TcpPingAdapter
        assert_eq!(fmgr.capability_for(0), PingCapability::Tcp);
    }

    #[tokio::test]
    async fn ping_unsupported_returns_error() {
        let fmgr = FastPingManager::new(Duration::from_secs(5));
        // ProtocolKind::Freedom has no adapter
        let result = fmgr
            .ping(ProtocolKind::Freedom.to_i32(), "1.2.3.4", 80)
            .await;
        assert!(matches!(result, Err(PingError::NotSupported)));
    }
}
