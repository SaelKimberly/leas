//! Native proxy core — in-process implementations of the proxy protocols
//! leas otherwise obtains by spawning xray-core / sing-box subprocesses.
//! Client face: [`connect`] and friends dial a remote proxy (TCP; SOCKS5's
//! client handshake lives in [`protocol::socks`]). Server face: [`inbound`]
//! provides the local SOCKS5 inbound (accept → route → outbound), with TCP
//! CONNECT and, when enabled, per-datagram UDP ASSOCIATE relay.
//!
//! # Layering
//!
//! Transports are OUTERMOST, protocols INNERMOST (Xray composition order):
//! dial → transport upgrade → security wrap → protocol handshake → tunnel.
//!
//! # Placeholder semantics
//!
//! Every protocol kind, transport, and security has a module and a dispatch
//! arm; unsupported combinations return [`NativeError::NotImplemented`].
//! The uniform `handshake(stream)` shape applies to the TCP-stream family
//! only — WireGuard/Tailscale (device tunnels), SSH (own handshake), and the
//! outbound-only kinds (Redirect/TProxy/Mixed/DokodemoDoor/...) diverge at
//! dispatch time per [`shape::ConnectShape`]. See `shape.rs`.
//!
//! # Config source of truth
//!
//! [`NativeConnectParams`] wraps `leas-proto` typed models
//! ([`ProtocolConfig`], [`EndpointEssentials`]). No config model is defined
//! here.

// The protocol/transport/security core holds no `unsafe`: every primitive is
// ring/RustCrypto and every buffer is a safe abstraction. Forbidding it here
// keeps that true — a future edit cannot add hand-rolled unsafe to the
// protocol engine silently.
#![forbid(unsafe_code)]

/// Byte-stream capability: readable, writable, `Unpin`, `Send` — the seam
/// between layers.
///
/// `Any` (so every stream is `'static`) lets a layer recover the concrete
/// stream behind the box: the vision codec splices the engine `TlsStream`'s
/// per-direction direct mode through the `DirectMode` impl on [`BoxStream`]
/// (see `protocol/vless/vision.rs`).
pub trait Stream:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::any::Any
{
}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> Stream for T {}

/// The boxed byte-stream seam between layers.
pub type BoxStream = Box<dyn Stream>;

pub mod addr;
pub mod capability;
pub mod chain;
pub mod context;
pub mod crypto;
#[cfg(feature = "native-e2e")]
pub mod e2e;
pub mod error;
pub mod headers;
pub mod inbound;
pub mod mux_session;
/// HTTP-over-tunnel primitive (the real-ping probe's transport).
pub mod probe;
pub mod protocol;
/// Buffered CSPRNG for non-secret randomness (padding, salts, ids). Key
/// material never comes from here — see the module docs.
pub(crate) mod rand;
pub mod security;
pub mod server;
pub mod shape;
pub mod telemetry;
pub mod transport;

pub use chain::{connect_chain, connect_chain_mux, connect_chain_udp};
pub use context::{LinkContext, NativeConnectParams};
pub use error::NativeError;
pub use inbound::{Outbound, OutboundKind, ProxyOutbound, Socks5Inbound, Socks5InboundConfig};
pub use protocol::MuxTunnel;
pub use protocol::PacketTunnel;
pub use protocol::vless::{
    MuxClient, MuxTarget, PacketConn, PacketMode, SessionStream, UdpSession,
};

/// Connect through a single proxy to `params.target`.
pub async fn connect(params: NativeConnectParams) -> Result<NativeTunnel, NativeError> {
    let target = params.target.clone();
    connect_chain(&[params], target).await
}

/// Connect through a single proxy with a UDP datagram tunnel to
/// `params.target`.
///
/// `params.udp` selects the packet mode: [`PacketMode::Raw`] (the header
/// destination — every protocol below) or the VLESS-only
/// [`PacketMode::PacketAddr`] / [`PacketMode::XUdp`], which the non-VLESS
/// protocols refuse.
///
/// The same dial → security → transport chain as [`connect`] runs
/// unchanged; only the protocol phase differs. The datagram carrier is
/// protocol-specific ([`PacketTunnel`]):
/// - **VLESS** command 0x02 + `[2B len]` framing; XUDP (`params.mux`, or
///   the `xtls-rprx-vision-udp443` flow which forces it) rides the mux
///   tunnel with a random 8-byte `GlobalID`.
/// - **`VMess`** command 0x02 AEAD records (one record = one datagram).
/// - **Trojan** command 3 address-prefixed frames.
/// - **Hysteria2** a fresh QUIC dial + QUIC DATAGRAM `UDPMessage` frames
///   (the QUIC-family protocol must be the only/last link).
/// - **Shadowsocks** one datagram per packet on a UDP socket dialed straight
///   to the server's relay port (classic-AEAD or 2022-blake3 per the row's
///   method; also the only/last link, and TLS/REALITY rows are refused).
///
/// The returned [`PacketTunnel`] is a datagram API over the tunnel.
pub async fn connect_udp(params: &NativeConnectParams) -> Result<PacketTunnel, NativeError> {
    let target = params.target.clone();
    connect_chain_udp(std::slice::from_ref(params), target).await
}

/// Connect through a single proxy with a VLESS v1.mux.cool multiplexed
/// tunnel (command 0x03).
///
/// The same dial → security → transport chain as [`connect`] runs
/// unchanged; only the protocol phase differs (VLESS command 0x03 + mux
/// framing to the fixed `v1.mux.cool` destination; a Shadowsocks plugin row
/// opens a session whose codec runs per session). The returned
/// [`MuxTunnel`] opens a session for any family via
/// [`MuxTunnel::open_session`]; VLESS-only callers can reach the raw
/// multiplexer through [`MuxTunnel::as_vless`] for the XUDP path
/// ([`MuxClient::open_udp_session`]).
pub async fn connect_mux(params: &NativeConnectParams) -> Result<MuxTunnel, NativeError> {
    let target = params.target.clone();
    connect_chain_mux(std::slice::from_ref(params), target).await
}

/// A completed native tunnel: the byte stream after the full layer stack.
///
/// Dropping the tunnel closes the underlying connection.
pub struct NativeTunnel {
    inner: BoxStream,
}

impl NativeTunnel {
    /// Wrap a completed layer stack (crate-internal; external users get
    /// tunnels from `connect`/`connect_chain`).
    pub(crate) fn from_stream(inner: BoxStream) -> Self {
        Self { inner }
    }

    /// The completed layer stack behind the tunnel (crate-internal; the
    /// e2e runner inspects it to assert PQ negotiation).
    #[cfg_attr(not(feature = "native-e2e"), allow(dead_code))]
    pub(crate) fn inner_stream(&self) -> &BoxStream {
        &self.inner
    }
}

impl tokio::io::AsyncRead for NativeTunnel {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for NativeTunnel {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
