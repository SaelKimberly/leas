//! The user-space IP stack a `WireGuard` tunnel carries.
//!
//! `smoltcp` owns the TCP state machine, its windows and retransmits; this
//! module owns only the bridge between inner IP packets and local streams.
//! One driver task per device is woken by the packet link, by a flow command,
//! or by the stack's own timer — never by a polling loop.
//!
//! Lifecycle rules follow `thirdparty/ZeroNet/vendor/netstack-smoltcp/PATCHES.md`
//! (the six bugs a naive integration inherits): a retransmitted SYN joins the
//! live socket, an orphaned socket is reset after a short linger, `shutdown`
//! completes when the FIN is queued, and the live-socket count is capped.

pub mod dns;
pub mod flow;
pub mod link;
pub mod net;

use std::net::SocketAddr;

use thiserror::Error;

pub use dns::TunnelDns;
pub use flow::{TcpFlow, UdpFlow, WgUdpConn, WgUdpReader, WgUdpWriter};
pub use link::WgLink;
pub use net::WgStack;

/// One datagram in each direction between the stack and whatever carries IP
/// packets (the `WireGuard` tunnel, or a test double).
pub trait PacketLink: Send + 'static {
    /// Receive one packet into `buf`, returning its length.
    fn recv(&mut self, buf: &mut [u8]) -> impl Future<Output = std::io::Result<usize>> + Send;

    /// Send one packet.
    fn send(&mut self, packet: &[u8]) -> impl Future<Output = std::io::Result<()>> + Send;
}

/// Why a flow could not be opened or completed.
#[derive(Debug, Error)]
pub enum StackError {
    /// The tunnel or the peer did not answer in time.
    #[error("wireguard stack timeout: {0}")]
    Timeout(&'static str),
    /// The peer refused the TCP connection (RST).
    #[error("wireguard stack: connection refused")]
    Refused,
    /// The stack shut down.
    #[error("wireguard stack is closed")]
    Closed,
    /// The packet link failed.
    #[error("wireguard stack link: {0}")]
    Link(String),
    /// The stack refused the request (limits, bad address).
    #[error("wireguard stack: {0}")]
    RefusedRequest(String),
}

/// Static device parameters.
#[derive(Debug, Clone)]
pub struct StackConfig {
    /// Tunnel addresses, already parsed from the config's CIDR list.
    pub addresses: Vec<smoltcp::wire::IpCidr>,
    /// Inner IP MTU (the `WireGuard` interface MTU).
    pub mtu: usize,
    /// Concurrent TCP socket ceiling.
    pub max_sockets: usize,
    /// How long a half-open handshake may hold a slot (seconds).
    pub handshake_linger_secs: u64,
    /// How long a dropped socket waits for the peer's FIN (seconds).
    pub orphan_linger_secs: u64,
}

impl StackConfig {
    /// Defaults for a client tunnel: MTU 1420, 512 sockets, 120 s handshake
    /// linger, 30 s orphan linger (the patched netstack's numbers).
    #[must_use]
    pub const fn new(addresses: Vec<smoltcp::wire::IpCidr>, mtu: usize) -> Self {
        Self {
            addresses,
            mtu,
            max_sockets: 512,
            handshake_linger_secs: 120,
            orphan_linger_secs: 30,
        }
    }
}

/// Sorted target for a TCP connect: an address, never a name (the WG profile
/// resolves names through the tunnel before dialling).
pub type Remote = SocketAddr;
