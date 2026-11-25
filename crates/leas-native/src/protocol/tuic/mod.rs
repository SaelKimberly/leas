//! TUIC v5 client (`ConnectShape::Quic`).
//!
//! Wire: [`wire`] (sans-I/O). QUIC dial/auth/UDP driver: `quic.rs`.
//! CONNECT stream and 0-RTT retry: `stream.rs`. UDP associations: `udp.rs`.

pub(crate) mod quic;
pub(crate) mod stream;
pub mod udp;
pub(crate) mod wire;

pub(crate) use stream::connect;
pub(crate) use udp::connect_udp;
