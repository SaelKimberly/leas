//! The sing-box mux wire (`sing-mux@caf09fe`, pinned in `thirdparty/`): a
//! versioned request/padding handshake, per-stream request/response framing,
//! and the `smux`/`yamux`/`h2mux` session protocols.
//!
//! This module owns the handshake and the padding connection (spec
//! `docs/aegis/specs/2026-11-17-mux-carrier-reuse-design.md` §8). The session
//! protocols live beside it; nothing here allocates per frame beyond the
//! padded write buffer, and the request is released with the first payload
//! exactly like the MUX.Cool client's `HeaderFirst`.

pub mod h2mux;
pub mod padding;
pub mod protocol;
pub mod smux;
pub mod stream;
pub mod tunnel;
pub mod udp;
pub mod yamux;

pub use h2mux::H2Mux;
pub use padding::PaddingConn;
pub use protocol::{PROTOCOL_H2MUX, PROTOCOL_SMUX, PROTOCOL_YAMUX, VERSION0, VERSION1};
pub use smux::SmuxSession;
pub use tunnel::{SboxSession, SboxTunnel};
pub use udp::SboxUdpTunnel;
pub use yamux::YamuxSession;
