//! VLESS `mlkem768x25519plus` payload encryption (xray
//! `proxy/vless/encryption`): the ML-KEM-768 + X25519 PFS handshake and the
//! sealed record tunnel.

mod b3;
mod mlkem;

/// Test-only re-export: `protocol/ss/method.rs` pins the 2022 subkey against
/// the hand-rolled BLAKE3 here. Production builds expose nothing new — `b3`
/// is private and its `derive_key_bytes` is reachable only from `encryption`.
#[cfg(test)]
pub(crate) use b3::derive_key_bytes;

pub use mlkem::{CommonConn, EncryptionConfig, ServerKey, handshake};
