//! Pure cryptographic algorithm codecs.
//!
//! Rule: `crypto/` owns ALGORITHMS, layers own DECISIONS. No I/O policy and
//! no transport logic lives here. Packet-level obfuscation (e.g. Hysteria2
//! Salamander) is implemented here but consumed inside the QUIC transport's
//! packet handling — it is never forced into the byte-stream seam.
//!
//! JA3/JA4 fingerprint codecs moved to `leas-tls::crypto::fingerprint`
//! with the fingerprint engine milestone; the `VMess` wire crypto lives here.

pub mod aead;
pub mod kdf;
pub mod legacy_stream;
pub mod salamander;
