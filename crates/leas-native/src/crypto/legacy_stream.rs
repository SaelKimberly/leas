//! Legacy Shadowsocks stream ciphers (sing-box legacy set).
//!
//! rc4-md5, chacha20-ietf, aes-128/192/256-cfb, aes-ctr, and the `none`
//! passthrough — the ciphers xray-core's `CipherType` enum has no entry for.
//! Consumers: `protocol/shadowsocks` (sing-box-routed legacy methods).
//! Backend: `RustCrypto` stream-cipher crates (added when implemented).
//! Implemented at milestone M4.
