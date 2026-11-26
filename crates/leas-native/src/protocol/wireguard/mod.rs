//! `WireGuard` — the `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` client.
//!
//! The protocol carries IP packets, not streams (`ConnectShape::DeviceTunnel`),
//! so this module is split on one line: [`core`] is sans-I/O (fixed message
//! layouts, key derivation, replay window, a `now: u64` state machine emitting
//! events), and [`stack`] is the only place that owns a socket, a runtime or a
//! `smoltcp` interface. Design and evidence:
//! `docs/aegis/specs/2026-11-26-wireguard-native-design.md`.
//!
//! Reference: `thirdparty/wireguard-go` (`device/noise-protocol.go`,
//! `cookie.go`, `timers.go`, `kdf_test.go`).

pub mod core;
pub mod kdf;
pub mod keys;
pub mod pool;
pub mod stack;
