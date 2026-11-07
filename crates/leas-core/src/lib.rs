pub mod grpc_client;
pub mod http;
pub mod log_heed;
pub mod ping;
pub mod speed_test;

pub use grpc_client::{SysStats, format_bytes, format_uptime};
pub use log_heed::HeedLogStorage;
#[cfg(feature = "quic-ping")]
pub use ping::QuicPingAdapter;
pub use ping::{
    FastPingAdapter, FastPingManager, IoFailure, PingCapability, PingError, TcpPingAdapter,
    UdpPingAdapter,
};
pub use speed_test::{SpeedTestError, TestType, speed_test, tcp_ping, udp_ping, udp_test};

/// Ensure the process-level rustls `CryptoProvider` is installed (idempotent).
///
/// reqwest 0.13 is built with `rustls-no-provider` (workspace standard: ring
/// backend) and panics at `Client::build` unless a provider is installed
/// process-wide — reqwest checks `CryptoProvider::get_default()` explicitly
/// and never auto-selects. Every reqwest `Client` construction in this crate
/// calls this first; the binary also installs it at startup (main.rs
/// `install_tls_provider`) before any subsystem runs.
pub fn ensure_tls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
