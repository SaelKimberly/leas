pub mod bin_manager;
pub mod config_builder;
pub mod core_type;
pub mod dns;
pub mod grpc_client;
pub mod log_heed;
pub mod ping;
pub mod process;
pub mod speed_test;
pub mod updater;

pub use bin_manager::{CoreBinInfo, find_binary, get_core_info};

pub use config_builder::{
    BackendConfig, BuildError, BuildParams, CLASH_API_PORT, ConfigBuilder, shadowsocks_method,
};
pub use core_type::CoreType;
pub use grpc_client::{
    API_ENDPOINT, GrpcError, StatsProvider, SysStats, create_stats_provider, format_bytes,
    format_uptime,
};
pub use log_heed::HeedLogStorage;
#[cfg(feature = "quic-ping")]
pub use ping::QuicPingAdapter;
pub use ping::{
    FastPingAdapter, FastPingManager, IoFailure, PingCapability, PingError, TcpPingAdapter,
    UdpPingAdapter,
};
pub use process::{CoreManager, MockCoreManager, ProcessError, RealCoreManager};
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
pub use leas_proto::proto_spec::core_mapping::{
    SINGBOX_ONLY_KINDS, SINGBOX_SS_METHODS, XRAY_SS_METHODS, resolve_core,
    singbox_supports_ss_method, ss_method_supported, xray_supports_ss_method,
};
