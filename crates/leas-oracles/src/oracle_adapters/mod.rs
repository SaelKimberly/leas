//! Oracle-side adapters moved out of `leas-core`.
//!
//! The TUI client is native-only; these modules exist only so the e2e oracles
//! can generate a config pair and launch the pinned Xray-core / sing-box
//! binaries. They compile whenever `leas-oracles` is built (which is an
//! explicit `-p leas-oracles` only), never in the client graph.

pub mod bin_manager;
pub mod config_builder;
pub mod core_mapping;
pub mod core_type;
pub mod grpc_client;
pub mod process;
pub mod updater;

pub use bin_manager::{CoreBinInfo, find_binary, get_core_info};
pub use config_builder::{
    BackendConfig, BuildError, BuildParams, CLASH_API_PORT, ConfigBuilder, shadowsocks_method,
};
pub use core_mapping::{
    SINGBOX_ONLY_KINDS, SINGBOX_SS_METHODS, XRAY_SS_METHODS, resolve_core,
    singbox_supports_ss_method, ss_method_supported, xray_supports_ss_method,
};
pub use core_type::CoreType;
pub use grpc_client::{API_ENDPOINT, GrpcError, StatsProvider, create_stats_provider};
pub use process::{CoreManager, MockCoreManager, ProcessError, RealCoreManager};
pub use updater::*;
