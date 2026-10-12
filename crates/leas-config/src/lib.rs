pub mod app_config;

/// Re-exported from `leas-proto` (db-rewamp D2/D6): the split is the ONE
/// owner of a DNS name's `domain`/`sub_domain`, and `leas-db` needs it too
/// (the rank keys materialize the split), so it lives in the crate both depend on.
pub use leas_proto::domain;
pub mod base64_util;
pub mod duration_or_secs;
pub mod fast_perc;
pub mod forms;
pub mod import_export;
pub mod ip_provider;
pub mod permissive_json;
pub mod subscription;

pub use app_config::{
    AppConfig, CoreConfig, GuiConfig, InboundConfig, LogConfig, MuxConfig, ParsingSettings,
    PurgatoryConfig, StatisticsConfig, SystemProxyConfig, TunConfig, UpdateConfig,
};
pub use duration_or_secs::DurationOrSecs;
pub use import_export::{ValidationSettings, ValidationSummary, profile_user_id};
pub use ip_provider::IpProvider;
