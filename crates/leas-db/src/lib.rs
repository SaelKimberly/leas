pub mod error;
pub mod hash;
pub use hash::stable_hash;
pub mod models_toasty;
pub use database::{
    Database, DnsCandidateRow, LinkGroups, LinkPatch, SCHEMA_VERSION,
    upsert_endpoint_group_links_bulk, upsert_endpoints_bulk, upsert_links_bulk,
    upsert_protocols_bulk,
};
pub use endpoint_rank::{RankRow, compute_rank, rank_of_row, weight_of_protocol};
pub use error::{DatabaseError, Result};
pub use leas_proto::proto_spec::weight;
pub use models_toasty as models;
pub use models_toasty::EndpointRank;
pub use models_toasty::RouteProbes;
pub use retry::{is_busy_error, retry_on_busy};
/// Persisted discriminator for a link the native engine cannot serve
/// (`profile_stats.error_text`).
///
/// The storage owner defines it so the binary's writer/readers and the
/// one-time capability clear cannot drift.
pub const UNTESTABLE_PREFIX: &str = "not testable by the native engine: ";

pub use write_behind::{
    CacheSpec, Coalesced, CountryPatch, CountryRow, CountrySpec, LinkRow, LinkSpec, LinkStageKey,
    SourceBatch, SourcePatch, SourceSpec, WriteBehind,
};

pub mod database;
pub mod driver;
pub mod endpoint_ip;
pub mod endpoint_rank;
pub mod export;
pub mod merge;
pub mod profiles_query;
mod retry;
pub mod schema;
pub mod write_behind;
