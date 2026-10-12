//! First-match routing engine primitives (addr/error foundation).

pub mod addr;
pub mod compiler;
#[cfg(feature = "dns")]
pub mod dns_adapter;
pub mod engine;
pub mod error;
pub mod events;
pub mod ir;
pub mod matchers;
pub mod resolve;
pub mod sniff;

pub use addr::{Cidr, NetAddr, NetHost, PortRange};
pub use compiler::{CompileOutput, compile_singbox, compile_xray};
#[cfg(feature = "dns")]
pub use dns_adapter::DnsSinkAdapter;
pub use engine::{ConnMeta, Decision, Engine};
pub use error::RouteError;
pub use events::RouteEvent;
pub use resolve::{DnsSink, ProbeTracker, ResolvedCache};
pub use sniff::{QuicSniffProgress, QuicSniffer, SniffResult, SniffedProtocol, probe};
