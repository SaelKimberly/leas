//! Per-module memory tracing for the leas workspace.
//!
//! Adapted from [`leaktracer`](https://github.com/veeso/leaktracer), which
//! intercepts every allocation, walks the call stack and charges the bytes to
//! the module that asked for them. The port keeps the accounting model (live
//! bytes and live count per symbol, decremented on free) and replaces the parts
//! that do not survive a multi-threaded application:
//!
//! - leaktracer symbolizes a fresh backtrace on **every** allocation and stores
//!   the pointer in a `ptr → symbol` map under one global mutex. Here the
//!   capture is frame-pointer only, the module is resolved **once per distinct
//!   instruction pointer** through a direct-mapped cache, and the symbol id
//!   travels in an 8-byte header in front of the payload, so a free is an O(1)
//!   header read with no map and no lock.
//! - leaktracer leaks a `String` per allocation for the demangled name. Here a
//!   module name is stored once, owned, in a registry the hot path never
//!   touches: no `Box::leak`, no per-allocation name growth.
//! - leaktracer exposes a live `Mutex<SymbolTable>` to the caller. Here the
//!   counters are plain atomics and the caller takes a [`Snapshot`].
//!
//! ## Scope
//!
//! Attribution is by **module path**, not by function: release builds inline
//! aggressively and `debug = 0` keeps the symbol table but drops inlining
//! information, so a function-granularity claim would be wrong in exactly the
//! builds people profile.
//!
//! The tracer sees its own process only. leas launches core child processes;
//! their memory is invisible here by construction, and every artifact header
//! says so.
//!
//! ## Usage
//!
//! ```ignore
//! #[global_allocator]
//! static GLOBAL: leas_memtrace::TracingAllocator = leas_memtrace::TracingAllocator::new();
//!
//! fn main() {
//!     leas_memtrace::start(&["leas"], 0);
//!     // … workload …
//!     leas_memtrace::write(Path::new("target/mem-trace"), "import").unwrap();
//! }
//! ```
//!
//! Rows are keyed by module path and ordered by live bytes. Allocations with no
//! workspace frame — and those below the configured minimum size — are charged
//! to the `<untraced>` row so the rows always sum to the allocator's own live
//! total.

mod alloc;
mod artifact;
mod attrib;
mod table;

pub use alloc::TracingAllocator;
pub use artifact::{Artifacts, CacheCounters, Row, Snapshot, Totals, snapshot, write};
pub use attrib::{is_started, live_bytes, start};

/// The row that collects allocations with no workspace frame, and those below
/// the configured minimum size.
pub const UNTRACED_ROW: &str = "<untraced>";
