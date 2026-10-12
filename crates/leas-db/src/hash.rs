use std::hash::{DefaultHasher, Hash, Hasher};

/// Deterministic 64-bit hash from two ordered inputs.
///
/// Uses `std::hash::DefaultHasher` (SipHash-2-4). Stable within a process but
/// not crypto-secure — suitable for `Endpoint.id` derivation.
///
/// # Examples
///
/// Known host:port → `stable_hash(host, port)`
/// Exotic config  → `stable_hash("undefined", uid_str)`
pub fn stable_hash(left: impl Hash, right: impl Hash) -> i64 {
    let mut hasher = DefaultHasher::new();
    left.hash(&mut hasher);
    right.hash(&mut hasher);
    hasher.finish().cast_signed()
}
