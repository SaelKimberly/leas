//! Bounded client-side TLS 1.3 session-ticket cache.
//!
//! Tickets arrive after the handshake on the record layer; the adapter stores
//! them keyed by `(server_name, ALPN)` and the next connect may offer the PSK.

use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::crypto::CipherSuiteId;
use crate::record::engine::ReceivedTicket;

const CAP: usize = 32;

/// One cached resumption PSK and the ticket that carries it.
pub struct CachedTicket {
    pub ticket: Vec<u8>,
    pub age_add: u32,
    pub suite: CipherSuiteId,
    pub psk: Zeroizing<Vec<u8>>,
    pub alpn: Vec<u8>,
    received: Instant,
    expires: Instant,
}

impl CachedTicket {
    /// Milliseconds since the ticket was received (saturating).
    #[must_use]
    pub fn age_ms(&self) -> u32 {
        u32::try_from(self.received.elapsed().as_millis()).unwrap_or(u32::MAX)
    }
}

static CACHE: LazyLock<Mutex<Vec<(String, CachedTicket)>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// Store a received ticket; lifetime 0 was already filtered by the parser.
pub fn store(server: &str, alpn: &[u8], ticket: ReceivedTicket) {
    let lifetime = Duration::from_secs(u64::from(ticket.lifetime.min(7 * 24 * 3600)));
    let entry = CachedTicket {
        ticket: ticket.ticket,
        age_add: ticket.age_add,
        suite: ticket.suite,
        psk: ticket.psk,
        alpn: alpn.to_vec(),
        received: Instant::now(),
        expires: Instant::now() + lifetime,
    };
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cache.retain(|(host, _)| host != server);
    cache.push((server.to_string(), entry));
    if cache.len() > CAP {
        cache.remove(0);
    }
}

/// Take `server`'s ticket when one of the offered ALPN protocols matches.
pub fn take(server: &str, offered_alpn: &[&[u8]], allowed_suites: &[u16]) -> Option<CachedTicket> {
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    cache.retain(|(_, t)| t.expires > now);
    let pos = cache.iter().position(|(host, t)| {
        host == server
            && allowed_suites.contains(&t.suite.to_u16())
            && (t.alpn.is_empty() || offered_alpn.iter().any(|p| *p == t.alpn))
    })?;
    Some(cache.remove(pos).1)
}

#[cfg(test)]
pub(crate) fn test_ticket(ticket: &[u8], psk: &[u8]) -> CachedTicket {
    let suite = crate::crypto::CipherSuiteId::Aes128GcmSha256;
    CachedTicket {
        ticket: ticket.to_vec(),
        age_add: 0,
        suite,
        psk: Zeroizing::new(psk.to_vec()),
        alpn: Vec::new(),
        received: Instant::now(),
        expires: Instant::now() + Duration::from_secs(60),
    }
}
