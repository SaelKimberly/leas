//! Per-link `AnyTLS` client: session pool plus the dial that feeds it.
//!
//! The protocol mandates reuse (spec "复用"): a new stream goes on the newest
//! idle session, a fresh TLS session is opened only when none is idle, and
//! idle sessions are reaped after a timeout. One `Client` exists per link
//! identity for the process lifetime — the identity is the serialize of the
//! protocol config plus the endpoint, which is exactly what the session's TLS
//! handshake and password depend on.
//!
//! Only the FIRST link of a chain pools. A later `AnyTLS` hop is carried by an
//! upstream tunnel, so its "dial" is the caller's stream, not a socket to the
//! server — `connect_pooled` is the first-link entry point and
//! `super::connect` the per-stream one.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant};

use leas_proto::proto_spec::ProtocolConfig;

use super::padding::PaddingScheme;
use super::session::{Padding, Session};
use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::NativeError;

/// How often the reaper scans idle sessions.
const CHECK_INTERVAL: Duration = Duration::from_secs(30);
/// How long a session may sit idle before it is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Idle sessions kept regardless of age (the protocol's `minIdleSession`).
const MIN_IDLE: usize = 2;

/// The identity-keyed client registry.
static POOL: LazyLock<Mutex<HashMap<String, Arc<Client>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// One link's sessions.
pub struct Client {
    padding: Arc<Padding>,
    sessions: Mutex<Vec<Arc<Session>>>,
    seq: AtomicU64,
}

/// Entry point for the first chain link: reuse an idle session or dial.
pub async fn connect_pooled(ctx: &LinkContext) -> Result<BoxStream, NativeError> {
    let client = client_for(ctx);
    let session = client.session(ctx).await?;
    let stream = session.open_stream(&ctx.target).await?;
    Ok(Box::new(stream))
}

impl Client {
    const fn new(padding: Arc<Padding>) -> Self {
        Self {
            padding,
            sessions: Mutex::new(Vec::new()),
            seq: AtomicU64::new(0),
        }
    }

    /// Newest idle session, or a freshly dialed one.
    async fn session(&self, ctx: &LinkContext) -> Result<Arc<Session>, NativeError> {
        {
            // Newest-first: the protocol's documented preference.
            let sessions = self.sessions.lock().expect("anytls pool lock poisoned");
            if let Some(session) = sessions
                .iter()
                .rev()
                .find(|session| session.is_idle())
                .cloned()
            {
                // Touch under the lock: the reaper cannot pick it afterwards.
                session.touch();
                return Ok(session);
            }
        }
        let stream = dial(ctx).await?;
        let password = match &ctx.params.protocol {
            ProtocolConfig::AnyTls(cfg) => cfg
                .password
                .as_deref()
                .filter(|password| !password.is_empty())
                .ok_or_else(|| NativeError::Config("anytls: missing password".into()))?,
            other => {
                return Err(NativeError::Config(format!(
                    "anytls pool asked to dial {other:?}"
                )));
            }
        };
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let session = Arc::new(
            Session::start(stream, password, self.padding.clone(), ctx.ack.clone(), seq).await?,
        );
        self.sessions
            .lock()
            .expect("anytls pool lock poisoned")
            .push(session.clone());
        Ok(session)
    }

    /// Drop dead sessions and close idle ones past the timeout, keeping the
    /// newest [`MIN_IDLE`].
    fn reap(&self, now: Instant) {
        let mut sessions = self.sessions.lock().expect("anytls pool lock poisoned");
        sessions.retain(|session| !session.is_dead());
        let mut idle: Vec<Arc<Session>> = sessions
            .iter()
            .filter(|session| session.is_idle())
            .cloned()
            .collect();
        idle.sort_by_key(|session| std::cmp::Reverse(session.seq));
        let expired: Vec<Arc<Session>> = idle
            .into_iter()
            .skip(MIN_IDLE)
            .filter(|session| now.duration_since(session.idle_since()) >= IDLE_TIMEOUT)
            .collect();
        sessions.retain(|session| !expired.iter().any(|gone| gone.seq == session.seq));
        drop(sessions);
        for session in expired {
            session.close();
        }
    }
}

/// The pooled client for a link, created (with its reaper) on first use.
fn client_for(ctx: &LinkContext) -> Arc<Client> {
    let key = pool_key(ctx);
    let mut pool = POOL.lock().expect("anytls pool registry poisoned");
    if let Some(client) = pool.get(&key) {
        return client.clone();
    }
    // The padding scheme is shared across the link's sessions; a server update
    // received on one session applies to every session created afterwards.
    let padding = Arc::new(std::sync::RwLock::new(Arc::new(
        PaddingScheme::default_scheme().clone(),
    )));
    let client = Arc::new(Client::new(padding));
    pool.insert(key, client.clone());
    drop(pool);

    let weak = Arc::downgrade(&client);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(CHECK_INTERVAL);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let Some(client) = Weak::upgrade(&weak) else {
                return;
            };
            client.reap(Instant::now());
        }
    });
    client
}

/// Every parameter that changes what a session authenticates as or how it is
/// dialed. Two rows that differ only in remarks share a client.
fn pool_key(ctx: &LinkContext) -> String {
    // `Debug` is the deterministic, total serialization available here: it
    // covers every field of both values (the typed configs derive `Serialize`
    // but this crate has no JSON dependency). A pool key only has to separate
    // links within one process, so a change to the debug format at worst
    // starts a fresh pool.
    format!("{:?}|{:?}", ctx.params.protocol, ctx.params.server)
}

/// Dial one new session's TLS stream through the standard pipeline.
///
/// `AnyTLS` has no transport upgrade (the capability gate refuses one), so this
/// is exactly `dial → TLS`, the same two calls `chain::connect_chain` makes.
async fn dial(ctx: &LinkContext) -> Result<BoxStream, NativeError> {
    let dialed = crate::transport::connect(ctx, None).await?;
    crate::chain::secured_upgraded(ctx, dialed).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::protocol::AuthAck;
    use crate::protocol::AuthAckSlot;

    fn padding() -> Arc<Padding> {
        Arc::new(std::sync::RwLock::new(Arc::new(
            PaddingScheme::default_scheme().clone(),
        )))
    }

    /// Four idle sessions, all past the timeout: the reaper keeps exactly the
    /// newest [`MIN_IDLE`] and closes the rest.
    #[tokio::test]
    async fn reaper_keeps_the_newest_idle_sessions_and_closes_the_rest() {
        let padding = padding();
        let client = Client::new(padding.clone());
        for seq in 1..=4 {
            let (client_half, _peer) = tokio::io::duplex(1024);
            let session = Session::start(
                Box::new(client_half),
                "secret",
                padding.clone(),
                AuthAckSlot::new(AuthAck::Unknown),
                seq,
            )
            .await
            .expect("session starts");
            client
                .sessions
                .lock()
                .expect("pool")
                .push(Arc::new(session));
        }
        assert_eq!(client.sessions.lock().expect("pool").len(), 4);

        client.reap(Instant::now() + IDLE_TIMEOUT + Duration::from_secs(1));

        let mut seqs: Vec<u64> = {
            let remaining = client.sessions.lock().expect("pool");
            assert_eq!(remaining.len(), MIN_IDLE);
            remaining.iter().map(|session| session.seq).collect()
        };
        seqs.sort_unstable();
        assert_eq!(seqs, vec![3, 4], "the newest idle sessions stay");
    }
}
