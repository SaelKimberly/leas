//! Secure DNS transport for leas: `sdns://` stamp parsing, a live resolver
//! pool over DNSCrypt/DoH/DoT/DoQ, and a latency probe.
//!
//! The crate owns the wire and the policy; it does not own persistence or
//! source URLs. [`parse_stamps`] turns source text into [`Candidate`]s,
//! [`fetch_source`] downloads one, [`measure`] times one candidate, and
//! [`DnsResolver`] serves lookups from whatever pool the caller installed via
//! [`DnsResolver::set_candidates`] — the app decides that pool and when it
//! changes.
//!
//! Policy, applied at parse: a stamp must claim `NO_LOGS|NO_FILTER`, its
//! transport address must be IPv4 and outside the local-use classes, and plain
//! DNS (and every unimplemented stamp kind) is refused. A refused stamp never
//! becomes a candidate.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use dns_stamp_parser::{Addr, DnsStamp, Props};
use hickory_resolver::{
    Resolver,
    config::{
        ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts, ServerOrderingStrategy,
    },
    system_conf,
};

mod dnscrypt;

/// Upper bound on a source body (the published list is under 1 MB).
pub const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;

/// Hard deadline for one source download.
const SOURCE_TIMEOUT: Duration = Duration::from_secs(10);

/// Pool behavior: 500 ms per attempt, rotate. The pool is already the measured
/// fast set, so rotation never needs to be smarter than round-robin.
static POOL_OPTS: std::sync::LazyLock<ResolverOpts> = std::sync::LazyLock::new(|| {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(500);
    // ONE send per nameserver: hickory's fixed 5 s TCP/TLS CONNECT_TIMEOUT
    // multiplied by `attempts + 1`, so the default 2 made a wedged resolver
    // cost 15 s — longer than any caller deadline — while the other pool
    // members are the failover (issue 013, decided 2026-11-23).
    opts.attempts = 1;
    opts.server_ordering_strategy = ServerOrderingStrategy::RoundRobin;
    opts
});

/// Process-wide reqwest client, built once: per-call `Client::build` pays a
/// full TLS-provider setup + connection pool on every source refresh.
/// `rustls-no-provider` needs the ring provider installed before first build —
/// done here, idempotently.
static HTTP_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    ensure_tls_provider();
    reqwest::Client::builder()
        .timeout(SOURCE_TIMEOUT)
        .build()
        .expect("reqwest client build must succeed")
});

/// Opt-in for artifact-supplied resolver addresses in the local-use classes
/// (loopback/private/link-local/multicast). Off by default, mirroring the
/// config layer's `allow_private_ips` default (finding f4).
const ALLOW_LOCAL_RESOLVERS: bool = false;

/// Whether an artifact-supplied stamp address may become the client's
/// resolver. Mirrors the host policy the config layer applies to profile hosts
/// (`crates/leas-config/src/import_export.rs`): an unspecified address is never
/// acceptable, and the local-use classes need an explicit opt-in. Without this,
/// an artifact line could point the client's own resolver at loopback/LAN/
/// metadata addresses and at arbitrary ports.
const fn stamp_addr_allowed(addr: IpAddr) -> bool {
    if ALLOW_LOCAL_RESOLVERS {
        return !addr.is_unspecified();
    }
    match addr {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast())
        }
    }
}

/// The transports this client can dial. Stored as the lowercase name the
/// database column carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsProtocol {
    Dnscrypt,
    Doh,
    Dot,
    Doq,
}

impl DnsProtocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dnscrypt => "dnscrypt",
            Self::Doh => "doh",
            Self::Dot => "dot",
            Self::Doq => "doq",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "dnscrypt" => Some(Self::Dnscrypt),
            "doh" => Some(Self::Doh),
            "dot" => Some(Self::Dot),
            "doq" => Some(Self::Doq),
            _ => None,
        }
    }
}

/// One resolver, identified by its exact stamp. Two stamps for one endpoint
/// differ by key/path and are distinct resolvers: only the live one answers.
#[derive(Clone)]
pub struct Candidate {
    /// The exact `sdns://` string — the persisted identity.
    pub stamp: String,
    pub protocol: DnsProtocol,
    /// Display endpoint: the TLS name for DoH/DoT/DoQ, the IP for `DNSCrypt`.
    pub host: String,
    pub port: u16,
    kind: Kind,
}

#[derive(Clone)]
enum Kind {
    Hickory(NameServerConfig),
    DnsCrypt(dnscrypt::DnsCryptServer),
}

/// The address a stamp dials, as a socket address.
fn stamp_addr(addr: Option<&Addr>) -> Option<SocketAddr> {
    match addr? {
        Addr::SocketAddr(addr) => Some(*addr),
        Addr::Port(_) => None,
    }
}

/// One stamp → one candidate, or `None` when the policy refuses it.
#[must_use]
pub fn candidate_from_stamp(stamp: &str) -> Option<Candidate> {
    let url = stamp.parse::<url::Url>().ok()?;
    let Ok(decoded) = DnsStamp::decode(url.as_str()) else {
        return None;
    };
    // DNSCrypt is its own wire; the parser applies the same address policy.
    if let Some(server) = dnscrypt::parse_stamp(stamp) {
        return Some(Candidate {
            stamp: stamp.to_string(),
            protocol: DnsProtocol::Dnscrypt,
            host: server.addr.ip().to_string(),
            port: server.addr.port(),
            kind: Kind::DnsCrypt(server),
        });
    }
    let (protocol, host, port, config) = match decoded {
        DnsStamp::DnsOverHttps(s) => {
            let addr = stamp_addr(s.addr.as_ref())?;
            allowed(addr, &s.props)?;
            let host = s.hostname;
            let mut conn =
                ConnectionConfig::https(Arc::from(host.as_str()), Some(Arc::from(s.path)));
            conn.port = addr.port();
            (
                DnsProtocol::Doh,
                host,
                addr.port(),
                NameServerConfig::new(addr.ip(), true, vec![conn]),
            )
        }
        DnsStamp::DnsOverTls(s) => {
            let addr = stamp_addr(s.addr.as_ref())?;
            allowed(addr, &s.props)?;
            let host = s.hostname;
            let mut conn = ConnectionConfig::tls(Arc::from(host.as_str()));
            conn.port = addr.port();
            (
                DnsProtocol::Dot,
                host,
                addr.port(),
                NameServerConfig::new(addr.ip(), true, vec![conn]),
            )
        }
        DnsStamp::DnsOverQuic(s) => {
            let addr = stamp_addr(s.addr.as_ref())?;
            allowed(addr, &s.props)?;
            let host = s.hostname;
            let mut conn = ConnectionConfig::quic(Arc::from(host.as_str()));
            conn.port = addr.port();
            (
                DnsProtocol::Doq,
                host,
                addr.port(),
                NameServerConfig::new(addr.ip(), true, vec![conn]),
            )
        }
        // A plain stamp carries no authenticated transport, so its answers are
        // forgeable by anyone on the path; never install one from artifact data.
        // The same holds for any stamp kind this client does not implement.
        _ => return None,
    };
    Some(Candidate {
        stamp: stamp.to_string(),
        protocol,
        host,
        port,
        kind: Kind::Hickory(config),
    })
}

/// Policy gate: address family/local use plus the `NO_LOGS|NO_FILTER` claim.
fn allowed(addr: SocketAddr, props: &Props) -> Option<()> {
    (addr.is_ipv4()
        && stamp_addr_allowed(addr.ip())
        && props.contains(Props::NO_LOGS)
        && props.contains(Props::NO_FILTER))
    .then_some(())
}

/// Parses source text into candidates, deduplicated by the exact stamp.
///
/// Non-`sdns://` lines (markdown headers, comments, blank lines) are ignored.
/// Stamp addresses stay IPv4-only: 467 of 893 published stamps are IPv6-only,
/// and with no IPv6 route each one burns a dial timeout.
#[must_use]
pub fn parse_stamps(text: &str) -> Vec<Candidate> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("sdns://"))
    {
        if !seen.insert(line) {
            continue;
        }
        if let Some(candidate) = candidate_from_stamp(line) {
            out.push(candidate);
        }
    }
    out
}

/// Idempotent install of the process-level rustls `CryptoProvider` (ring).
/// Required before any reqwest `Client::build` — reqwest 0.13 is built with
/// `rustls-no-provider` and panics otherwise.
fn ensure_tls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Downloads one resolver source, bounded by [`SOURCE_TIMEOUT`] and
/// [`MAX_SOURCE_BYTES`].
///
/// Without the size cap a hostile or broken endpoint can exhaust memory;
/// without the timeout a blocked network hangs the refresh.
pub async fn fetch_source(url: &str) -> anyhow::Result<String> {
    let mut response = HTTP_CLIENT.get(url).send().await?.error_for_status()?;
    if let Some(n) = response.content_length()
        && n > MAX_SOURCE_BYTES as u64
    {
        anyhow::bail!("resolver source declares {n} bytes, over the {MAX_SOURCE_BYTES}-byte cap");
    }
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > MAX_SOURCE_BYTES {
            anyhow::bail!("resolver source exceeds the {MAX_SOURCE_BYTES}-byte cap");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8(bytes)?)
}

/// One candidate's measured outcome. `latency_ms` is present exactly when the
/// lookup returned at least one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestOutcome {
    pub stamp: String,
    /// Wall time from the call to a non-empty answer, in whole milliseconds.
    pub latency_ms: Option<u32>,
    /// The error class on failure; `None` on success.
    pub error: Option<String>,
}

/// Builds a resolver over `candidates` with the given options.
fn build_resolver(
    candidates: &[Candidate],
    opts: &ResolverOpts,
) -> anyhow::Result<Resolver<dnscrypt::DnsCryptProvider>> {
    let mut config = ResolverConfig::default();
    let mut servers = Vec::new();
    for candidate in candidates {
        match &candidate.kind {
            Kind::Hickory(name_server) => config.add_name_server(name_server.clone()),
            Kind::DnsCrypt(server) => {
                config.add_name_server(dnscrypt::name_server_config(server));
                servers.push(server.clone());
            }
        }
    }
    let provider = dnscrypt::DnsCryptProvider::new(&servers);
    Ok(Resolver::builder_with_config(config, provider)
        .with_options(opts.clone())
        .build()?)
}

/// Times one candidate against `domain`. Never fails: a build error is an
/// outcome with its message.
async fn measure_one(candidate: &Candidate, domain: &str, timeout: Duration) -> TestOutcome {
    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;
    opts.attempts = 1;
    let resolver = match build_resolver(std::slice::from_ref(candidate), &opts) {
        Ok(resolver) => resolver,
        Err(e) => {
            return TestOutcome {
                stamp: candidate.stamp.clone(),
                latency_ms: None,
                error: Some(e.to_string()),
            };
        }
    };
    let started = Instant::now();
    match tokio::time::timeout(timeout, resolver.lookup_ip(domain)).await {
        Ok(Ok(answer)) if answer.iter().next().is_some() => TestOutcome {
            stamp: candidate.stamp.clone(),
            latency_ms: Some(u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX)),
            error: None,
        },
        Ok(Ok(_)) => TestOutcome {
            stamp: candidate.stamp.clone(),
            latency_ms: None,
            error: Some("empty answer".to_string()),
        },
        Ok(Err(e)) => TestOutcome {
            stamp: candidate.stamp.clone(),
            latency_ms: None,
            error: Some(e.to_string()),
        },
        Err(_) => TestOutcome {
            stamp: candidate.stamp.clone(),
            latency_ms: None,
            error: Some("timed out".to_string()),
        },
    }
}

/// Measures every candidate against `domain`, at most `concurrency` in flight.
/// Results keep the input order.
pub async fn measure(
    candidates: &[Candidate],
    domain: &str,
    timeout: Duration,
    concurrency: usize,
) -> Vec<TestOutcome> {
    let mut out = Vec::with_capacity(candidates.len());
    // `join_all` per chunk, not a `buffered` stream: the stream adapter needs
    // the per-item future type to be uniform across lifetimes, which a future
    // borrowing `domain` is not (the spawn in `ops::dns` saw it as
    // "FnOnce is not general enough"). Chunking is the same concurrency bound.
    for chunk in candidates.chunks(concurrency.max(1)) {
        out.extend(
            futures_util::future::join_all(
                chunk
                    .iter()
                    .map(|candidate| measure_one(candidate, domain, timeout)),
            )
            .await,
        );
    }
    out
}

/// The OS resolver configuration as a pool, or `None` when the host has none
/// (a container without `resolv.conf`, a registry failure). A missing
/// configuration is a lookup error, never a panic: `lookup_ip` runs inside the
/// routing engine's connection task.
fn build_system_resolver() -> Option<Arc<Resolver<dnscrypt::DnsCryptProvider>>> {
    let (config, opts) = system_conf::read_system_conf().ok()?;
    Resolver::builder_with_config(config, dnscrypt::DnsCryptProvider::new(&[]))
        .with_options(opts)
        .build()
        .ok()
        .map(Arc::new)
}

/// The live resolver pool. Reads are one atomic load; a swap is rare and sync.
///
/// `ArcSwapOption` (not a lock): the read side is every lookup, and
/// `load_full` hands the `Arc` back with no guard, so an in-flight lookup
/// finishes on the pool it started with while every holder — including the
/// routing adapter's `Arc<DnsResolver>` — sees the next one.
pub struct DnsResolver {
    resolver: ArcSwapOption<Resolver<dnscrypt::DnsCryptProvider>>,
    /// OS resolver config, built at most once and never replaced: the fallback
    /// when no candidates are installed. `None` caches an unreadable
    /// configuration instead of panicking on every lookup.
    system: OnceLock<Option<Arc<Resolver<dnscrypt::DnsCryptProvider>>>>,
}

impl DnsResolver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            resolver: ArcSwapOption::empty(),
            system: OnceLock::new(),
        }
    }

    /// Installs a new pool. An empty slice leaves the resolver unconfigured
    /// (lookups fall back to the OS configuration).
    pub fn set_candidates(&self, candidates: &[Candidate]) -> anyhow::Result<()> {
        if candidates.is_empty() {
            self.resolver.store(None);
            return Ok(());
        }
        let resolver = build_resolver(candidates, &POOL_OPTS)?;
        self.resolver.store(Some(Arc::new(resolver)));
        Ok(())
    }

    /// Whether a pool is installed (the UI's "no resolvers yet" state).
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.resolver.load().is_some()
    }

    /// Resolves `hostname`, returning all addresses as a boxed slice — one
    /// contiguous allocation, no growth headroom, so cache and callers hold
    /// exactly the answer. IPv6 results are included when `allow_ipv6`.
    pub async fn lookup_ip(
        &self,
        hostname: &str,
        allow_ipv6: bool,
    ) -> anyhow::Result<Box<[IpAddr]>> {
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            return Ok(vec![ip].into_boxed_slice());
        }
        let Some(resolver) = self
            .resolver
            .load_full()
            .or_else(|| self.system.get_or_init(build_system_resolver).clone())
        else {
            anyhow::bail!(
                "no resolver pool installed and the OS resolver configuration is unreadable"
            );
        };
        let ips: Vec<IpAddr> = resolver
            .lookup_ip(hostname)
            .await?
            .iter()
            .filter(|ip| allow_ipv6 || ip.is_ipv4())
            .collect();
        Ok(ips.into_boxed_slice())
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A dns.aa.net.uk `DoH` stamp published with an IPv4 address.
    const STAMP_IPV4: &str =
        "sdns://AgcAAAAAAAAADTIxNy4xNjkuMjAuMjIADWRucy5hYS5uZXQudWsKL2Rucy1xdWVyeQ";
    /// The same resolver published with an IPv6-only address.
    const STAMP_IPV6: &str =
        "sdns://AgcAAAAAAAAAEFsyMDAxOjhiMDo6MjAyMl0ADWRucy5hYS5uZXQudWsKL2Rucy1xdWVyeQ";
    /// `AdGuard` `2.dnscrypt.unfiltered.ns1.adguard.com`.
    const STAMP_DNSCRYPT: &str = "sdns://AQcAAAAAAAAAEjk0LjE0MC4xNC4xNDA6NTQ0MyC16ETWuDo-PhJo62gfvqcN48X6aNvWiBQdvy7AZrLa-iUyLmRuc2NyeXB0LnVuZmlsdGVyZWQubnMxLmFkZ3VhcmQuY29t";

    /// Serves `body` as a single HTTP response on an ephemeral loopback port,
    /// returning the URL. Lets the download path run without the network.
    async fn serve(body: String) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        std::mem::drop(tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        }));
        format!("http://{addr}/public-resolvers.md")
    }

    #[test]
    fn parse_stamps_dedupes_and_applies_policy() {
        // The markdown header, a duplicate, an IPv6-only stamp, a bogus line
        // and a plain stamp must all collapse to the one usable candidate.
        let text = format!(
            "# DNSCrypt resolver list\n{STAMP_IPV4}\nnot a stamp\n{STAMP_IPV4}\n{STAMP_IPV6}\nsdns://AAYAAAAAAAAACTEyNy4wLjAuMQ\n"
        );
        let parsed = parse_stamps(&text);
        assert_eq!(parsed.len(), 1, "only the IPv4 DoH stamp is usable");
        assert_eq!(parsed[0].protocol, DnsProtocol::Doh);
        assert_eq!(parsed[0].host, "dns.aa.net.uk");
        assert_eq!(parsed[0].port, 443);
    }

    #[test]
    fn dnscrypt_stamps_become_candidates() {
        let parsed = parse_stamps(&format!("# list\n{STAMP_DNSCRYPT}\n"));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].protocol, DnsProtocol::Dnscrypt);
        assert_eq!(parsed[0].host, "94.140.14.140");
        assert_eq!(parsed[0].port, 5443);
    }

    #[test]
    fn stamp_addr_policy_matches_host_policy() {
        for bad in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "::",
        ] {
            assert!(
                !stamp_addr_allowed(bad.parse().unwrap()),
                "{bad} must be refused"
            );
        }
        for good in [
            "1.1.1.1",
            "8.8.8.8",
            "217.169.20.22",
            "2606:4700:4700::1111",
        ] {
            assert!(
                stamp_addr_allowed(good.parse().unwrap()),
                "{good} must be allowed"
            );
        }
    }

    /// A plain (unauthenticated) stamp and a stamp pointing at a local-use
    /// address must both be refused, while the published public stamp is still
    /// accepted (finding f4).
    #[test]
    fn plain_and_local_stamps_never_become_candidates() {
        // Plain 127.0.0.1, props NO_LOGS|NO_FILTER.
        const PLAIN_LOOPBACK: &str = "sdns://AAYAAAAAAAAACTEyNy4wLjAuMQ";
        // DoT 127.0.0.1:<port>, TLS name v12-verify.example.
        const DOT_LOOPBACK: &str =
            "sdns://AwYAAAAAAAAADzEyNy4wLjAuMTozMzk5OQASdjEyLXZlcmlmeS5leGFtcGxl";
        for stamp in [PLAIN_LOOPBACK, DOT_LOOPBACK] {
            assert!(
                candidate_from_stamp(stamp).is_none(),
                "must be refused: {stamp}"
            );
        }
        assert!(candidate_from_stamp(STAMP_IPV4).is_some());
    }

    #[test]
    fn an_empty_pool_leaves_the_resolver_unconfigured() {
        let resolver = DnsResolver::new();
        assert!(!resolver.is_configured());
        resolver.set_candidates(&[]).unwrap();
        assert!(!resolver.is_configured());
        let candidates = parse_stamps(&format!("{STAMP_IPV4}\n"));
        resolver.set_candidates(&candidates).unwrap();
        assert!(resolver.is_configured());
    }

    /// A TCP listener that accepts and never answers: the probe must time out
    /// and report the class, not hang.
    #[tokio::test]
    async fn measure_times_out_a_stalled_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        std::mem::drop(tokio::spawn(async move {
            // Hold every accepted stream open without writing.
            // Leak every accepted stream: the point is a connected peer that
            // never answers, and a dropped stream would close it.
            while let Ok((stream, _)) = listener.accept().await {
                std::mem::forget(stream);
            }
        }));
        let mut conn = ConnectionConfig::tls(Arc::from("stalled.example"));
        conn.port = addr.port();
        let candidate = Candidate {
            stamp: "sdns://test-stalled".to_string(),
            protocol: DnsProtocol::Dot,
            host: "stalled.example".to_string(),
            port: addr.port(),
            kind: Kind::Hickory(NameServerConfig::new(addr.ip(), true, vec![conn])),
        };
        let started = Instant::now();
        let outcomes = measure(&[candidate], "example.com", Duration::from_millis(200), 1).await;
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].latency_ms.is_none());
        assert_eq!(outcomes[0].error.as_deref(), Some("timed out"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn fetch_source_refuses_an_oversized_body() {
        let url = serve("x".repeat(MAX_SOURCE_BYTES + 1)).await;
        let err = fetch_source(&url)
            .await
            .expect_err("an over-cap body must be refused");
        assert!(
            err.to_string().contains("cap"),
            "error names the cap: {err}"
        );
    }

    #[tokio::test]
    async fn fetch_source_returns_the_body() {
        let url = serve(format!("# list\n{STAMP_IPV4}\n")).await;
        let body = fetch_source(&url).await.expect("body");
        assert_eq!(parse_stamps(&body).len(), 1);
    }

    /// The `DNSCrypt` transport end to end: one published server stamp and no
    /// hickory name server at all.
    #[tokio::test]
    #[ignore = "requires network (DNSCrypt resolver)"]
    async fn live_dnscrypt_only_lookup() -> anyhow::Result<()> {
        let resolver = DnsResolver::new();
        resolver.set_candidates(&parse_stamps(STAMP_DNSCRYPT))?;
        let ips = resolver.lookup_ip("example.com", true).await?;
        assert!(!ips.is_empty(), "DNSCrypt lookup returned no address");
        Ok(())
    }

    /// A minimal UDP DNS responder: one A record `203.0.113.7` for every
    /// query. Proves `set_candidates` installs a pool that SERVES a lookup,
    /// not merely `is_configured`.
    async fn serve_dns() -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        std::mem::drop(tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                if len < 12 {
                    continue;
                }
                // End of the question: labels, then QTYPE + QCLASS.
                let mut off = 12;
                while off < len && buf[off] != 0 {
                    off += usize::from(buf[off]) + 1;
                }
                off = (off + 5).min(len);
                let mut response = Vec::with_capacity(off + 16);
                response.extend_from_slice(&buf[..off]);
                response[2] = 0x81; // QR=1, RD=1
                response[3] = 0x80; // RA=1, rcode=0
                response[6] = 0; // ANCOUNT = 1
                response[7] = 1;
                response[8] = 0; // NSCOUNT = 0
                response[9] = 0;
                response[10] = 0; // ARCOUNT = 0 (drop any EDNS OPT)
                response[11] = 0;
                response.extend_from_slice(&[
                    0xC0, 0x0C, // name: pointer to the question
                    0x00, 0x01, // A
                    0x00, 0x01, // IN
                    0x00, 0x00, 0x00, 0x3C, // TTL 60
                    0x00, 0x04, // RDLENGTH
                    203, 0, 113, 7,
                ]);
                let _ = socket.send_to(&response, peer).await;
            }
        }));
        addr
    }

    /// The swap is only useful if the installed candidate actually answers.
    #[tokio::test]
    async fn a_pool_serves_a_lookup_from_the_installed_candidate() {
        let addr = serve_dns().await;
        let mut conn = ConnectionConfig::udp();
        conn.port = addr.port();
        let candidate = Candidate {
            stamp: "sdns://test-udp".to_string(),
            // Label only; `Kind` decides the wire.
            protocol: DnsProtocol::Dot,
            host: "test.local".to_string(),
            port: addr.port(),
            kind: Kind::Hickory(NameServerConfig::new(addr.ip(), true, vec![conn])),
        };
        let resolver = DnsResolver::new();
        resolver
            .set_candidates(&[candidate])
            .expect("install the pool");
        let ips = resolver
            .lookup_ip("example.com", true)
            .await
            .expect("lookup");
        assert_eq!(
            ips.as_ref(),
            [IpAddr::from([203, 0, 113, 7])],
            "the installed candidate must answer"
        );
    }

    /// A real `DoH` pool through the same path the app uses.
    #[tokio::test]
    #[ignore = "requires network (DoH resolver)"]
    async fn live_doh_lookup() -> anyhow::Result<()> {
        let resolver = DnsResolver::new();
        resolver.set_candidates(&parse_stamps(STAMP_IPV4))?;
        let ips = resolver.lookup_ip("example.com", true).await?;
        assert!(!ips.is_empty());
        Ok(())
    }
}
