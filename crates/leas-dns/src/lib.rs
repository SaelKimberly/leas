use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dns_stamp_parser::{Addr, DnsStamp, Props};
use hickory_resolver::{
    Resolver, TokioResolver,
    config::{
        ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts, ServerOrderingStrategy,
    },
    net::runtime::TokioRuntimeProvider,
    system_conf,
};
use tokio::io::AsyncWriteExt;

const DNSCRYPT_RESOLVERS_URL: &str =
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md";
const DNSCRYPT_RESOLVERS_CACHE: &str = "dsncrypt.resolvers.txt";
/// Cached resolver lists older than this are refreshed on the next lookup.
const DNSCRYPT_CACHE_MAX_AGE: Duration = Duration::from_hours(168);

static DEFAULT_RESOLVER_OPTS: std::sync::LazyLock<ResolverOpts> = std::sync::LazyLock::new(|| {
    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.timeout = Duration::from_millis(500);
    resolver_opts.server_ordering_strategy = ServerOrderingStrategy::RoundRobin;
    resolver_opts
});

/// Process-wide reqwest client, built once: per-call `Client::build` pays
/// a full TLS-provider setup + connection pool on every `DNSCrypt` list
/// refresh. `rustls-no-provider` needs the ring provider installed before
/// first build — done here, idempotently.
static HTTP_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    ensure_tls_provider();
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client build must succeed")
});

/// Opt-in for artifact-supplied resolver addresses in the local-use classes
/// (loopback/private/link-local/multicast). Off by default, mirroring the
/// config layer's `allow_private_ips` default (finding f4).
const ALLOW_LOCAL_RESOLVERS: bool = false;

/// Whether an artifact-supplied stamp address may become the client's
/// resolver. Mirrors the host policy the config layer applies to profile
/// hosts (`crates/leas-config/src/import_export.rs`): an unspecified
/// address is never acceptable, and the local-use classes need an explicit
/// opt-in. Without this, an artifact line could point the client's own
/// resolver at loopback/LAN/metadata addresses and at arbitrary ports.
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

fn sdns_to_nsc(url: &url::Url, allow_ipv6: bool) -> Option<NameServerConfig> {
    let Ok(stamp) = DnsStamp::decode(url.as_str()) else {
        return None;
    };
    match stamp {
        DnsStamp::DnsOverHttps(s) => {
            if let Some(Addr::SocketAddr(addr)) = s.addr
                && (allow_ipv6 || addr.is_ipv4())
                && stamp_addr_allowed(addr.ip())
                && s.props.contains(Props::NO_LOGS)
                && s.props.contains(Props::NO_FILTER)
            {
                let mut conn =
                    ConnectionConfig::https(Arc::from(s.hostname), Some(Arc::from(s.path)));
                conn.port = addr.port();
                Some(NameServerConfig::new(addr.ip(), true, vec![conn]))
            } else {
                None
            }
        }
        DnsStamp::DnsOverTls(s) => {
            if let Some(Addr::SocketAddr(addr)) = s.addr
                && (allow_ipv6 || addr.is_ipv4())
                && stamp_addr_allowed(addr.ip())
                && s.props.contains(Props::NO_LOGS)
                && s.props.contains(Props::NO_FILTER)
            {
                let mut conn = ConnectionConfig::tls(Arc::from(s.hostname));
                conn.port = addr.port();
                Some(NameServerConfig::new(addr.ip(), true, vec![conn]))
            } else {
                None
            }
        }
        DnsStamp::DnsOverQuic(s) => {
            if let Some(Addr::SocketAddr(addr)) = s.addr
                && (allow_ipv6 || addr.is_ipv4())
                && stamp_addr_allowed(addr.ip())
                && s.props.contains(Props::NO_LOGS)
                && s.props.contains(Props::NO_FILTER)
            {
                let mut conn = ConnectionConfig::quic(Arc::from(s.hostname));
                conn.port = addr.port();
                Some(NameServerConfig::new(addr.ip(), true, vec![conn]))
            } else {
                None
            }
        }
        // A plain stamp carries no authenticated transport, so its answers are
        // forgeable by anyone on the path; never install one from artifact data.
        // The same holds for any stamp kind this client does not implement.
        _ => None,
    }
}

/// Parses `DNSCrypt` resolver list text (fetched markdown or cache file) into
/// name server configs. Lines that are not `sdns://` stamps, or that do not
/// decode to a usable resolver, are skipped.
fn parse_dnscrypt_lines(text: &str) -> Vec<NameServerConfig> {
    text.lines()
        .filter(|s| s.starts_with("sdns://"))
        .filter_map(|s| s.parse::<url::Url>().ok())
        .filter_map(|url| sdns_to_nsc(&url, true))
        .collect()
}

/// Reads the cache file, returning the parsed name servers and whether the
/// file is stale (mtime older than [`DNSCRYPT_CACHE_MAX_AGE`], or undatable).
/// Missing, unreadable, or empty/corrupt caches yield `None` so they get
/// re-downloaded instead of serving a 0-server config forever.
async fn read_dnscrypt_cache(cache_file: &Path) -> (Option<Vec<NameServerConfig>>, bool) {
    let Ok(metadata) = tokio::fs::metadata(cache_file).await else {
        return (None, false);
    };
    let Ok(contents) = tokio::fs::read_to_string(cache_file).await else {
        return (None, false);
    };
    let parsed = parse_dnscrypt_lines(&contents);
    if parsed.is_empty() {
        return (None, false);
    }
    // A future-dated mtime makes `elapsed()` fail; treat that as stale so an
    // undatable cache is eventually re-fetched instead of living forever.
    let stale = metadata.modified().is_ok_and(|mtime| {
        mtime
            .elapsed()
            .map_or(true, |age| age > DNSCRYPT_CACHE_MAX_AGE)
    });
    (Some(parsed), stale)
}

/// Idempotent install of the process-level rustls `CryptoProvider` (ring).
/// Required before any reqwest `Client::build` — reqwest 0.13 is built with
/// `rustls-no-provider` and panics otherwise.
fn ensure_tls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Upper bound on the `DNSCrypt` resolver list (the published list is under 1 MB).
const MAX_RESOLVER_LIST_BYTES: usize = 8 * 1024 * 1024;

/// Downloads the `DNSCrypt` public resolver list under a hard 10s deadline;
/// without the timeout a blocked network hangs every lookup forever.
async fn download_dnscrypt_resolvers(resolvers_url: &str) -> anyhow::Result<String> {
    let mut response = HTTP_CLIENT
        .get(resolvers_url)
        .send()
        .await?
        .error_for_status()?;
    if let Some(n) = response.content_length()
        && n > MAX_RESOLVER_LIST_BYTES as u64
    {
        anyhow::bail!(
            "resolver list declares {n} bytes, over the {MAX_RESOLVER_LIST_BYTES}-byte cap"
        );
    }
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > MAX_RESOLVER_LIST_BYTES {
            anyhow::bail!("resolver list exceeds the {MAX_RESOLVER_LIST_BYTES}-byte cap");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8(bytes)?)
}

/// Atomically writes the fetched list to the cache file (temp file + rename,
/// so a crash or concurrent reader never observes a partial cache). Only the
/// `sdns://` lines are kept, deduplicated, one per line.
async fn write_dnscrypt_cache(
    cache_dir: &Path,
    cache_file: &Path,
    text: &str,
) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(cache_dir).await?;
    let tmp_path = cache_file.with_file_name(format!(
        "{}.tmp{}",
        cache_file
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        std::process::id()
    ));
    let write = async {
        let mut file = tokio::fs::File::create(&tmp_path).await?;
        // Borrowed keys: `line` lives in `text`, so dedup costs no per-line
        // String allocation.
        let mut seen = HashSet::new();
        for line in text.lines().filter(|s| s.starts_with("sdns://")) {
            if seen.insert(line) {
                file.write_all(line.as_bytes()).await?;
                file.write_all(b"\n").await?;
            }
        }
        file.sync_all().await?;
        tokio::fs::rename(&tmp_path, cache_file).await
    };
    if let Err(e) = write.await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(e.into());
    }
    Ok(())
}

async fn get_dns_servers(cache_dir: &Path) -> anyhow::Result<ResolverConfig> {
    get_dns_servers_from(cache_dir, DNSCRYPT_RESOLVERS_URL).await
}

/// Core implementation of [`get_dns_servers`]; the resolver list URL is a
/// parameter so tests can exercise the download paths hermetically.
async fn get_dns_servers_from(
    cache_dir: &Path,
    resolvers_url: &str,
) -> anyhow::Result<ResolverConfig> {
    let cache_file = cache_dir.join(DNSCRYPT_RESOLVERS_CACHE);
    let (cached, cache_stale) = read_dnscrypt_cache(&cache_file).await;

    // Re-download when the cache is missing/empty or stale. A failed refresh
    // keeps the (stale) cache; an empty download is never written; a failed
    // cache write only costs the next run's refresh, never this lookup.
    let downloaded = if cached.is_none() || cache_stale {
        match download_dnscrypt_resolvers(resolvers_url).await {
            Ok(text) => {
                let parsed = parse_dnscrypt_lines(&text);
                if parsed.is_empty() {
                    None
                } else {
                    if let Err(e) = write_dnscrypt_cache(cache_dir, &cache_file, &text).await {
                        tracing::warn!(
                            error = %e,
                            "failed to write DNSCrypt resolver cache; using in-memory list"
                        );
                    }
                    Some(parsed)
                }
            }
            Err(_) => None,
        }
    } else {
        None
    };

    if let Some(name_servers) = downloaded.or(cached) {
        let mut config = ResolverConfig::default();
        for ns in name_servers {
            config.add_name_server(ns);
        }
        Ok(config)
    } else {
        // Last resort: the OS-provided resolver configuration (e.g.
        // /etc/resolv.conf) so lookups still work without the DNSCrypt list.
        Ok(system_conf::read_system_conf().map(|(cfg, _)| cfg)?)
    }
}

pub struct DnsResolver {
    cache_dir: PathBuf,
    resolver: tokio::sync::OnceCell<TokioResolver>,
}

impl DnsResolver {
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
            resolver: tokio::sync::OnceCell::new(),
        }
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
        let resolver = self.resolver.get_or_try_init(|| self.init()).await?;
        let ips: Vec<IpAddr> = resolver
            .lookup_ip(hostname)
            .await?
            .iter()
            .filter(|ip| allow_ipv6 || ip.is_ipv4())
            .collect();
        Ok(ips.into_boxed_slice())
    }

    async fn init(&self) -> anyhow::Result<TokioResolver> {
        let resolver_cfg = get_dns_servers(&self.cache_dir).await?;
        let resolver_opt = DEFAULT_RESOLVER_OPTS.clone();
        Ok(
            Resolver::builder_with_config(resolver_cfg, TokioRuntimeProvider::default())
                .with_options(resolver_opt)
                .build()?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dns.aa.net.uk `DoH` stamp published with an IPv4 address.
    const STAMP_IPV4: &str =
        "sdns://AgcAAAAAAAAADTIxNy4xNjkuMjAuMjIADWRucy5hYS5uZXQudWsKL2Rucy1xdWVyeQ";
    /// The same resolver published with an IPv6-only address.
    const STAMP_IPV6: &str =
        "sdns://AgcAAAAAAAAAEFsyMDAxOjhiMDo6MjAyMl0ADWRucy5hYS5uZXQudWsKL2Rucy1xdWVyeQ";
    /// Nothing listens here; downloads fail fast (ECONNREFUSED).
    const UNREACHABLE_URL: &str = "http://127.0.0.1:1/unreachable";

    /// Serves `body` as a single HTTP response on an ephemeral loopback port,
    /// returning the URL. Lets the download path run without the network.
    async fn serve(body: String) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        std::mem::drop(tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
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

    /// Asserts the result is either a non-empty config, or an error that is
    /// justified by the host having no OS-level resolver config to fall back
    /// to. Never tolerates a 0-server Ok config.
    fn assert_usable(result: anyhow::Result<ResolverConfig>) {
        match result {
            Ok(cfg) => assert!(
                !cfg.name_servers().is_empty(),
                "resolver config must not have 0 name servers"
            ),
            Err(_) => assert!(
                system_conf::read_system_conf().is_err(),
                "get_dns_servers must not fail when system resolvers are available"
            ),
        }
    }

    #[test]
    fn parse_dnscrypt_lines_includes_ipv6_stamps() {
        // dns.aa.net.uk published as an IPv4 DoH stamp and as an IPv6 DoH
        // stamp; with allow_ipv6=true both parse.
        let text = format!(
            "# DNSCrypt resolver list (markdown header)\n{STAMP_IPV4}\nnot a stamp\n{STAMP_IPV6}\n"
        );
        let parsed = parse_dnscrypt_lines(&text);
        assert_eq!(parsed.len(), 2, "both IPv4 and IPv6 stamps should parse");
        assert!(parsed[0].ip.is_ipv4());
        assert!(parsed[1].ip.is_ipv6());
    }

    /// The stamp address policy must match the config layer's host policy:
    /// unspecified is never allowed, local-use classes need an opt-in.
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
    /// address must both be refused, while the published public stamp is
    /// still accepted (finding f4).
    #[test]
    fn sdns_refuses_plain_and_local_stamps() {
        // Plain 127.0.0.1, props NO_LOGS|NO_FILTER.
        const PLAIN_LOOPBACK: &str = "sdns://AAYAAAAAAAAACTEyNy4wLjAuMQ";
        // DoT 127.0.0.1:<port>, TLS name v12-verify.example.
        const DOT_LOOPBACK: &str =
            "sdns://AwYAAAAAAAAADzEyNy4wLjAuMTozMzk5OQASdjEyLXZlcmlmeS5leGFtcGxl";
        for s in [PLAIN_LOOPBACK, DOT_LOOPBACK] {
            let url = url::Url::parse(s).expect("fixture parses");
            assert!(
                DnsStamp::decode(url.as_str()).is_ok(),
                "fixture must decode (rejection must be policy, not parse): {s}"
            );
            assert!(sdns_to_nsc(&url, false).is_none(), "must be refused: {s}");
        }
        // The published public DoH stamp is still accepted.
        let public = url::Url::parse(STAMP_IPV4).expect("fixture parses");
        assert!(sdns_to_nsc(&public, false).is_some());
    }

    #[tokio::test]
    async fn stale_cache_is_refreshed_or_falls_back_to_stale() -> anyhow::Result<()> {
        // A cache older than 7 days triggers a refresh attempt; with the list
        // unreachable the refresh fails and the stale entries must be kept.
        let dir = tempfile::tempdir()?;
        let cache = dir.path().join(DNSCRYPT_RESOLVERS_CACHE);
        tokio::fs::write(&cache, format!("{STAMP_IPV4}\n")).await?;
        let file = std::fs::File::options().write(true).open(&cache)?;
        file.set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::SystemTime::now() - Duration::from_hours(192)),
        )?;
        drop(file);

        let cfg = get_dns_servers_from(dir.path(), UNREACHABLE_URL)
            .await
            .expect("failed refresh must keep the stale cache");
        assert_eq!(
            cfg.name_servers().len(),
            1,
            "stale cache entry must be kept"
        );
        Ok(())
    }

    #[tokio::test]
    async fn empty_cache_is_not_used() -> anyhow::Result<()> {
        // An empty cache file (e.g. a rate-limit HTML page saved as 200) must
        // never yield a 0-server config: re-download, and if that fails, the
        // system resolver config.
        let dir = tempfile::tempdir()?;
        let cache = dir.path().join(DNSCRYPT_RESOLVERS_CACHE);
        tokio::fs::write(&cache, "").await?;
        let result = get_dns_servers_from(dir.path(), UNREACHABLE_URL).await;
        assert_usable(result);
        Ok(())
    }

    #[tokio::test]
    async fn empty_download_is_never_written() -> anyhow::Result<()> {
        // A 200 response without any stamps (e.g. a rate-limit HTML page)
        // must not be written to the cache and must not yield 0 servers.
        let url = serve("<html>rate limited</html>".to_string()).await;
        let dir = tempfile::tempdir()?;
        let cache = dir.path().join(DNSCRYPT_RESOLVERS_CACHE);
        tokio::fs::write(&cache, "").await?;
        let result = get_dns_servers_from(dir.path(), &url).await;
        assert_usable(result);
        let contents = tokio::fs::read_to_string(&cache).await?;
        assert!(
            contents.is_empty(),
            "empty download must not be written to cache"
        );
        Ok(())
    }

    /// An over-cap body must be refused outright, so the unbounded artifact
    /// fetch can never write a huge cache file (finding f1).
    #[tokio::test]
    async fn oversized_resolver_list_is_refused() -> anyhow::Result<()> {
        let url = serve("x".repeat(MAX_RESOLVER_LIST_BYTES + 1)).await;
        let err = download_dnscrypt_resolvers(&url)
            .await
            .expect_err("an over-cap body must be refused");
        assert!(
            err.to_string().contains("cap"),
            "error names the cap: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn download_succeeds_writes_cache() -> anyhow::Result<()> {
        // A successful first download populates the cache (happy path).
        let url = serve(format!("# DNSCrypt resolver list\n{STAMP_IPV4}\n")).await;
        let dir = tempfile::tempdir()?;
        let cache = dir.path().join(DNSCRYPT_RESOLVERS_CACHE);
        let cfg = get_dns_servers_from(dir.path(), &url).await?;
        assert_eq!(cfg.name_servers().len(), 1);
        let contents = tokio::fs::read_to_string(&cache).await?;
        assert_eq!(
            contents,
            format!("{STAMP_IPV4}\n"),
            "cache must hold the sdns:// lines"
        );
        Ok(())
    }

    #[tokio::test]
    async fn download_write_failure_keeps_in_memory_list() -> anyhow::Result<()> {
        // The cache path is a directory, so the atomic rename fails; the
        // freshly downloaded list must still be returned — a failed cache
        // write never fails DNS init.
        let url = serve(format!("# DNSCrypt resolver list\n{STAMP_IPV4}\n")).await;
        let dir = tempfile::tempdir()?;
        tokio::fs::create_dir(dir.path().join(DNSCRYPT_RESOLVERS_CACHE)).await?;
        let cfg = get_dns_servers_from(dir.path(), &url).await?;
        assert_eq!(cfg.name_servers().len(), 1);

        let mut entries = tokio::fs::read_dir(dir.path()).await?;
        let mut count = 0;
        while entries.next_entry().await?.is_some() {
            count += 1;
        }
        assert_eq!(
            count, 1,
            "failed cache write must not leave temp files behind"
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires network (fetches dnscrypt resolver list)"]
    async fn test_lookup_ip() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let resolver = DnsResolver::new(dir.path());
        let ips = resolver.lookup_ip("example.com", true).await?;
        assert!(!ips.is_empty());
        Ok(())
    }
}
