use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use maxminddb::Reader;
use tokio::io::AsyncWriteExt;

const GEOLITE_DOWNLOAD: &str =
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb";

/// Upper bound on the `GeoLite` artifact (the real database is about 70 MB).
const MAX_GEOLITE_BYTES: u64 = 256 * 1024 * 1024;

/// Fetches the `GeoLite` database, streaming the body to `dest` on disk — the
/// ~70 MB payload is never buffered in memory, let alone copied.
type FetchResult = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;
type Fetcher = dyn Fn(&Path) -> FetchResult + Send + Sync;

#[derive(Debug, Clone)]
pub struct Location {
    /// ISO-3166 alpha-2 country code, shared (`Arc<str>`) so the per-IP
    /// micro-cache and every consumer hand it around with refcount bumps.
    pub country: Arc<str>,
    /// English city name, when the database carries one.
    pub city_en: Option<Arc<str>>,
}

pub struct GeoIp {
    db_path: PathBuf,
    reader: tokio::sync::OnceCell<Arc<Reader<Vec<u8>>>>,
    init_lock: tokio::sync::Mutex<()>,
    fetch: Arc<Fetcher>,
    /// Per-IP decode cache (misses cached too), bounded at 1024 entries: a
    /// repeated IP costs a lock + `Arc` clones, never another mmdb walk or
    /// string decode; distinct-IP churn evicts cold entries.
    cache: Mutex<lru::LruCache<IpAddr, Option<Arc<Location>>>>,
    /// Cross-lookup latch for a persistently-unopenable artifact. Without it
    /// every cache-missing lookup deletes + re-downloads the database, since a
    /// failed heal latches nothing (finding f5).
    heal_latch: Mutex<HealLatch>,
}

/// Backoff state for the `GeoLite` heal path (see [`GeoIp::heal_latch`]).
#[derive(Debug, Default)]
struct HealLatch {
    /// The next instant a heal attempt is permitted; `None` = not latched.
    retry_after: Option<Instant>,
    /// Consecutive heal failures, driving the backoff (`1 << min(failures, 6)` s).
    failures: u32,
}

impl GeoIp {
    pub fn new(db_path: impl Into<PathBuf>) -> Self {
        Self::new_with_fetcher(db_path, |dest: &Path| {
            let dest = dest.to_path_buf();
            Box::pin(async move { fetch_geolite_to(&dest).await })
        })
    }

    /// Build a `GeoIp` backed by a custom fetcher, so tests can avoid the
    /// real 70 MB network download.
    pub fn new_with_fetcher<F>(db_path: impl Into<PathBuf>, fetcher: F) -> Self
    where
        F: Fn(&Path) -> FetchResult + Send + Sync + 'static,
    {
        Self {
            db_path: db_path.into(),
            reader: tokio::sync::OnceCell::new(),
            init_lock: tokio::sync::Mutex::new(()),
            fetch: Arc::new(fetcher),
            cache: Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(1024).expect("cache cap is nonzero"),
            )),
            heal_latch: Mutex::new(HealLatch::default()),
        }
    }

    pub async fn location_by_ip(&self, ip: IpAddr) -> anyhow::Result<Option<Location>> {
        // Cache-first: the common repeat lookup never touches the reader.
        // (Lock scoped to this block: the guard must drop before the awaits
        // below, and a guard in an `if let` scrutinee trips clippy.)
        let hit = {
            let mut cache = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cache.get(&ip).cloned()
        };
        if let Some(hit) = hit {
            return Ok(hit.map(|loc| Location {
                // Refcount bumps — no re-decode, no string copies.
                country: loc.country.clone(),
                city_en: loc.city_en.clone(),
            }));
        }
        if self.reader.get().is_none() {
            // Serialize first init so concurrent lookups can't race the
            // download and observe a partially-written database.
            let _guard = self.init_lock.lock().await;
            // Re-check under the lock: an earlier task may have initialized.
            if self.reader.get().is_none() {
                let reader = self.open_reader_healing().await?;
                let _ = self.reader.set(Arc::new(reader));
            }
        }
        let reader = Arc::clone(self.reader.get().expect("reader set above"));
        let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Location>> {
            let result = reader.lookup(ip)?;
            // Borrowed decodes: the strings live inside the mmap'd buffer,
            // so `decode_path::<&str>` copies nothing; `Arc::from` moves
            // them into shared strings the cache reuses.
            let Some(country) =
                result.decode_path::<&str>(&maxminddb::path!["country", "iso_code"])?
            else {
                return Ok(None);
            };
            let Some(city_en) =
                result.decode_path::<&str>(&maxminddb::path!["city", "names", "en"])?
            else {
                return Ok(Some(Location {
                    country: Arc::from(country),
                    city_en: None,
                }));
            };
            Ok(Some(Location {
                country: Arc::from(country),
                city_en: Some(Arc::from(city_en)),
            }))
        })
        .await??;
        let _ = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ip, result.as_ref().map(|loc| Arc::new(loc.clone())));
        Ok(result)
    }

    fn open_reader(path: &Path) -> anyhow::Result<Reader<Vec<u8>>> {
        Reader::open_readfile(path)
            .map_err(|e| anyhow::anyhow!("Invalid geolite file: {} ({e})", path.display()))
    }

    /// Open the database, healing a corrupt/truncated file by deleting it and
    /// re-downloading once before giving up. A failed heal is LATCHED with a
    /// growing backoff so a persistently-unopenable artifact is not deleted and
    /// re-downloaded on every cache-missing lookup (finding f5).
    async fn open_reader_healing(&self) -> anyhow::Result<Reader<Vec<u8>>> {
        if let Some(wait) = self.heal_backoff_remaining() {
            anyhow::bail!(
                "GeoLite artifact {} unavailable; retrying in {}s",
                self.db_path.display(),
                wait.as_secs().max(1)
            );
        }
        match self.try_open_healing().await {
            Ok(reader) => {
                self.clear_heal_latch();
                Ok(reader)
            }
            Err(e) => {
                self.record_heal_failure();
                Err(e)
            }
        }
    }

    /// Remaining backoff before the next heal attempt, if one is latched.
    fn heal_backoff_remaining(&self) -> Option<Duration> {
        let latch = self
            .heal_latch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        latch
            .retry_after
            .and_then(|at| at.checked_duration_since(Instant::now()))
    }

    /// Latch a failed heal, growing the backoff (`1..=64` s).
    fn record_heal_failure(&self) {
        let mut latch = self
            .heal_latch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        latch.failures = latch.failures.saturating_add(1);
        let secs = 1_u64 << latch.failures.min(6);
        latch.retry_after = Some(Instant::now() + Duration::from_secs(secs));
    }

    /// Clear the latch after a successful open.
    fn clear_heal_latch(&self) {
        let mut latch = self
            .heal_latch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        latch.failures = 0;
        latch.retry_after = None;
    }

    /// The heal itself: ensure the file, open it, and on an open failure
    /// delete + re-download once before giving up.
    async fn try_open_healing(&self) -> anyhow::Result<Reader<Vec<u8>>> {
        self.ensure_db().await?;
        // The 70 MB read is blocking — never on the async runtime.
        let path = self.db_path.clone();
        let opened = tokio::task::spawn_blocking(move || Self::open_reader(&path))
            .await
            .map_err(|e| anyhow::anyhow!("geoip open thread panicked: {e}"))?;
        match opened {
            Ok(reader) => Ok(reader),
            Err(first_err) => {
                tracing::warn!(
                    "GeoLite db {} is corrupt ({first_err}); removing and re-downloading",
                    self.db_path.display()
                );
                // Ignore a missing file: it may already have been removed.
                let _ = tokio::fs::remove_file(&self.db_path).await;
                self.ensure_db().await?;
                let path = self.db_path.clone();
                tokio::task::spawn_blocking(move || Self::open_reader(&path))
                    .await
                    .map_err(|e| anyhow::anyhow!("geoip open thread panicked: {e}"))?
            }
        }
    }

    async fn ensure_db(&self) -> anyhow::Result<()> {
        if self.db_path.is_file() {
            return Ok(());
        }
        tracing::info!(
            "Downloading {GEOLITE_DOWNLOAD} to {}",
            self.db_path.display()
        );
        if let Some(parent) = self.db_path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent).await?;
        }
        // Download to a temp path and rename into place, so a crash or a
        // concurrent reader can never observe a partially-written database.
        let tmp_path = self.db_path.with_file_name(format!(
            "{}.tmp{}",
            self.db_path
                .file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default(),
            std::process::id()
        ));
        let write = async {
            // Streamed straight to disk — no 70 MB `Vec` in memory.
            (self.fetch)(&tmp_path).await?;
            tokio::fs::rename(&tmp_path, &self.db_path).await?;
            Ok::<(), anyhow::Error>(())
        };
        if let Err(e) = write.await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e);
        }
        Ok(())
    }
}

/// Idempotent install of the process-level rustls `CryptoProvider` (ring).
/// Required before any reqwest `Client::build` — reqwest 0.13 is built with
/// `rustls-no-provider` and panics otherwise.
fn ensure_tls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Streams the `GeoLite` database to `dest`: each body chunk is written as it
/// arrives (bounded memory), then fsync'd before the caller's atomic rename.
async fn fetch_geolite_to(dest: &Path) -> anyhow::Result<()> {
    ensure_tls_provider();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;
    let response = client
        .get(GEOLITE_DOWNLOAD)
        .send()
        .await?
        .error_for_status()?;
    stream_capped(response, dest, MAX_GEOLITE_BYTES).await
}

/// Stream `response` into `dest`, refusing a body larger than `cap` — both a
/// declared `Content-Length` over the cap and the accumulated bytes actually
/// received (findings f1). On breach the caller's error path removes the temp
/// file, so an oversized artifact never becomes the live database.
async fn stream_capped(
    mut response: reqwest::Response,
    dest: &Path,
    cap: u64,
) -> anyhow::Result<()> {
    if let Some(n) = response.content_length()
        && n > cap
    {
        anyhow::bail!("artifact declares {n} bytes, over the {cap}-byte cap");
    }
    let mut file = tokio::fs::File::create(dest).await?;
    let mut written: u64 = 0;
    while let Some(chunk) = response.chunk().await? {
        written += chunk.len() as u64;
        if written > cap {
            anyhow::bail!("artifact exceeds the {cap}-byte cap");
        }
        file.write_all(&chunk).await?;
    }
    file.sync_all().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn bytes_fetcher(bytes: Vec<u8>) -> impl Fn(&Path) -> FetchResult + Send + Sync {
        move |dest: &Path| {
            let bytes = bytes.clone();
            let dest = dest.to_path_buf();
            Box::pin(async move {
                tokio::fs::write(&dest, &bytes).await?;
                Ok(())
            })
        }
    }

    /// A fetcher that counts invocations and tracks the maximum number of
    /// concurrent downloads, so tests can assert first init is serialized.
    fn counting_fetcher(
        bytes: Vec<u8>,
        calls: Arc<AtomicUsize>,
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
    ) -> impl Fn(&Path) -> FetchResult + Send + Sync {
        move |dest: &Path| {
            let bytes = bytes.clone();
            let dest = dest.to_path_buf();
            let calls = Arc::clone(&calls);
            let active = Arc::clone(&active);
            let max_active = Arc::clone(&max_active);
            Box::pin(async move {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_active.fetch_max(now, Ordering::SeqCst);
                // Keep the download in flight long enough for a racing second
                // lookup to reach the same spot, detecting non-serialized init.
                tokio::time::sleep(Duration::from_millis(300)).await;
                active.fetch_sub(1, Ordering::SeqCst);
                calls.fetch_add(1, Ordering::SeqCst);
                tokio::fs::write(&dest, &bytes).await?;
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn corrupt_db_is_healed_by_redownload() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("GeoLite2-City.mmdb");
        // A corrupt file that `Reader::open_readfile` cannot parse.
        tokio::fs::write(&db_path, b"this is not a maxmind database")
            .await
            .unwrap();

        // Count fetches: the corrupt file must be removed and exactly one
        // re-download attempt made before the error surfaces.
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher_calls = Arc::clone(&calls);
        let geo = GeoIp::new_with_fetcher(db_path.as_path(), move |_dest: &Path| {
            let calls = Arc::clone(&fetcher_calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(anyhow::anyhow!("simulated download failure"))
            })
        });

        let result = geo.location_by_ip("193.29.139.235".parse().unwrap()).await;
        assert!(result.is_err(), "corrupt db must surface an error");
        assert!(
            !db_path.exists(),
            "corrupt db must not remain as a permanent tombstone"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "corrupt db must trigger exactly one re-download attempt"
        );
    }

    /// A persistently-unopenable artifact must be latched: the first lookup
    /// attempts the heal, later lookups fail fast without another download
    /// (finding f5 — the per-lookup delete + re-download loop).
    #[tokio::test]
    async fn failed_heal_is_latched_across_lookups() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("GeoLite2-City.mmdb");
        tokio::fs::write(&db_path, b"not a maxmind database")
            .await
            .unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher_calls = Arc::clone(&calls);
        let geo = GeoIp::new_with_fetcher(db_path.as_path(), move |_dest: &Path| {
            let calls = Arc::clone(&fetcher_calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(anyhow::anyhow!("simulated download failure"))
            })
        });

        // Four lookups with distinct IPs (so every one takes the init path):
        // only the first may fetch.
        for ip in ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.1.1.1"] {
            assert!(geo.location_by_ip(ip.parse().unwrap()).await.is_err());
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the failed heal must be latched, not repeated per lookup"
        );
    }

    /// A body over the cap must be refused — both a declared `Content-Length`
    /// over the cap and the accumulated streamed bytes (finding f1). The
    /// fixture omits `Content-Length` so the streamed counter decides.
    #[tokio::test]
    async fn stream_capped_refuses_an_over_cap_body() {
        use tokio::io::AsyncReadExt as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut head = [0_u8; 4096];
                let _ = stream.read(&mut head).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = stream.write_all(&vec![b'a'; 2048]).await;
            }
        });

        ensure_tls_provider();
        let client = reqwest::Client::builder().build().unwrap();
        let response = client
            .get(format!("http://{addr}/geo.mmdb"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("geo.mmdb");
        let err = stream_capped(response, &dest, 1024)
            .await
            .expect_err("an over-cap body must be refused");
        assert!(
            err.to_string().contains("cap"),
            "error names the cap: {err}"
        );
    }

    #[tokio::test]
    async fn concurrent_first_init_downloads_serially() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let db_path = dir.path().join("GeoLite2-City.mmdb");
        let calls = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let geo = Arc::new(GeoIp::new_with_fetcher(
            db_path.as_path(),
            counting_fetcher(
                b"garbage".to_vec(),
                Arc::clone(&calls),
                Arc::clone(&active),
                Arc::clone(&max_active),
            ),
        ));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let geo = Arc::clone(&geo);
            handles.push(tokio::spawn(async move {
                let _ = geo.location_by_ip("193.29.139.235".parse().unwrap()).await;
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(
            max_active.load(Ordering::SeqCst),
            1,
            "first init must be serialized ({} concurrent downloads observed)",
            max_active.load(Ordering::SeqCst)
        );
        Ok(())
    }

    #[tokio::test]
    async fn ensure_db_skips_download_when_file_exists() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let db_path = dir.path().join("GeoLite2-City.mmdb");
        tokio::fs::write(&db_path, b"existing db").await?;

        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher_calls = Arc::clone(&calls);
        let geo = GeoIp::new_with_fetcher(db_path.as_path(), move |_dest: &Path| {
            let calls = Arc::clone(&fetcher_calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        geo.ensure_db().await?;
        assert_eq!(calls.load(Ordering::SeqCst), 0, "must not re-download");
        Ok(())
    }

    #[tokio::test]
    async fn ensure_db_writes_atomically_via_temp_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let db_path = dir.path().join("GeoLite2-City.mmdb");
        let geo = GeoIp::new_with_fetcher(
            db_path.as_path(),
            bytes_fetcher(b"fake mmdb bytes".to_vec()),
        );

        geo.ensure_db().await?;
        assert_eq!(tokio::fs::read(&db_path).await?, b"fake mmdb bytes");

        // No temp files should be left behind after the rename.
        let mut entries = tokio::fs::read_dir(dir.path()).await?;
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        assert_eq!(names, vec!["GeoLite2-City.mmdb".to_owned()]);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "downloads 70MB GeoLite2 database over network"]
    async fn test_location_by_ip() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let geo = GeoIp::new(dir.path().join("GeoLite2-City.mmdb"));
        let result = geo.location_by_ip("193.29.139.235".parse()?).await?;
        assert!(result.is_some());
        Ok(())
    }
}
