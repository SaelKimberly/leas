//! Spider-X: keep the established TLS session alive after a REALITY fallback.
//!
//! When the server fails REALITY auth (a real certificate — transparent
//! proxy / possible MITM), xray-core's `reality.go` `!Verified` behavior
//! keeps the session looking like a browsing session instead of closing
//! abruptly: this module is the engine's bounded implementation — HTTP/2
//! GETs to the real site so a DPI observer sees traffic, not a teardown.

use crate::Stream;
use crate::http2;
use crate::reality::SpiderConfig;
use crate::record::stream::TlsStream;

/// Padding cookie zeros (xray `SpiderY[0..1]`).
const PADDING_MAX: usize = 512;

/// Default browser ("nav") header set applied to every spider GET — the
/// `TryDefaultHeadersWith(…, "nav")` Chrome navigation set from xray-core
/// (`thirdparty/Xray-core/common/utils/browser.go`). A real browser opening
/// the steal target sends these; a bare `:authority/:method/:path/:scheme`
/// GET plus cookie is a DPI tell. Values are kept short (<128 bytes each;
/// the HPACK encoder handles longer values via the base-128 varint either
/// way).
const BROWSER_HEADERS: &[(&str, &str)] = &[
    (
        "user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    ),
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    ),
    ("accept-language", "en-US,en;q=0.9"),
    ("accept-encoding", "gzip, deflate, br"),
    ("sec-fetch-dest", "document"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-site", "none"),
    ("upgrade-insecure-requests", "1"),
];

/// Bounded Spider-X session: `max_gets` HTTP/2 GETs to `https://<sni><path>`
/// with default browser ("nav") headers, a padding cookie, Referer chaining,
/// and jittered `request_interval` delays.
/// All errors are swallowed — the caller already received its
/// `RealityFallback` error and this task owns the connection. An empty
/// `paths` list closes the session immediately (nothing to walk).
pub(crate) async fn run<S: Stream + 'static>(
    conn: TlsStream<S>,
    spider: SpiderConfig,
    sni: String,
) {
    if spider.paths.is_empty() {
        return;
    }
    let mut conn = conn;
    let mut client = http2::Client::new();
    let rng = ring::rand::SystemRandom::new();
    let mut prev_path: Option<String> = None;
    for idx in 0..spider.max_gets {
        let path = &spider.paths[idx % spider.paths.len()];
        // Padding cookie: `padding=0…0` (xray SpiderY, 0..=512 zeros).
        let pad =
            usize::try_from(crate::crypto::fingerprint::rand_u64(&rng) % (PADDING_MAX as u64 + 1))
                .unwrap_or(0);
        let pad_cookie = format!("padding={}", "0".repeat(pad));
        // Referer chain: each later request refers to the previous path.
        let referer = prev_path
            .as_ref()
            .map(|prev| format!("https://{sni}{prev}"));
        let mut extra_refs: Vec<(&str, &str)> = Vec::with_capacity(BROWSER_HEADERS.len() + 2);
        extra_refs.extend_from_slice(BROWSER_HEADERS);
        extra_refs.push(("cookie", pad_cookie.as_str()));
        if let Some(referer) = referer.as_deref() {
            extra_refs.push(("referer", referer));
        }
        let result = client.get(&mut conn, path, &sni, &extra_refs).await;
        prev_path = Some(path.clone());
        if result.is_err() {
            break;
        }
        // Jittered interval: draw ×(0.5..=1.5) in tenths per request so the
        // GET cadence is not a fixed sleep (mirrors xray's SpiderY interval
        // randomization; a constant interval is a DPI tell). Drawn from the
        // same `rand_u64` seam as the padding cookie.
        let tenths = 5 + (crate::crypto::fingerprint::rand_u64(&rng) % 11); // 5..=15
        let millis = u64::try_from(spider.request_interval.as_millis()).unwrap_or(0);
        let jittered = std::time::Duration::from_millis(millis * tenths / 10);
        tokio::time::sleep(jittered.max(std::time::Duration::from_millis(1))).await;
    }
}
