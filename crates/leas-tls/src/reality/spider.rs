//! Spider-X: keep the established TLS session alive after a REALITY fallback.
//!
//! When the server fails REALITY auth (a real certificate — transparent
//! proxy / possible MITM), xray-core's `reality.go` `!Verified` behavior
//! keeps the session looking like a browsing session instead of closing
//! abruptly: this module is the engine's bounded implementation — HTTP/2
//! GETs to the real site so a DPI observer sees traffic, not a teardown.

use crate::Stream;
use crate::http2;
use crate::http2_profile::Http2Profile;
use crate::reality::SpiderConfig;
use crate::record::stream::TlsStream;

/// Padding cookie zeros (xray `SpiderY[0..1]`).
const PADDING_MAX: usize = 512;

/// Browser ("nav") header set applied to every spider GET — the
/// `TryDefaultHeadersWith(…, "nav")` navigation set from xray-core
/// (`thirdparty/Xray-core/common/utils/browser.go`). A real browser opening
/// the steal target sends these; a bare `:authority/:method/:path/:scheme`
/// GET plus cookie is a DPI tell.
///
/// The `User-Agent`, `Accept` and `Accept-Language` values come from the
/// browser family of the REALITY fingerprint ([`Http2Profile`]), so the HTTP
/// layer cannot contradict the TLS hello. The Chromium-specific
/// `sec-fetch-*`/`upgrade-insecure-requests` navigation hints are sent for every
/// family: Firefox sends the same navigation set, and omitting them would be a
/// larger tell than a family-level mismatch in these opaque hints.
const fn browser_headers(profile: Http2Profile) -> [(&'static str, &'static str); 8] {
    [
        ("user-agent", profile.user_agent),
        ("accept", profile.accept),
        ("accept-language", profile.accept_language),
        ("accept-encoding", "gzip, deflate, br"),
        ("sec-fetch-dest", "document"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-site", "none"),
        ("upgrade-insecure-requests", "1"),
    ]
}

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
    let headers = browser_headers(Http2Profile::for_browser(spider.browser));
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
        let mut extra_refs: Vec<(&str, &str)> = Vec::with_capacity(headers.len() + 2);
        extra_refs.extend_from_slice(&headers);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprints::Browser;

    fn ua(browser: Browser) -> &'static str {
        browser_headers(Http2Profile::for_browser(browser))
            .iter()
            .find(|(k, _)| *k == "user-agent")
            .map(|(_, v)| *v)
            .expect("user-agent header")
    }

    #[test]
    fn spider_user_agent_follows_the_fingerprint_family() {
        // The bug this guards: a Firefox-shaped REALITY hello followed by a
        // Chrome navigation UA.
        assert!(ua(Browser::Firefox).contains("Firefox/"));
        assert!(!ua(Browser::Firefox).contains("Chrome/"));
        assert!(ua(Browser::Chrome).contains("Chrome/"));
        assert!(ua(Browser::Safari).contains("Safari/"));
        assert_ne!(ua(Browser::Firefox), ua(Browser::Chrome));
    }

    #[test]
    fn spider_keeps_the_navigation_header_set() {
        let headers = browser_headers(Http2Profile::for_browser(Browser::Firefox));
        for key in [
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "upgrade-insecure-requests",
        ] {
            assert!(
                headers.iter().any(|(k, _)| *k == key),
                "spider must send {key}"
            );
        }
    }
}
