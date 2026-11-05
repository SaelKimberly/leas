//! HTTP/2 + navigation-header profile for a resolved browser identity.
//!
//! The TLS hello and the HTTP layer must describe the *same* browser. A
//! Firefox-shaped `ClientHello` followed by a Chrome `User-Agent` and Chromium
//! window sizes is exactly the cross-layer discontinuity an Akamai-style h2
//! fingerprint or a header-ordering check catches.
//!
//! Values are seeded from `leas-native`'s sweep tables (themselves transcribed
//! from `thirdparty/impit`); they live here so the engine, the grader and the
//! REALITY spider share one source instead of three drifting copies.

use crate::fingerprints::{Browser, Device, Os};

/// One browser family's HTTP/2 + header defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2Profile {
    /// `SETTINGS_INITIAL_WINDOW_SIZE`.
    pub initial_window_size: u32,
    /// Connection-level flow-control window.
    pub connection_window_size: u32,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`.
    pub max_header_list_size: u32,
    /// `User-Agent` for navigations.
    pub user_agent: &'static str,
    /// `Accept` for navigations.
    pub accept: &'static str,
    /// `Accept-Language` for navigations.
    pub accept_language: &'static str,
}

/// Chromium navigation headers (Chrome/Edge/Brave/Opera/Samsung share them).
const CHROMIUM_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const CHROMIUM_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
const CHROMIUM_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";

const FIREFOX_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0";
const FIREFOX_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8";
const FIREFOX_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.5";

const SAFARI_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";
const SAFARI_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const SAFARI_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";

impl Http2Profile {
    /// The profile for one browser family.
    ///
    /// Window sizes follow `impit`'s captures: Chromium
    /// `6_291_456 / 15_663_105`, Firefox `131_072 / 12_517_377`, Safari
    /// `2_097_152 / 10_485_760`. `max_header_list_size` is pinned uniformly to
    /// hyper's default cap because impit leaves it unset for Firefox/Safari.
    #[must_use]
    pub const fn for_browser(browser: Browser) -> Self {
        match browser {
            Browser::Firefox => Self {
                initial_window_size: 131_072,
                connection_window_size: 12_517_377,
                max_header_list_size: 262_144,
                user_agent: FIREFOX_UA,
                accept: FIREFOX_ACCEPT,
                accept_language: FIREFOX_ACCEPT_LANGUAGE,
            },
            Browser::Safari => Self {
                initial_window_size: 2_097_152,
                connection_window_size: 10_485_760,
                max_header_list_size: 262_144,
                user_agent: SAFARI_UA,
                accept: SAFARI_ACCEPT,
                accept_language: SAFARI_ACCEPT_LANGUAGE,
            },
            Browser::Chrome
            | Browser::Edge
            | Browser::Brave
            | Browser::Opera
            | Browser::SamsungInternet => Self {
                initial_window_size: 6_291_456,
                connection_window_size: 15_663_105,
                max_header_list_size: 262_144,
                user_agent: CHROMIUM_UA,
                accept: CHROMIUM_ACCEPT,
                accept_language: CHROMIUM_ACCEPT_LANGUAGE,
            },
        }
    }

    /// The profile for a concrete roster identity. Today only the browser
    /// family changes the values; the OS/device inputs are accepted so callers
    /// pass the resolved identity rather than re-deriving the family.
    ///
    /// Note: iOS rows are Safari-shaped on the wire whatever the brand says
    /// (`WKWebView` reality), which is why `os` is consulted first.
    #[must_use]
    pub const fn for_identity(browser: Browser, os: Os, device: Device) -> Self {
        let _ = device;
        if matches!(os, Os::Ios) {
            return Self::for_browser(Browser::Safari);
        }
        Self::for_browser(browser)
    }

    /// `(initial_stream_window, initial_connection_window, max_header_list)`
    /// — the tuple shape the HTTP/2 SETTINGS writer wants.
    #[must_use]
    pub const fn settings(self) -> (u32, u32, u32) {
        (
            self.initial_window_size,
            self.connection_window_size,
            self.max_header_list_size,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_do_not_share_settings_or_ua() {
        let chrome = Http2Profile::for_browser(Browser::Chrome);
        let firefox = Http2Profile::for_browser(Browser::Firefox);
        let safari = Http2Profile::for_browser(Browser::Safari);
        assert_ne!(chrome.settings(), firefox.settings());
        assert_ne!(firefox.settings(), safari.settings());
        assert!(!chrome.user_agent.contains("Firefox"));
        assert!(firefox.user_agent.contains("Firefox"));
        assert!(!firefox.user_agent.contains("Chrome/"));
    }

    #[test]
    fn chromium_brands_share_one_profile() {
        let chrome = Http2Profile::for_browser(Browser::Chrome);
        for brand in [
            Browser::Edge,
            Browser::Brave,
            Browser::Opera,
            Browser::SamsungInternet,
        ] {
            assert_eq!(Http2Profile::for_browser(brand), chrome);
        }
    }

    #[test]
    fn ios_identity_is_safari_shaped() {
        let profile = Http2Profile::for_identity(Browser::Chrome, Os::Ios, Device::Phone);
        assert_eq!(profile, Http2Profile::for_browser(Browser::Safari));
    }
}
