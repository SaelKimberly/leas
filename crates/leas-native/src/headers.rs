//! Per-family HTTP request header emulation + h2 settings for the
//! amiabot verification sweep.
//!
//! Header vectors and h2 window sizes are transcribed from `thirdparty/impit`
//! (`fingerprint/database/{chrome,firefox,safari}.rs` + `http_headers`) —
//! data only, Apache-2.0. impit's TLS is patched-rustls and unused here; only
//! its observed header values and HTTP/2 SETTINGS are copied. Families impit
//! does not model (edge/opera/brave/samsung) reuse the Chromium defaults;
//! majors impit does not capture fall back to the synthesized per-major
//! templates.

use leas_tls::fingerprints::{Browser, Device, Os};

/// The HTTP request headers the amiabot sweep sends for one profile.
///
/// `user_agent` and `sec_ch_ua` are synthesized per identity; the rest are
/// family-level defaults transcribed from impit.
#[derive(Debug, Clone)]
pub struct HeadersFor {
    pub user_agent: String,
    pub accept: &'static str,
    pub accept_language: &'static str,
    /// `sec-ch-ua` brand string; `None` when the family does not send it
    /// (Firefox, Safari).
    pub sec_ch_ua: Option<String>,
    pub sec_fetch_site: &'static str,
    pub sec_fetch_mode: &'static str,
    pub sec_fetch_user: &'static str,
    pub sec_fetch_dest: &'static str,
}

/// Build the header set for one roster identity.
///
/// # Panics
/// Never; `Os::name`/`Device::name` cover every variant.
#[must_use]
pub fn for_identity(browser: Browser, os: Os, device: Device, major: u16) -> HeadersFor {
    let (accept, accept_language) = match browser {
        Browser::Firefox => (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
            "en-US,en;q=0.5",
        ),
        // Chromium family + Safari share the application/xhtml+svg-less
        // accept set; impit's safari/edge/opera/brave/samsung coverage is
        // absent, so the family defaults here are the Chromium capture.
        _ => (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "en-US,en;q=0.9",
        ),
    };
    HeadersFor {
        user_agent: user_agent(browser, os, device, major),
        accept,
        accept_language,
        sec_ch_ua: sec_ch_ua(browser, major),
        sec_fetch_site: "none",
        sec_fetch_mode: "navigate",
        sec_fetch_user: "?1",
        sec_fetch_dest: "document",
    }
}

/// Synthesize a browser `User-Agent` from identity. Chromium-family and
/// Firefox templates follow the impit captures; the OS/device token is
/// mapped from the identity's platform.
#[must_use]
pub fn user_agent(browser: Browser, os: Os, device: Device, major: u16) -> String {
    match browser {
        Browser::Firefox => {
            let plat = os_token_firefox(os);
            format!("Mozilla/5.0 ({plat}; rv:{major}.0) Gecko/20100101 Firefox/{major}.0")
        }
        Browser::Safari => {
            // iOS is the only modeled Safari OS; desktop fallback is a
            // macOS Safari shape.
            let token = match os {
                Os::Ios => "iPhone; CPU iPhone OS 17_0 like Mac OS X",
                _ => "Macintosh; Intel Mac OS X 10_15_7",
            };
            format!(
                "Mozilla/5.0 ({token}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{major}.0 Mobile/15E148 Safari/604.1"
            )
        }
        // Chromium family: chrome/edge/brave/opera/samsung_internet.
        _ => {
            let token = os_token_chromium(os, device);
            let brand = ua_brand(browser);
            format!(
                "Mozilla/5.0 ({token}) AppleWebKit/537.36 (KHTML, like Gecko) {brand}/{major}.0.0.0 Safari/537.36"
            )
        }
    }
}

/// The `sec-ch-ua` brand header for `browser` at `major`.
///
/// Chrome majors impit captured (100..151) use the exact observed strings;
/// all other Chromium-family identities use the synthesized
/// `Chromium`/`Not_A Brand`/family-brand triple. Firefox and Safari do not
/// send `sec-ch-ua` → `None`.
#[must_use]
pub fn sec_ch_ua(browser: Browser, major: u16) -> Option<String> {
    match browser {
        Browser::Chrome => Some(chrome_sec_ch_ua(major)),
        Browser::Edge | Browser::Brave | Browser::Opera | Browser::SamsungInternet => {
            Some(format!(
                "\"Chromium\";v=\"{major}\", \"Not_A Brand\";v=\"24\", \"{}\";v=\"{major}\"",
                sec_ch_ua_brand(browser)
            ))
        }
        Browser::Firefox | Browser::Safari => None,
    }
}

/// Exact impit-captured `sec-ch-ua` for Chrome majors 100..151; majors
/// outside the table use the synthesized `Chromium`/`Not_A Brand`/`Chrome`
/// triple.
fn chrome_sec_ch_ua(major: u16) -> String {
    let exact: Option<&'static str> = match major {
        100 => {
            Some("\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"100\", \"Google Chrome\";v=\"100\"")
        }
        101 => {
            Some("\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"101\", \"Google Chrome\";v=\"101\"")
        }
        104 => {
            Some("\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"104\", \"Google Chrome\";v=\"104\"")
        }
        107 => {
            Some("\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"107\", \"Google Chrome\";v=\"107\"")
        }
        110 => {
            Some("\"Chromium\";v=\"110\", \"Not A(Brand\";v=\"24\", \"Google Chrome\";v=\"110\"")
        }
        116 => {
            Some("\"Chromium\";v=\"116\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"116\"")
        }
        124 => {
            Some("\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"")
        }
        125 => {
            Some("\"Google Chrome\";v=\"125\", \"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"24\"")
        }
        131 => {
            Some("\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"")
        }
        133 => {
            Some("\"Not(A:Brand\";v=\"99\", \"Google Chrome\";v=\"133\", \"Chromium\";v=\"133\"")
        }
        136 => {
            Some("\"Chromium\";v=\"136\", \"Google Chrome\";v=\"136\", \"Not.A/Brand\";v=\"99\"")
        }
        142 => {
            Some("\"Chromium\";v=\"142\", \"Google Chrome\";v=\"142\", \"Not_A Brand\";v=\"99\"")
        }
        151 => {
            Some("\"Not=A?Brand\";v=\"99\", \"Google Chrome\";v=\"151\", \"Chromium\";v=\"151\"")
        }
        _ => None,
    };
    exact.map_or_else(
        || {
            format!(
                "\"Chromium\";v=\"{major}\", \"Not_A Brand\";v=\"24\", \"Chrome\";v=\"{major}\""
            )
        },
        String::from,
    )
}

/// HTTP/2 SETTINGS for a browser family: `(initial_stream_window_size,
/// initial_connection_window_size, max_header_list_size)`.
///
/// Transcribed from impit: chrome (and every Chromium-family build) uses
/// `6_291_456 / 15_663_105 / 262_144`; firefox `131_072 / 12_517_377`;
/// safari (iOS) `2_097_152 / 10_485_760`. impit leaves `max_header_list`
/// unset for firefox/safari; the sweep pins `262_144` (hyper's h2 default
/// cap) uniformly.
#[must_use]
pub const fn h2_settings(browser: Browser) -> (u32, u32, u32) {
    match browser {
        Browser::Firefox => (131_072, 12_517_377, 262_144),
        Browser::Safari => (2_097_152, 10_485_760, 262_144),
        Browser::Chrome
        | Browser::Edge
        | Browser::Brave
        | Browser::Opera
        | Browser::SamsungInternet => (6_291_456, 15_663_105, 262_144),
    }
}

/// Chromium-family `User-Agent` product token (the version slot).
const fn ua_brand(browser: Browser) -> &'static str {
    match browser {
        // Firefox/Safari never reach this function (`user_agent` handles
        // them first); "Chrome" is the unreachable fallback token.
        Browser::Chrome | Browser::Firefox | Browser::Safari => "Chrome",
        Browser::Edge => "Edg",
        Browser::Brave => "Brave",
        Browser::Opera => "OPR",
        Browser::SamsungInternet => "SamsungBrowser",
    }
}

/// `sec-ch-ua` family-brand token (the real-brand slot).
const fn sec_ch_ua_brand(browser: Browser) -> &'static str {
    match browser {
        // Firefox/Safari never reach this function (`sec_ch_ua` returns
        // `None` for them); "Chrome" is the unreachable fallback token.
        Browser::Chrome | Browser::Firefox | Browser::Safari => "Chrome",
        Browser::Edge => "Microsoft Edge",
        Browser::Brave => "Brave",
        Browser::Opera => "Opera",
        Browser::SamsungInternet => "Samsung Internet",
    }
}

const fn os_token_chromium(os: Os, device: Device) -> &'static str {
    match (os, device) {
        (Os::Windows, _) => "Windows NT 10.0; Win64; x64",
        (Os::MacOs, _) => "Macintosh; Intel Mac OS X 10_15_7",
        (Os::Linux, _) => "X11; Linux x86_64",
        (Os::Android, Device::Phone) => "Linux; Android 13; Pixel 7",
        (Os::Android, _) => "Linux; Android 13",
        (Os::Ios, _) => "iPhone; CPU iPhone OS 17_0 like Mac OS X",
    }
}

const fn os_token_firefox(os: Os) -> &'static str {
    match os {
        Os::Windows => "Windows NT 10.0; Win64; x64",
        Os::MacOs => "Macintosh; Intel Mac OS X 10.15",
        Os::Linux => "X11; Linux x86_64",
        Os::Android => "Android",
        Os::Ios => "iPhone",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_140_windows_desktop_ua() {
        assert_eq!(
            user_agent(Browser::Chrome, Os::Windows, Device::Desktop, 140),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
        );
    }

    #[test]
    fn firefox_144_macos_ua() {
        assert_eq!(
            user_agent(Browser::Firefox, Os::MacOs, Device::Desktop, 144),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0"
        );
    }

    #[test]
    fn edge_and_brave_ua_tokens() {
        assert_eq!(
            user_agent(Browser::Edge, Os::Windows, Device::Desktop, 106),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/106.0.0.0 Safari/537.36"
        );
        assert_eq!(
            user_agent(Browser::Brave, Os::Windows, Device::Desktop, 126),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave/126.0.0.0 Safari/537.36"
        );
    }

    #[test]
    fn sec_ch_ua_major_interpolation() {
        // impit-captured majors are exact.
        assert_eq!(
            sec_ch_ua(Browser::Chrome, 131).as_deref(),
            Some("\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"")
        );
        // Uncaptured majors fall back to the synthesized triple.
        assert_eq!(
            sec_ch_ua(Browser::Chrome, 140).as_deref(),
            Some("\"Chromium\";v=\"140\", \"Not_A Brand\";v=\"24\", \"Chrome\";v=\"140\"")
        );
        // Chromium-family brands use their own product token.
        assert_eq!(
            sec_ch_ua(Browser::Edge, 106).as_deref(),
            Some("\"Chromium\";v=\"106\", \"Not_A Brand\";v=\"24\", \"Microsoft Edge\";v=\"106\"")
        );
        // Firefox/Safari send no sec-ch-ua.
        assert_eq!(sec_ch_ua(Browser::Firefox, 144), None);
        assert_eq!(sec_ch_ua(Browser::Safari, 18), None);
    }

    #[test]
    fn h2_settings_per_family() {
        assert_eq!(
            h2_settings(Browser::Chrome),
            (6_291_456, 15_663_105, 262_144)
        );
        assert_eq!(h2_settings(Browser::Edge), (6_291_456, 15_663_105, 262_144));
        assert_eq!(
            h2_settings(Browser::Brave),
            (6_291_456, 15_663_105, 262_144)
        );
        assert_eq!(
            h2_settings(Browser::Firefox),
            (131_072, 12_517_377, 262_144)
        );
        assert_eq!(
            h2_settings(Browser::Safari),
            (2_097_152, 10_485_760, 262_144)
        );
    }

    #[test]
    fn identity_builds_full_header_set() {
        let h = for_identity(Browser::Chrome, Os::Windows, Device::Desktop, 130);
        assert_eq!(h.sec_fetch_dest, "document");
        assert_eq!(h.sec_fetch_mode, "navigate");
        assert!(h.user_agent.contains("Chrome/130.0.0.0"));
        assert!(h.sec_ch_ua.as_deref().unwrap().contains("130"));
    }
}
