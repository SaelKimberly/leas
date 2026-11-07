//! HTTP helpers shared by the client's subscription fetches and the oracle
//! updater.

/// Refuse redirect targets that point at local/private hosts.
///
/// A subscription or update URL is untrusted input: following its redirect to
/// `127.0.0.1`, a LAN address or the cloud metadata endpoint turns an SSRF
/// into a credential leak. Scheme downgrades are refused separately.
#[must_use]
#[allow(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "domain suffix, not a file extension; the host is already lowercased"
)]
pub fn redirect_target_is_local(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local") {
        return true;
    }
    // `Url::host_str` keeps the brackets around an IPv6 literal.
    let bare = lower
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&lower);
    let Ok(ip) = bare.parse::<std::net::IpAddr>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local(),
    }
}

/// Redirect policy: at most 5 hops, no HTTPS→HTTP downgrade, no local target.
#[must_use]
pub fn safe_redirect_policy(require_https: bool) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("too many redirects");
        }
        let target = attempt.url();
        let downgrade = attempt
            .previous()
            .last()
            .is_some_and(|prev| prev.scheme() == "https" && target.scheme() != "https");
        if downgrade
            || (require_https && target.scheme() != "https")
            || redirect_target_is_local(target)
        {
            return attempt.stop();
        }
        attempt.follow()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_target_is_local_matches_local_use_hosts() {
        for local in [
            "http://127.0.0.1/x",
            "http://10.0.0.1/x",
            "http://192.168.1.1/x",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/x",
            "http://localhost/x",
            "http://foo.localhost/x",
            "http://printer.local/x",
        ] {
            assert!(
                redirect_target_is_local(&reqwest::Url::parse(local).unwrap()),
                "{local} must be refused as a redirect target"
            );
        }
        for public in ["https://example.com/x", "https://1.1.1.1/x"] {
            assert!(!redirect_target_is_local(
                &reqwest::Url::parse(public).unwrap()
            ));
        }
    }
}
