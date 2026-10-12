//! Typed share-URL parse/format boundary.
//!
//! [`parse_share_url`] returns a [`ParsedProfile`] — a proto-crate
//! [`ParsedProto`] (endpoints + protocol essentials) plus a per-profile
//! validation result. All URL parsing lives in `leas-proto`
//! ([`ProtocolConfig::try_parse_proto`]: scheme dispatch + fallback chain);
//! this module owns the URL-shape gate, validation settings, host checks,
//! and the format entry point ([`format_share_url`] →
//! [`ProtocolConfig::reconstruct_proto`]).
//!
//! The legacy `Profile` struct, per-protocol `XxxFmt` parsers/formatters,
//! and settings-JSON round-trips were removed in T11 (see the task report
//! for the deleted public API surface).

use std::net::IpAddr;

use leas_proto::proto_spec::{
    EndpointEssentials, ParseError, ParsedProto, ProtoSpec, ProtocolConfig, SecurityConfig,
};
use leas_proto::urlx::RawUrlX;

/// Result of parsing a share URL: the typed parse-boundary payload.
#[derive(Debug, Clone)]
pub struct ParsedProfile {
    pub parsed: ParsedProto,
    /// Per-profile validation result (required fields etc.) — Ok(()) or Err(msg).
    pub validation: Result<(), String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("unsupported URL scheme")]
    UnsupportedScheme,
    #[error("parse error: {0}")]
    Parse(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("missing required field: {0}")]
    MissingField(String),
    #[error("validation failed: {0}")]
    Validation(String),
}

impl From<ParseError> for ImportError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::UnsupportedScheme(_) => Self::UnsupportedScheme,
            other => Self::Parse(other.to_string()),
        }
    }
}

pub type Result<T, E = ImportError> = std::result::Result<T, E>;

/// Extract user identification from a typed [`ProtocolConfig`] for form population.
///
/// Reads the primary credential field of each protocol variant (uuid /
/// password / auth / username). Stub (placeholder) protocols fall back to
/// their legacy `settings_json` blob, preserving the pre-T11 behavior for
/// redirect/tproxy/mixed.
#[must_use]
pub fn profile_user_id(config: &ProtocolConfig) -> Option<String> {
    fn non_empty(s: &str) -> Option<String> {
        (!s.is_empty()).then(|| s.to_string())
    }

    match config {
        ProtocolConfig::Vless(c) => non_empty(&c.uuid),
        ProtocolConfig::Vmess(c) => non_empty(&c.uuid),
        ProtocolConfig::Trojan(c) => non_empty(&c.password),
        ProtocolConfig::Ss(c) => non_empty(&c.password),
        ProtocolConfig::Ssr(c) => non_empty(&c.password),
        ProtocolConfig::Tuic(c) => non_empty(&c.uuid).or_else(|| non_empty(&c.password)),
        ProtocolConfig::Hysteria2(c) => non_empty(&c.auth),
        ProtocolConfig::Hysteria1(c) => c.auth.as_deref().and_then(non_empty),
        ProtocolConfig::Naive(c) => non_empty(&c.username).or_else(|| non_empty(&c.password)),
        ProtocolConfig::AnyTls(c) => c.password.as_deref().and_then(non_empty),
        ProtocolConfig::ShadowTls(c) => c.password.as_deref().and_then(non_empty),
        ProtocolConfig::Socks(c) => c
            .username
            .as_deref()
            .and_then(non_empty)
            .or_else(|| c.password.as_deref().and_then(non_empty)),
        ProtocolConfig::Http(c) => c
            .username
            .as_deref()
            .and_then(non_empty)
            .or_else(|| c.password.as_deref().and_then(non_empty)),
        ProtocolConfig::Wireguard(c) => {
            non_empty(&c.private_key).or_else(|| non_empty(&c.public_key))
        }
        ProtocolConfig::Ssh(c) => c
            .user
            .as_deref()
            .and_then(non_empty)
            .or_else(|| c.password.as_deref().and_then(non_empty))
            .or_else(|| c.private_key.as_deref().and_then(non_empty)),
        ProtocolConfig::Tor(_) | ProtocolConfig::Tailscale(_) => None,
        // Placeholder protocols: legacy settings_json blob.
        ProtocolConfig::Redirect(c) | ProtocolConfig::TProxy(c) | ProtocolConfig::Mixed(c) => {
            let extra: serde_json::Value = serde_json::from_slice(&c.settings_json).ok()?;
            let obj = extra.as_object()?;
            let pick =
                |v: &serde_json::Value| v.as_str().filter(|s| !s.is_empty()).map(str::to_string);
            for key in [
                "id",
                "password",
                "uuid",
                "user_id",
                "client_id",
                "method",
                "secret",
                "key",
            ] {
                if let Some(v) = obj.get(key).and_then(pick) {
                    return Some(v);
                }
            }
            if let Some(p) = obj.get("protocol_settings").and_then(|v| v.as_object()) {
                for key in ["user_id", "username", "user", "password"] {
                    if let Some(v) = p.get(key).and_then(pick) {
                        return Some(v);
                    }
                }
            }
            None
        }
    }
}

/// Parse a share URL into a typed [`ParsedProfile`].
///
/// Splits the URL first (shape gate — garbage without a `://` gets a clean
/// error, never a `RawUrlX` panic), then runs
/// [`ProtocolConfig::try_parse_proto`] (scheme dispatch + fallback chain,
/// entirely in the proto crate). Required-field validation is carried on
/// [`ParsedProfile::validation`] (the parse may succeed while validation
/// fails); host validation (unspecified/private/loopback) is a hard error.
///
/// # Errors
///
/// [`ImportError::Parse`] when the URL is not a valid proxy URL for any
/// supported protocol, [`ImportError::Validation`] when the parsed host is
/// unspecified/private/loopback/link-local (subject to `settings`).
pub fn parse_share_url(url: &str, settings: &ValidationSettings) -> Result<ParsedProfile> {
    // Shape gate before RawUrlX (which requires a `://`): garbage URLs get a
    // clean ImportError instead of a panic.
    let _ = split_share_url(url)?;

    let raw = RawUrlX::from(url);
    let parsed = ProtocolConfig::try_parse_proto(&raw).map_err(ImportError::from)?;

    let validation = validate_required_fields(&parsed);

    // `reject_insecure`: the documented import policy. Without this branch
    // the setting is dead state and a feed's `allowInsecure=1` /
    // `insecure=1` always lands in the store with TLS certificate
    // verification disabled.
    if settings.reject_insecure
        && parsed
            .protocol
            .config
            .security()
            .and_then(SecurityConfig::insecure)
            == Some(true)
    {
        return Err(ImportError::Validation(
            "profile disables certificate verification (allowInsecure/insecure)".into(),
        ));
    }

    validate_host(&parsed, settings)?;

    Ok(ParsedProfile { parsed, validation })
}

/// Format a [`ParsedProto`] back into a share URL string for the given endpoint.
///
/// The endpoint supplies host/port (the config payload is endpoint-free by
/// the T4/T5 host-free parse mandate).
///
/// # Errors
///
/// If this protocol has no URL format (placeholder protocols) or the
/// config/endpoint cannot be rendered.
pub fn format_share_url(parsed: &ParsedProto, endpoint: &EndpointEssentials) -> Result<String> {
    parsed
        .protocol
        .config
        .reconstruct_proto(endpoint)
        .map_err(ImportError::from)
}

// ── URL splitter ───────────────────────────────────────────────────────

/// Parsed URL components that avoid the edge-case failures of `url::Url::parse`
/// (Trojan `#` in password, `@` in query values, etc.).
struct UrlComponents<'a> {
    _scheme: String,
    _username: std::borrow::Cow<'a, str>,
    _password: Option<std::borrow::Cow<'a, str>>,
    _host: String,
    _port: Option<u16>,
    _path: Option<std::borrow::Cow<'a, str>>,
    _query_pairs: Vec<(&'a str, std::borrow::Cow<'a, str>)>,
    _fragment: Option<std::borrow::Cow<'a, str>>,
}
/// Robust URL splitting that handles Trojan `#`-in-password and `@`-in-query edge cases.
/// Returns components without using `url::Url`.
fn split_share_url(url: &str) -> Result<UrlComponents<'_>> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| ImportError::Parse("missing scheme in URL".into()))?;
    let scheme = scheme.to_string();
    let mut unparsed = rest;

    // 2. Extract userinfo (find the correct @ before any # or ?)
    let (username, password, rest) = find_userinfo(unparsed, &scheme);
    unparsed = rest;

    // 3. Extract fragment
    let fragment = unparsed.split_once('#').map(|(r, f)| {
        unparsed = r;
        percent_decode(f)
    });

    // 4. Extract query
    let query_pairs = if let Some((r, q)) = unparsed.split_once('?') {
        unparsed = r;
        parse_query_params(q)
    } else {
        Vec::new()
    };

    // 5. Extract path
    let path = unparsed.find('/').map(|pos| {
        let (r, p) = unparsed.split_at(pos);
        unparsed = r;
        percent_decode(p)
    });

    // 6. Remaining: host:port
    // Handle the case where userinfo was not present (unparsed is still the full body)
    let hostport = if unparsed.contains('@') {
        // Multiple @ signs — take the part after the last @
        unparsed.split_once('@').map_or(unparsed, |(_, r)| r)
    } else {
        unparsed
    };

    let (host, port) = parse_hostport(hostport);
    let host = fix_percent_encoding(&host).into_owned();

    Ok(UrlComponents {
        _scheme: scheme,
        _username: username,
        _password: password,
        _host: host,
        _port: port,
        _path: path,
        _query_pairs: query_pairs,
        _fragment: fragment,
    })
}

/// Find userinfo separator (`@`) with Trojan password `#` handling.
/// Returns `(username, password, rest_of_url)`.
/// When no `@` found at the correct position, username and password are empty and rest is the full body.
fn find_userinfo<'a>(
    s: &'a str,
    scheme: &str,
) -> (
    std::borrow::Cow<'a, str>,
    Option<std::borrow::Cow<'a, str>>,
    &'a str,
) {
    let at_pos = s.find('@').and_then(|pos| {
        let earliest = s.find('#').or_else(|| s.find('?'));
        match earliest {
            None => Some(pos),
            Some(early) if pos < early => Some(pos),
            Some(_early) => {
                // Trojan special case: 16-char ASCII password with # in it
                // e.g., "8r<[9'l6hAO#8ZQi@host:port"
                if scheme.starts_with("trojan") && pos == 16 && s[..pos].is_ascii() {
                    // Validate that what follows @ is a host:port
                    let after_at = &s[pos + 1..];
                    let host_end = after_at
                        .find('/')
                        .or_else(|| after_at.find('?'))
                        .or_else(|| after_at.find('#'))
                        .unwrap_or(after_at.len());
                    if host_end > 0 {
                        let candidate = &after_at[..host_end];
                        if candidate.contains(':') {
                            return Some(pos);
                        }
                    }
                }
                None // @ is after ? or # so it's part of query/fragment
            }
        }
    });

    at_pos.map_or_else(
        || (std::borrow::Cow::Borrowed(""), None, s),
        |pos| {
            let userinfo = &s[..pos];
            let rest = &s[pos + 1..];
            match userinfo.split_once(':') {
                Some((u, p)) => (percent_decode(u), Some(percent_decode(p)), rest),
                None => (percent_decode(userinfo), None, rest),
            }
        },
    )
}

/// Parse `host:port` string with recovery for:
/// - Port-suffix garbage: `host:443:extra` → `(host, Some(443))`
/// - Trailing garbage: `host:443abc` → `(host, Some(443))`
fn parse_hostport(s: &str) -> (String, Option<u16>) {
    // Handle IPv6: [::1]:port
    if let Some(inner) = s.strip_prefix('[') {
        if let Some((host, port_part)) = inner.split_once("]:") {
            let port = port_part.parse::<u16>().ok();
            let host = port.map_or_else(
                || format!("[{host}]"),
                |port| format!("[{host}]:{port}").split_off(host.len() + 2),
            );
            return (host, port);
        }
        let trimmed = s.trim_end_matches(']');
        return (format!("[{}]", &trimmed[1..]), None);
    }
    // Iterative scan from right: find first colon where the suffix starts
    // with valid ASCII digits forming a u16 port number.
    // Handles port-suffix like `host:443:extra` and trailing-garbage like `host:443abc`.
    let mut remaining = s;
    let mut selected_port = None;
    while let Some((h, p)) = remaining.rsplit_once(':') {
        let digit_len = p
            .bytes()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(p.len());
        if digit_len > 0
            && digit_len <= 5
            && let Ok(parsed) = p[..digit_len].parse::<u16>()
        {
            selected_port = Some(parsed);
            remaining = h;
            break;
        }
        // Not a valid port suffix — scan further left
        remaining = h;
    }
    (remaining.to_string(), selected_port)
}

/// Fix bare `%` characters not followed by 2 valid hex digits by percent-encoding them.
/// Borrows when the input needs no fix (the common path for hosts).
fn fix_percent_encoding(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains('%') {
        return std::borrow::Cow::Borrowed(s);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit()
            {
                out.push(b'%');
            } else {
                out.extend_from_slice(b"%25");
            }
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    std::borrow::Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

/// Percent-decode a string, borrowing when there is nothing to decode.
/// Fallback to original on failure. Keys/values that need no unescaping stay
/// zero-copy; only escaped components allocate.
fn percent_decode(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains('%') {
        return std::borrow::Cow::Borrowed(s);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val_sub(bytes[i + 1]);
            let lo = hex_val_sub(bytes[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned().into()
}

/// Normalize a remark string: percent-decode, trim, collapse inner whitespace.
#[must_use]
pub fn normalize_remark(s: &str) -> String {
    let decoded = percent_decode(s);
    let mut out = String::with_capacity(decoded.len());
    let mut prev_was_space = false;
    for c in decoded.chars() {
        if c.is_whitespace() {
            if !prev_was_space {
                out.push(' ');
                prev_was_space = true;
            }
        } else {
            out.push(c);
            prev_was_space = false;
        }
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        trimmed.to_string()
    }
}

#[inline]
const fn hex_val_sub(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}
/// Parse query string into borrowed `&str` ranges — linear scan, no `HashMap`.
/// Keys stay borrowed (URL-split validation compares `k` directly); only
/// decoded values that need unescaping allocate.
fn parse_query_params(query: &str) -> Vec<(&str, std::borrow::Cow<'_, str>)> {
    let mut result = Vec::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            result.push((k, percent_decode(v)));
        } else if !pair.is_empty() {
            result.push((pair, std::borrow::Cow::Borrowed("")));
        }
    }
    result
}

// ── Validation Layer ─────────────────────────────────────────────────────

/// Settings controlling how strictly parsed profiles are validated.
#[derive(Debug, Clone, Default)]
pub struct ValidationSettings {
    /// If true, allow private/loopback IPs. Default: false.
    ///
    /// NOTE: the typed parse boundary (T4/T5) already rejects private/
    /// loopback/localhost hosts at parse time, so this setting can no longer
    /// admit them for URL parsing; it still governs the config-layer
    /// `validate_host` checks (unspecified/private/loopback) for parsed hosts.
    pub allow_private_ips: bool,
    /// If true, reject profiles with allowInsecure=true. Default: false.
    pub reject_insecure: bool,
}

impl From<crate::app_config::ParsingSettings> for ValidationSettings {
    fn from(p: crate::app_config::ParsingSettings) -> Self {
        Self {
            allow_private_ips: p.allow_private_ips,
            reject_insecure: p.reject_insecure,
        }
    }
}

/// Per-protocol required-field validation against a typed [`ParsedProto`].
///
/// The primary endpoint supplies address/port; the credential requirement is
/// checked per protocol variant on the typed config fields (port of the
/// legacy `validate_required_fields` — T11).
fn validate_required_fields(parsed: &ParsedProto) -> Result<(), String> {
    let missing = |field: &str| Err(format!("missing field: {field}"));

    let endpoint_ok = || {
        parsed
            .endpoints
            .first()
            .is_some_and(|e| !e.host.is_empty() && e.port != 0)
    };
    let cred = |s: &str| {
        if s.is_empty() {
            missing("user_id")
        } else {
            Ok(())
        }
    };

    match &parsed.protocol.config {
        ProtocolConfig::Vless(c) => {
            if !endpoint_ok() {
                return missing("address");
            }
            cred(&c.uuid)
        }
        ProtocolConfig::Vmess(c) => {
            if !endpoint_ok() {
                return missing("address");
            }
            cred(&c.uuid)
        }
        ProtocolConfig::Trojan(c) => {
            if !endpoint_ok() {
                return missing("address");
            }
            cred(&c.password)
        }
        ProtocolConfig::Ss(c) => {
            if !endpoint_ok() {
                return missing("address");
            }
            cred(&c.password)
        }
        ProtocolConfig::Ssr(c) => {
            if !endpoint_ok() {
                return missing("address");
            }
            cred(&c.password)
        }
        ProtocolConfig::Tuic(c) => {
            if !endpoint_ok() {
                return missing("address");
            }
            // Legacy has_credential counted uuid OR password (tuic URLs carry
            // `uuid:password`; password-only must not be stricter).
            if c.uuid.is_empty() && c.password.is_empty() {
                missing("user_id")
            } else {
                Ok(())
            }
        }
        ProtocolConfig::Hysteria2(c) => {
            if !endpoint_ok() {
                return missing("address");
            }
            cred(&c.auth)
        }
        ProtocolConfig::Naive(c) => {
            if !endpoint_ok() {
                return missing("address");
            }
            if c.password.is_empty() {
                return missing("user_id");
            }
            Ok(())
        }
        ProtocolConfig::AnyTls(c) => {
            if !endpoint_ok() {
                return missing("address");
            }
            if c.password.as_deref().unwrap_or("").is_empty() {
                return missing("user_id");
            }
            Ok(())
        }
        ProtocolConfig::ShadowTls(c) => {
            if !endpoint_ok() {
                return missing("address");
            }
            if c.password.as_deref().unwrap_or("").is_empty() {
                return missing("user_id");
            }
            Ok(())
        }
        ProtocolConfig::Hysteria1(_) | ProtocolConfig::Socks(_) | ProtocolConfig::Http(_) => {
            if endpoint_ok() {
                Ok(())
            } else {
                missing("address")
            }
        }
        ProtocolConfig::Wireguard(c) => {
            if c.public_key.is_empty() {
                missing("public_key in protocol_settings")
            } else {
                Ok(())
            }
        }
        ProtocolConfig::Tor(_)
        | ProtocolConfig::Ssh(_)
        | ProtocolConfig::Tailscale(_)
        | ProtocolConfig::Redirect(_)
        | ProtocolConfig::TProxy(_)
        | ProtocolConfig::Mixed(_) => Ok(()),
    }
}

/// Check whether a hostname is valid for use as a server address.
/// Rejects underscores, non-ASCII, and other characters that are
/// not valid in DNS labels.
fn is_valid_hostname(host: &str) -> bool {
    // Strip a trailing dot (FQDN root dot).
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 || host.starts_with('.') || host.contains("..") {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Validate the primary endpoint host is not unspecified/private/loopback/link-local.
///
/// This config layer is the single authority for host policy (T11 moved it
/// out of the parse boundary): the hard unspecified-address rule applies to
/// every host, and the `allow_private_ips` setting gates private, loopback,
/// link-local, and "localhost" hosts.
///
/// Hostnames are validated against RFC-compliant DNS labels — underscores,
/// non-ASCII, and other invalid characters are rejected.
pub fn validate_host(
    parsed: &ParsedProto,
    settings: &ValidationSettings,
) -> Result<(), ImportError> {
    let Some(endpoint) = parsed.endpoints.first() else {
        return Ok(()); // no address to validate
    };
    let addr = &endpoint.host;
    if addr.is_empty() {
        return Ok(()); // no address to validate
    }

    // Strip brackets for IPv6 literals (e.g. "[::1]").
    let parse_target: &str = addr
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(addr);

    // Normalize IDN (internationalized domain names) to punycode using
    // `url::Host`, which handles non-ASCII labels per RFC 3490. Non-ASCII
    // hostnames like `中文.example.com` become `xn--fsqu00a.xn--0zwm56d.xn--5nxp`,
    // which the IP/hostname checks below can classify correctly.
    let normalized =
        url::Host::parse(parse_target).map_or_else(|_| parse_target.to_string(), |h| h.to_string());

    let parsed_ip: Option<IpAddr> = normalized.parse().ok();

    // Classify a NORMALIZED address. "::ffff:a.b.c.d" denotes the embedded
    // IPv4 address, but Ipv6Addr::is_loopback/is_unique_local/
    // is_unicast_link_local/is_unspecified are defined over native v6 prefixes
    // only, so the mapped form escaped every check below (including the
    // ungated unspecified hard rule). Unwrap it before choosing the rules.
    let parsed_ip: Option<IpAddr> = parsed_ip.map(|ip| match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    });

    // Hard rule: unspecified addresses (0.0.0.0 / ::) are never valid server
    // targets — not gated by allow_private_ips.
    if let Some(ip) = parsed_ip {
        let unspecified = match ip {
            IpAddr::V4(v4) => v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified(),
        };
        if unspecified {
            return Err(ImportError::Validation(
                "unspecified IP address (0.0.0.0/::)".into(),
            ));
        }
    }

    // DNS-name rules run BEFORE the private-IP gate: a DNS name is not an IP,
    // so `allow_private_ips` must not skip them. db-rewamp T5 adds the
    // registrable-domain rule — a name the psl2 split cannot map to a domain
    // cannot key an endpoint, so it is rejected (per-profile; the import skips
    // and counts it).
    if parsed_ip.is_none() {
        let lower = normalized.to_lowercase();
        if lower == "localhost" || lower.ends_with(".localhost") {
            return Err(ImportError::Validation("localhost hostname".into()));
        }
        if !is_valid_hostname(&normalized) {
            return Err(ImportError::Validation("invalid hostname".into()));
        }
        if leas_proto::domain::split(&normalized).is_none() {
            return Err(ImportError::Validation(
                "host has no registrable domain".into(),
            ));
        }
    }

    if settings.allow_private_ips {
        return Ok(());
    }

    // Try parsing as IP address
    match parsed_ip {
        Some(IpAddr::V4(v4)) => {
            if v4.is_loopback() {
                return Err(ImportError::Validation("loopback IP address".into()));
            }
            if v4.is_private() {
                return Err(ImportError::Validation("private IP address".into()));
            }
            if v4.is_link_local() {
                return Err(ImportError::Validation("link-local IP address".into()));
            }
        }
        Some(IpAddr::V6(v6)) => {
            if v6.is_loopback() {
                return Err(ImportError::Validation("loopback IP address".into()));
            }
            if v6.is_unique_local() {
                return Err(ImportError::Validation("unique-local IP address".into()));
            }
            if v6.is_unicast_link_local() {
                return Err(ImportError::Validation("link-local IP address".into()));
            }
        }
        None => {} // validated above
    }

    Ok(())
}

/// Consolidated validation summary for a batch of profile imports (e.g. subscription).
#[derive(Debug, Clone, Default)]
pub struct ValidationSummary {
    /// Errors that made a candidate unusable (missing fields, host validation,
    /// other parse failures). **Excludes** [`Self::security_warning_count`]:
    /// a profile whose author disabled TLS verification imports fine, and
    /// counting it here made a 23,574-link import log "16,325 errors" when
    /// 16,140 of them were `insecure=true` warnings.
    pub total_errors: usize,
    pub missing_field_count: usize,
    pub host_validation_count: usize,
    /// Profiles that imported but demand no certificate verification.
    pub security_warning_count: usize,
    pub other_count: usize,
    /// A bounded sample of WHY entries failed.
    ///
    /// The counters alone could not diagnose the 2026-10-01 run's
    /// `1 links, 1 errors` subscription: it failed 4/4 with every count zero
    /// except `other: 1`, and the message explaining why was discarded right
    /// where it was produced. Capped, because a 90k-link feed with 1,498 errors
    /// must not turn the log into a wall of text.
    pub sample_errors: Vec<String>,
    /// Errors not represented in `sample_errors`, because the cap was reached.
    pub sample_errors_omitted: usize,
}

impl ValidationSummary {
    /// Cap on `sample_errors`.
    pub const SAMPLE_ERROR_CAP: usize = 5;

    /// Record one failure reason — the **message only**, never the URL, which
    /// carries credentials.
    pub fn record_error(&mut self, reason: impl Into<String>) {
        if self.sample_errors.len() < Self::SAMPLE_ERROR_CAP {
            self.sample_errors.push(reason.into());
        } else {
            self.sample_errors_omitted += 1;
        }
    }
    /// Add `other`'s counters into `self` (chunked imports sum per-batch
    /// summaries into one whole-run summary).
    pub fn merge(&mut self, other: &Self) {
        self.total_errors += other.total_errors;
        self.missing_field_count += other.missing_field_count;
        self.host_validation_count += other.host_validation_count;
        self.security_warning_count += other.security_warning_count;
        self.other_count += other.other_count;
        for reason in &other.sample_errors {
            self.record_error(reason.clone());
        }
        self.sample_errors_omitted += other.sample_errors_omitted;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leas_proto::proto_spec::{ProtoSpec, ProtocolKind};

    /// Test settings with private IPs allowed (existing tests use various IPs).
    fn permissive_settings() -> ValidationSettings {
        ValidationSettings {
            allow_private_ips: true,
            reject_insecure: false,
        }
    }

    /// Minimal Vless [`ParsedProto`] whose endpoint host is overridden — lets
    /// `validate_host` be exercised on arbitrary hosts without round-tripping
    /// through `parse_share_url`.
    fn parsed_with_host(host: &str) -> ParsedProto {
        let mut parsed = ProtocolConfig::try_parse_proto(&RawUrlX::from(
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?type=tcp",
        ))
        .expect("canonical vless URL parses");
        parsed.endpoints[0].host = host.to_string();
        parsed
    }

    /// Parse → format → re-parse; assert semantic equality (identity, endpoint,
    /// and config payload all match).
    fn assert_roundtrip(url: &str) -> (ParsedProfile, ParsedProfile) {
        let p1 = parse_share_url(url, &permissive_settings())
            .unwrap_or_else(|e| panic!("parse {url}: {e}"));
        let rebuilt = format_share_url(&p1.parsed, &p1.parsed.endpoints[0])
            .unwrap_or_else(|e| panic!("format {url}: {e}"));
        let p2 = parse_share_url(&rebuilt, &permissive_settings())
            .unwrap_or_else(|e| panic!("reparse {rebuilt}: {e}"));
        assert_eq!(
            p1.parsed.uid(),
            p2.parsed.uid(),
            "uid mismatch for {url} -> {rebuilt}"
        );
        assert_eq!(
            p1.parsed.endpoints, p2.parsed.endpoints,
            "endpoint mismatch for {url} -> {rebuilt}"
        );
        assert_eq!(
            serde_json::to_value(&p1.parsed.protocol).expect("protocol serializable"),
            serde_json::to_value(&p2.parsed.protocol).expect("protocol serializable"),
            "config payload mismatch for {url} -> {rebuilt}"
        );
        (p1, p2)
    }

    // ── normalize_remark ──

    #[test]
    fn normalize_remark_basic() {
        assert_eq!(normalize_remark("hello"), "hello");
    }

    #[test]
    fn normalize_remark_percent_decoded() {
        // Japanese "test" in percent-encoded UTF-8
        let result = normalize_remark("%E6%B5%8B%E8%AF%95");
        assert_eq!(result, "测试");
    }

    #[test]
    fn normalize_remark_whitespace_collapsed() {
        assert_eq!(normalize_remark("  hello   world  "), "hello world");
        assert_eq!(normalize_remark("\tfoo \n bar\r\n baz"), "foo bar baz");
    }

    #[test]
    fn normalize_remark_emoji_percent_decoded() {
        // Grinning face emoji
        let result = normalize_remark("%F0%9F%98%80");
        assert_eq!(result, "😀");
    }

    #[test]
    fn normalize_remark_empty_after_trim() {
        assert_eq!(normalize_remark("  "), "");
        assert_eq!(normalize_remark("%20%20"), "");
    }

    #[test]
    fn normalize_remark_no_change_for_plain_text() {
        assert_eq!(normalize_remark("  My Server 1  "), "My Server 1");
    }

    // ── validate_host ──

    #[test]
    fn validate_host_rejects_unspecified_ipv4() {
        let err = validate_host(&parsed_with_host("0.0.0.0"), &ValidationSettings::default())
            .expect_err("0.0.0.0 must be rejected");
        assert!(
            err.to_string().contains("unspecified"),
            "error must mention unspecified: {err}"
        );
        // Hard rule — allow_private_ips must not re-admit it.
        let err = validate_host(&parsed_with_host("0.0.0.0"), &permissive_settings())
            .expect_err("0.0.0.0 must be rejected even with allow_private_ips");
        assert!(
            err.to_string().contains("unspecified"),
            "error must mention unspecified: {err}"
        );
    }

    #[test]
    fn validate_host_rejects_unspecified_ipv6() {
        for addr in ["::", "[::]"] {
            let err = validate_host(&parsed_with_host(addr), &ValidationSettings::default())
                .expect_err("addr must be rejected");
            assert!(
                err.to_string().contains("unspecified"),
                "error for {addr} must mention unspecified: {err}"
            );
        }
    }

    #[test]
    fn validate_host_bracketed_ipv6_loopback_rejected() {
        // Regression guard: IPv6 hosts in bracketed form ("[::1]").
        let err = validate_host(&parsed_with_host("[::1]"), &ValidationSettings::default())
            .expect_err("[::1] loopback must be rejected");
        assert!(
            err.to_string().contains("loopback"),
            "error must mention loopback: {err}"
        );
    }

    #[test]
    fn validate_host_rejects_localhost_hostname() {
        let err = validate_host(
            &parsed_with_host("localhost"),
            &ValidationSettings::default(),
        )
        .expect_err("localhost must be rejected");
        assert!(
            err.to_string().contains("localhost"),
            "error must mention localhost: {err}"
        );
    }

    /// IPv4-mapped IPv6 literals (e.g. `::ffff:0.0.0.0`) must NOT bypass
    /// the unspecified-address hard rule.
    #[test]
    fn validate_host_rejects_ipv4_mapped_unspecified() {
        for addr in ["::ffff:0.0.0.0", "[::ffff:0.0.0.0]"] {
            let err =
                validate_host(&parsed_with_host(addr), &ValidationSettings::default()).unwrap_err();
            assert!(
                err.to_string().contains("unspecified"),
                "error for {addr} must mention unspecified: {err}"
            );
        }
    }

    /// IPv4-mapped IPv6 loopback (`::ffff:127.0.0.1`) must NOT bypass
    /// the loopback check.
    #[test]
    fn validate_host_rejects_ipv4_mapped_loopback() {
        let err = validate_host(
            &parsed_with_host("::ffff:127.0.0.1"),
            &ValidationSettings::default(),
        )
        .expect_err("mapped loopback must be rejected");
        assert!(
            err.to_string().contains("loopback"),
            "error must mention loopback: {err}"
        );
    }

    /// IPv4-mapped IPv6 private addresses (`::ffff:192.168.1.1`) must NOT
    /// bypass the private-IP check.
    #[test]
    fn validate_host_rejects_ipv4_mapped_private() {
        let err = validate_host(
            &parsed_with_host("::ffff:192.168.1.1"),
            &ValidationSettings::default(),
        )
        .expect_err("mapped private must be rejected");
        assert!(
            err.to_string().contains("private"),
            "error must mention private: {err}"
        );
    }

    /// Hostnames that IDN can normalize must be validated in their punycode
    /// form. Non-ASCII names are ACCEPTED (converted to punycode), but a
    /// Unicode spelling of `localhost` or a private/loopback IP must still be
    /// rejected after normalization — otherwise the normalization itself would
    /// be a bypass.
    #[test]
    fn validate_host_accepts_idn_and_rejects_unicode_bypasses() {
        // Underscores are not punycode-encodable and are not valid hostname
        // characters → rejected.
        let err = validate_host(
            &parsed_with_host("host_with_underscore.example.com"),
            &ValidationSettings::default(),
        )
        .expect_err("underscore hostname must be rejected");
        assert!(
            err.to_string().contains("host"),
            "error must mention host: {err}"
        );

        // Genuine IDN (Chinese) converts to punycode → accepted.
        validate_host(
            &parsed_with_host("中文.example.com"),
            &ValidationSettings::default(),
        )
        .expect("IDN hostname must be accepted via punycode");

        // A Unicode/fullwidth spelling of a restricted form must still be
        // rejected once normalized: `ｌｏｃａｌｈｏｓｔ` → `localhost`.
        let err = validate_host(
            &parsed_with_host("ｌｏｃａｌｈｏｓｔ"),
            &ValidationSettings::default(),
        )
        .expect_err("fullwidth localhost must be rejected after normalization");
        assert!(
            err.to_string().contains("localhost"),
            "error must mention localhost: {err}"
        );

        // `１２７.０.０.１` (fullwidth digits) → `127.0.0.1` → loopback.
        let err = validate_host(
            &parsed_with_host("１２７.０.０.１"),
            &ValidationSettings::default(),
        )
        .expect_err("fullwidth loopback IP must be rejected after normalization");
        assert!(
            err.to_string().contains("loopback"),
            "error must mention loopback: {err}"
        );
    }

    // ── parse_share_url error paths ──

    #[test]
    fn parse_share_url_rejects_unspecified_host() {
        let settings = ValidationSettings::default();
        let v4 = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@0.0.0.0:443?type=tcp#r";
        let Err(err) = parse_share_url(v4, &settings) else {
            panic!("0.0.0.0 URL must be rejected");
        };
        assert!(
            err.to_string().contains("unspecified"),
            "error must mention unspecified: {err}"
        );
        let v6 = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@[::]:443?type=tcp#r";
        let Err(err) = parse_share_url(v6, &settings) else {
            panic!("[::] URL must be rejected");
        };
        assert!(
            err.to_string().contains("unspecified"),
            "error must mention unspecified: {err}"
        );
    }

    #[test]
    fn subscription_unspecified_host_counts_as_host_validation() {
        let payload = concat!(
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@0.0.0.0:443?type=tcp#bad\n",
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@cdn.example.com:443?type=tcp#ok\n",
        );
        let (profiles, summary) = crate::subscription::parse_subscription_data(
            payload.as_bytes(),
            &ValidationSettings::default(),
        )
        .expect("subscription data must decode");
        assert_eq!(profiles.len(), 1, "only the valid URL should survive");
        assert_eq!(
            summary.host_validation_count, 1,
            "0.0.0.0 must count as host validation"
        );
    }

    #[test]
    fn reject_private_ip() {
        // Private/loopback hosts parse fine at the typed boundary (structural
        // only) but are rejected by the config-layer host policy when
        // allow_private_ips=false.
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@127.0.0.1:443?type=tcp#test";
        let settings = ValidationSettings {
            allow_private_ips: false,
            reject_insecure: false,
        };
        assert!(matches!(
            parse_share_url(url, &settings),
            Err(ImportError::Validation(_))
        ));
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@10.0.0.5:443?type=tcp#test";
        assert!(matches!(
            parse_share_url(url, &settings),
            Err(ImportError::Validation(_))
        ));
    }

    #[test]
    fn accept_private_ip_when_allowed() {
        // Same URLs with allow_private_ips=true must succeed (the gate is the
        // single host-policy authority — regression guard for T11 F1).
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@127.0.0.1:443?type=tcp#test";
        let settings = ValidationSettings {
            allow_private_ips: true,
            reject_insecure: false,
        };
        let p = parse_share_url(url, &settings).unwrap();
        assert_eq!(p.parsed.endpoints[0].host, "127.0.0.1");
    }

    #[test]
    fn reject_localhost_hostname() {
        // "localhost" and "*.localhost" (RFC 6761 special-use domains) have no
        // registrable domain, so the psl2 split (db-rewamp D2/T5) rejects them
        // at the config layer — unconditionally, because the private-IP gate
        // does not apply to a DNS name and the endpoint model cannot key a
        // domainless host.
        for host in ["localhost", "foo.localhost"] {
            let url =
                format!("vless://6202b230-417c-4d8e-b624-0f71afa9c75d@{host}:443?type=tcp#test");
            for allow_private_ips in [false, true] {
                let settings = ValidationSettings {
                    allow_private_ips,
                    reject_insecure: false,
                };
                assert!(
                    matches!(
                        parse_share_url(&url, &settings),
                        Err(ImportError::Validation(_))
                    ),
                    "{host} must be rejected (allow_private_ips={allow_private_ips})"
                );
            }
        }
    }

    /// A DNS name with no registrable domain (a single label, or a bare public
    /// suffix) is rejected for BOTH gate settings — the psl2 split cannot map it
    /// to `domain`/`sub_domain` (db-rewamp D2/T5).
    #[test]
    fn reject_dns_name_without_registrable_domain() {
        for host in ["myproxyserver", "co.uk", "github.io"] {
            let url =
                format!("vless://6202b230-417c-4d8e-b624-0f71afa9c75d@{host}:443?type=tcp#test");
            for allow_private_ips in [false, true] {
                let settings = ValidationSettings {
                    allow_private_ips,
                    reject_insecure: false,
                };
                assert!(
                    matches!(
                        parse_share_url(&url, &settings),
                        Err(ImportError::Validation(_))
                    ),
                    "{host} has no registrable domain and must be rejected"
                );
            }
        }
        // A registrable name (including one under a private suffix) is admitted.
        let ok = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@foo.github.io:443?type=tcp#x";
        let settings = ValidationSettings {
            allow_private_ips: false,
            reject_insecure: false,
        };
        assert!(
            parse_share_url(ok, &settings).is_ok(),
            "foo.github.io is registrable"
        );
    }

    /// The documented `parsing.reject_insecure` gate must actually reject a
    /// feed-supplied profile whose TLS verification is disabled.
    #[test]
    fn reject_insecure_gate_is_enforced() {
        let rejecting = ValidationSettings {
            allow_private_ips: false,
            reject_insecure: true,
        };
        let permissive = ValidationSettings {
            allow_private_ips: false,
            reject_insecure: false,
        };
        let insecure_urls = [
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=tls&type=tcp&allowInsecure=1#r",
            "trojan://humanity@example.com:443?security=tls&type=tcp&allowInsecure=1#r",
            "hysteria2://secret@example.com:443?insecure=1#r",
        ];
        for url in insecure_urls {
            assert!(
                matches!(
                    parse_share_url(url, &rejecting),
                    Err(ImportError::Validation(_))
                ),
                "reject_insecure=true must reject {url}"
            );
            assert!(
                parse_share_url(url, &permissive).is_ok(),
                "reject_insecure=false must accept {url}"
            );
        }
        // A profile that keeps verification is unaffected by the gate.
        let secure =
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?security=tls&type=tcp#r";
        assert!(parse_share_url(secure, &rejecting).is_ok());
    }

    #[test]
    fn garbage_url_rejected() {
        // No `://` at all — shape gate error.
        assert!(parse_share_url("not-a-url", &permissive_settings()).is_err());
        assert!(parse_share_url("", &permissive_settings()).is_err());
        // Unknown scheme → UnsupportedScheme.
        assert!(matches!(
            parse_share_url("xyzzy://192.168.1.1:443", &permissive_settings()),
            Err(ImportError::UnsupportedScheme)
        ));
    }

    #[test]
    fn hostless_wireguard_rejected() {
        // Behavior change vs legacy: the legacy parser accepted hostless
        // wireguard:// URLs (deterministic fallback uid); the typed parse
        // boundary requires a host (MissingHost).
        let url = "wireguard://?public_key=abc&address=10.0.0.2/32";
        assert!(parse_share_url(url, &permissive_settings()).is_err());
    }

    // ── Validation (required fields) ──

    #[test]
    fn missing_credential_reports_validation_error() {
        // ShadowTLS without password parses (credential optional in parser)
        // but fails required-field validation.
        let p = parse_share_url("shadowtls://1.2.3.4:443", &permissive_settings()).unwrap();
        assert!(
            p.validation.is_err(),
            "shadowtls w/o password must fail validation"
        );
        assert!(
            p.validation.as_ref().unwrap_err().contains("missing field"),
            "error must mention missing field: {:?}",
            p.validation
        );
        // Trojan with empty password: parse ok, validation err.
        let p =
            parse_share_url("trojan://@example.com:443?type=tcp", &permissive_settings()).unwrap();
        assert!(
            p.validation.is_err(),
            "trojan w/o password must fail validation"
        );
        // A complete trojan URL validates ok.
        let p = parse_share_url("trojan://pass@example.com:443", &permissive_settings()).unwrap();
        assert!(p.validation.is_ok(), "complete trojan must validate ok");
    }

    #[test]
    fn tuic_password_only_validation_not_stricter_than_legacy() {
        // Legacy has_credential accepted uuid OR password for tuic; the typed
        // check must not be stricter. (The typed PARSER requires a valid
        // uuid, so this exercises validate_required_fields directly on a
        // parsed profile with the uuid stripped.)
        let mut parsed = ProtocolConfig::try_parse_proto(&RawUrlX::from(
            "tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:pw@example.com:443",
        ))
        .expect("canonical tuic URL parses");
        match &mut parsed.protocol.config {
            ProtocolConfig::Tuic(c) => c.uuid.clear(),
            other => panic!("expected tuic config, got {other:?}"),
        }
        assert!(
            validate_required_fields(&parsed).is_ok(),
            "password-only tuic must pass validation"
        );
        match &mut parsed.protocol.config {
            ProtocolConfig::Tuic(c) => c.password.clear(),
            other => panic!("expected tuic config, got {other:?}"),
        }
        assert!(
            validate_required_fields(&parsed).is_err(),
            "credential-less tuic must fail validation"
        );
    }

    #[test]
    fn vmess_missing_address_is_parse_error() {
        // The typed vmess parser requires `add` (MissingHost), so an
        // address-less vmess URL is a parse error rather than a validation
        // error (legacy behavior differed).
        let qr = serde_json::json!({ "v": 2, "ps": "test", "add": "", "port": 443, "id": "uuid" });
        let b64 = base64_simd::STANDARD.encode_to_string(serde_json::to_string(&qr).unwrap());
        let url = format!("vmess://{b64}");
        assert!(parse_share_url(&url, &permissive_settings()).is_err());
    }

    // ── Round-trip tests for all URL-supported protocols ──

    #[test]
    fn roundtrip_vmess() {
        let qr = serde_json::json!({
            "v": "2", "ps": "test", "add": "1.2.3.4", "port": "443",
            "id": "550e8400-e29b-41d4-a716-446655440000", "aid": "0", "scy": "auto",
            "net": "tcp", "type": "none", "host": "", "path": "", "tls": "",
            "sni": "", "alpn": "", "fp": "", "insecure": "0",
        });
        let b64 = base64_simd::STANDARD.encode_to_string(serde_json::to_string(&qr).unwrap());
        let url = format!("vmess://{b64}");
        let p1 = parse_share_url(&url, &permissive_settings()).unwrap();
        assert_eq!(p1.parsed.protocol.proto_kind, ProtocolKind::Vmess);
        assert_eq!(p1.parsed.endpoints[0].host, "1.2.3.4");
        assert_eq!(p1.parsed.endpoints[0].port, 443);
        assert!(p1.validation.is_ok());
        assert_roundtrip(&url);
    }

    #[test]
    fn roundtrip_vless() {
        assert_roundtrip("vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?type=tcp");
    }

    #[test]
    fn roundtrip_trojan() {
        assert_roundtrip("trojan://pass@example.com:443?security=none");
    }

    #[test]
    fn roundtrip_shadowsocks() {
        assert_roundtrip("ss://Y2xlb2Y6cGFzc3dvcmQ@example.com:443#my-server");
    }

    #[test]
    fn roundtrip_shadowsocksr() {
        assert_roundtrip(
            "ssr://ZXhhbXBsZS5jb206NDQzOm9yaWdpbjpyYzQtbWQ1OnBsYWluOmNHRnpjM2R2Y21RLz9ncm91cD1WR1Z6ZEVkeWIzVncmcmVtYXJrcz1WR1Z6ZEZObGNuWmxjZw",
        );
    }

    #[test]
    fn roundtrip_tuic() {
        assert_roundtrip(
            "tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:dongtaiwang.com@5.178.101.117:30006?congestion_control=cubic&udp_relay_mode=native&alpn=h3",
        );
    }

    #[test]
    fn roundtrip_hysteria2() {
        assert_roundtrip("hysteria2://secret@example.com:443,7788,9999?insecure=1");
    }

    #[test]
    fn roundtrip_hysteria() {
        assert_roundtrip("hysteria://example.com:443?protocol=udp#My%20Server");
    }

    #[test]
    fn roundtrip_socks() {
        assert_roundtrip("socks://user:pass@1.2.3.4:1080");
    }

    #[test]
    fn roundtrip_http() {
        assert_roundtrip("http://user:pass@1.2.3.4:8080");
    }

    #[test]
    fn roundtrip_naive() {
        assert_roundtrip("naive+https://user:pass@example.com:443#my-server");
    }

    #[test]
    fn roundtrip_anytls() {
        assert_roundtrip("anytls://1.2.3.4:8080?password=secret");
    }

    #[test]
    fn roundtrip_shadowtls() {
        // No password: parse + format still round-trip; validation errs
        // (covered by `missing_credential_reports_validation_error`).
        assert_roundtrip("shadowtls://1.2.3.4:443");
    }

    #[test]
    fn roundtrip_wireguard() {
        assert_roundtrip(
            "wireguard://privatekey==@wg.example.com:51820?address=10.0.0.2%2F32&publickey=serverpubkey==",
        );
    }

    // ── Identity ──

    #[test]
    fn identity_same_config_different_servers() {
        // Same protocol config pointed at two endpoints → equal uid
        // (endpoints never participate in identity hashing).
        let a = parse_share_url(
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?type=tcp",
            &permissive_settings(),
        )
        .unwrap();
        let b = parse_share_url(
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@other.example.org:8443?type=tcp",
            &permissive_settings(),
        )
        .unwrap();
        assert_eq!(
            a.parsed.uid(),
            b.parsed.uid(),
            "same config must dedup to one uid"
        );
        assert_ne!(a.parsed.endpoints[0].host, b.parsed.endpoints[0].host);
    }

    #[test]
    fn identity_differs_across_credentials() {
        let a = parse_share_url(
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@example.com:443?type=tcp",
            &permissive_settings(),
        )
        .unwrap();
        let b = parse_share_url(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp",
            &permissive_settings(),
        )
        .unwrap();
        assert_ne!(
            a.parsed.uid(),
            b.parsed.uid(),
            "different credentials must differ"
        );
    }

    // ── Real-world URL fidelity (ported from legacy suite) ──

    const WORKING_URL_1: &str = "vless://a5ea9247-79f3-4655-aece-3fb51e1e669e@146.103.99.45:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=rezerv.yunus.guru&fp=firefox&pbk=S4WFc-SD_FpmmQdM21Of7O6XmYaLlmwcmlbgO4lZQQg&sid=a7ec6c3316eddb11&type=tcp&headerType=none#%5B332ms%20%D0%A4%D0%B8%D0%BD%D0%BB%D1%8F%D0%BD%D0%B4%D0%B8%D1%8F%20FI%20%F0%9F%87%AB%F0%9F%87%AE%20%40vlesstrojan%5D";
    const WORKING_URL_2: &str = "vless://a5ea9247-79f3-4655-aece-3fb51e1e669e@144.124.241.233:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=rezerv1.yunus.guru&fp=firefox&pbk=-X9CZv5MYKivpxPVP1vdgFKf2AJWmZ0Pju-j8LFmlh4&sid=6c88854e73e86773&type=tcp&headerType=none#%5B333ms%20%D0%A4%D0%B8%D0%BD%D0%BB%D1%8F%D0%BD%D0%B4%D0%B8%D1%8F%20FI%20%F0%9F%87%AB%F0%9F%87%AE%20%40vlesstrojan%5D";
    const WORKING_URL_3: &str = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTprMWRCT21PQjRvcWk3VW1wMzdhMWJR@82.38.31.192:8080?#%5B164ms%20%D0%90%D0%B2%D1%81%D1%82%D1%80%D0%B8%D1%8F%20AT%20%F0%9F%87%A6%F0%9F%87%B9%20%40vlesstrojan%5D";

    #[test]
    fn parse_working_txt_urls() {
        // ── VLESS Reality URL 1 ──
        let p = parse_share_url(WORKING_URL_1, &permissive_settings()).unwrap();
        assert_eq!(p.parsed.protocol.proto_kind, ProtocolKind::Vless);
        assert_eq!(p.parsed.endpoints[0].host, "146.103.99.45");
        assert_eq!(p.parsed.endpoints[0].port, 443);
        assert_eq!(
            profile_user_id(&p.parsed.protocol.config).as_deref(),
            Some("a5ea9247-79f3-4655-aece-3fb51e1e669e")
        );
        let sec = p
            .parsed
            .protocol
            .config
            .security()
            .expect("vless has security");
        assert_eq!(sec.sni(), Some("rezerv.yunus.guru"));
        assert_eq!(sec.fp(), Some("firefox"));
        assert_eq!(
            sec.pbk(),
            Some("S4WFc-SD_FpmmQdM21Of7O6XmYaLlmwcmlbgO4lZQQg")
        );
        assert_eq!(sec.sid(), Some("a7ec6c3316eddb11"));
        let remarks = p.parsed.protocol.config.remarks().expect("remarks present");
        assert!(
            remarks.contains("Финляндия"),
            "remarks must contain the country name: {remarks}"
        );

        // ── VLESS Reality URL 2 ──
        let p = parse_share_url(WORKING_URL_2, &permissive_settings()).unwrap();
        assert_eq!(p.parsed.protocol.proto_kind, ProtocolKind::Vless);
        assert_eq!(p.parsed.endpoints[0].host, "144.124.241.233");
        assert_eq!(p.parsed.endpoints[0].port, 443);
        assert_eq!(
            profile_user_id(&p.parsed.protocol.config).as_deref(),
            Some("a5ea9247-79f3-4655-aece-3fb51e1e669e")
        );
        let sec = p
            .parsed
            .protocol
            .config
            .security()
            .expect("vless has security");
        assert_eq!(sec.sni(), Some("rezerv1.yunus.guru"));
        assert_eq!(
            sec.pbk(),
            Some("-X9CZv5MYKivpxPVP1vdgFKf2AJWmZ0Pju-j8LFmlh4")
        );
        assert_eq!(sec.sid(), Some("6c88854e73e86773"));

        // ── Shadowsocks URL 3 ──
        let p = parse_share_url(WORKING_URL_3, &permissive_settings()).unwrap();
        assert_eq!(p.parsed.protocol.proto_kind, ProtocolKind::Shadowsocks);
        assert_eq!(p.parsed.endpoints[0].host, "82.38.31.192");
        assert_eq!(p.parsed.endpoints[0].port, 8080);
        let remarks = p.parsed.protocol.config.remarks().expect("remarks present");
        assert!(
            remarks.contains("Австрия"),
            "remarks must contain the country: {remarks}"
        );
        match &p.parsed.protocol.config {
            ProtocolConfig::Ss(c) => {
                assert_eq!(c.method.as_str(), "chacha20-ietf-poly1305");
                assert_eq!(c.password, "k1dBOmOB4oqi7Ump37a1bQ");
            }
            other => panic!("expected Ss config, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_vless_reality() {
        // Parse a working VLESS Reality URL, format back, re-parse — all
        // Reality fields must survive.
        let p1 = parse_share_url(WORKING_URL_1, &permissive_settings()).unwrap();
        let rebuilt = format_share_url(&p1.parsed, &p1.parsed.endpoints[0]).unwrap();
        assert!(rebuilt.starts_with("vless://"));
        let p2 = parse_share_url(&rebuilt, &permissive_settings()).unwrap();
        assert_eq!(p1.parsed.uid(), p2.parsed.uid());
        assert_eq!(p1.parsed.endpoints, p2.parsed.endpoints);
        let s1 = p1
            .parsed
            .protocol
            .config
            .security()
            .expect("vless has security");
        let s2 = p2
            .parsed
            .protocol
            .config
            .security()
            .expect("vless has security");
        assert_eq!(s1.sni(), s2.sni());
        assert_eq!(s1.fp(), s2.fp());
        assert_eq!(s1.pbk(), s2.pbk());
        assert_eq!(s1.sid(), s2.sid());
    }

    #[test]
    fn roundtrip_shadowsocks_real() {
        let p1 = parse_share_url(WORKING_URL_3, &permissive_settings()).unwrap();
        let rebuilt = format_share_url(&p1.parsed, &p1.parsed.endpoints[0]).unwrap();
        assert!(rebuilt.starts_with("ss://"));
        let p2 = parse_share_url(&rebuilt, &permissive_settings()).unwrap();
        assert_eq!(p1.parsed.uid(), p2.parsed.uid());
        assert_eq!(p1.parsed.endpoints, p2.parsed.endpoints);
        match (&p1.parsed.protocol.config, &p2.parsed.protocol.config) {
            (ProtocolConfig::Ss(a), ProtocolConfig::Ss(b)) => {
                assert_eq!(a.method, b.method);
                assert_eq!(a.password, b.password);
            }
            other => panic!("expected Ss configs, got {other:?}"),
        }
    }
}
