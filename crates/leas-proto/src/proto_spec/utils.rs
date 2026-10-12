use std::borrow::Cow;

use base64::Engine;
use bstr::ByteSlice;

use crate::urlx::{HostSpec, PortSpec, RawUrlX, TinyText};

use super::ParseError;

/// Parse host:port from a string, returning (`HostSpec`, `PortSpec`)
///
/// Structural validation only. Host *policy* (private/loopback/link-local/
/// localhost rejection, gated by `allow_private_ips`) is the config layer's
/// job (`leas-config::import_export::validate_host`) — T11 fix moved the
/// single host-policy authority there, so parsers accept any syntactically
/// valid host.
///
/// # Errors
///
/// Returns an error if the string is not a valid host:port specification.
pub fn parse_hostport(s: &str) -> Result<(HostSpec, PortSpec), ParseError> {
    // Strip decorative prefixes like @@ or $*@
    let s = s.trim_start_matches('@');
    let s = s.trim_start_matches("$*@");
    let (tail, (host, port)) = crate::utils::host_port_spec(s.as_bytes())
        .map_err(|_| ParseError::InvalidHostPort(format!("Invalid hostport: {s}").into()))?;
    let host = host.to_owned();
    if !tail.is_empty() {
        let tail_str = unsafe { std::str::from_utf8_unchecked(tail) };
        // Lenient: if tail contains query-like chars (= or &), strip it
        if !tail_str.contains('=') && !tail_str.contains('&') {
            return Err(ParseError::InvalidHostPort(
                format!("Invalid hostport: {s} (non-empty tail: {tail_str})").into(),
            ));
        }
    }
    Ok((host, port))
}

/// Parse host from a string (no port)
///
/// # Errors
///
pub fn parse_host(s: &str) -> Result<HostSpec, ParseError> {
    let (tail, host) = crate::utils::host_port::host(s.as_bytes())
        .map_err(|_| ParseError::InvalidHost(format!("Invalid host: {s}").into()))?;
    let host = host.to_owned();
    if !tail.is_empty() {
        return Err(ParseError::InvalidHost(
            format!("Invalid host: {s} (non-empty tail: {})", unsafe {
                std::str::from_utf8_unchecked(tail)
            })
            .into(),
        ));
    }
    Ok(host)
}

/// Parse port from string
///
/// # Errors
///
/// If the string is not a valid port.
pub fn parse_port(s: &str) -> Result<PortSpec, Cow<'static, str>> {
    let (tail, port) = crate::utils::host_port::port_specs(s.as_bytes())
        .map_err(|_| format!("Invalid port: {s}"))?;
    if !tail.is_empty() {
        return Err(format!("Invalid port: {s} (non-empty tail: {})", unsafe {
            std::str::from_utf8_unchecked(tail)
        })
        .into());
    }
    Ok(port)
}

/// Base64 decode a string (tries URL-safe then standard)
///
/// Silently strips trailing non-base64 characters (Telegram annotation text, emoji, etc.)
/// and stray backtick characters that sometimes appear mid-base64 in subscription data.
/// Returns the decoded bytes or an error.
///
/// # Errors
/// Returns a `base64::DecodeError` if the input is not valid base64.
pub fn decode_base64(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // Strip stray backtick characters inline, no alloc if none found
    let data: Vec<u8> = data.bytes().filter(|&b| b != b'`').collect();
    let end = data
        .iter()
        .position(|&b| !b.is_ascii_alphanumeric() && !matches!(b, b'+' | b'/' | b'-' | b'_' | b'='))
        .unwrap_or(data.len());
    let mut data = &data[..end];
    // After the last padding marker (`==` or `=`), strip ASCII annotation text too.
    // E.g. `...base64==Irancell&Mci...` — the `Irancell` is valid base64 chars but is annotation.
    if let Some(pos) = data.rfind(b"==") {
        data = &data[..pos + 2];
    } else if let Some(pos) = data.rfind(b"=") {
        data = &data[..=pos];
    }
    let decoded = urlencoding::decode_binary(data);
    let data = decoded.trim_end_with(|c| c == '=' || c.is_whitespace());
    'block: {
        let e = match base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(data) {
            Ok(r) => break 'block Ok(r),
            Err(e) => e,
        };
        if let Ok(r) = base64::prelude::BASE64_STANDARD_NO_PAD.decode(data) {
            break 'block Ok(r);
        }
        Err(e)
    }
}

/// Parse query string into key-value pairs (linear-scan friendly Vec, no `HashMap` overhead).
#[must_use]
pub fn parse_query(query: Option<&str>) -> Vec<(String, String)> {
    let mut result = Vec::with_capacity(8);
    let query_str = query.unwrap_or("");
    if query_str.is_empty() {
        return result;
    }
    for pair in query_str.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let decoded = urlencoding::decode(v).unwrap_or(Cow::Borrowed(v));
            result.push((k.to_string(), decoded.into_owned()));
        }
    }
    result
}

/// Look up a value by key in a query parameter list. Linear scan (≤5 entries).
#[must_use]
pub fn query_get<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Look up the first matching value from a list of candidate keys.
#[must_use]
pub fn query_get_multi<'a>(params: &'a [(String, String)], keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| query_get(params, key))
}

/// Decode fragment (remarks) from raw URL
///
/// # Errors
/// - If the fragment is not valid UTF-8
pub fn decode_fragment(
    raw: &RawUrlX<'_>,
) -> Result<Option<TinyText>, crate::proto_spec::ParseError> {
    raw.fragment().map_err(|e| {
        crate::proto_spec::ParseError::InvalidConf("remarks".into(), e.to_string().into())
    })
}

// ========================================
// Coercion helpers for TryFrom<RawUrlX>
// ========================================

/// Try to coerce a `serde_json::Value` to u16 (number, string, etc.)
#[must_use]
pub fn coerce_u16(val: &serde_json::Value) -> Option<u16> {
    val.as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .or_else(|| val.as_str().and_then(|s| s.parse::<u16>().ok()))
        .or_else(|| {
            val.as_f64().and_then(|f| {
                (f.is_finite() && (f >= 0.0 && f <= f64::from(u16::MAX)))
                    .then(|| unsafe { f.to_int_unchecked::<u16>() })
            })
        })
}

/// Try to coerce a `serde_json::Value` to bool (bool, string "true"/"1"/"yes", etc.)
#[must_use]
pub fn coerce_bool(val: &serde_json::Value) -> Option<bool> {
    val.as_bool().or_else(|| {
        val.as_str()
            .and_then(|s| match s.trim().to_lowercase().as_str() {
                "true" | "1" | "yes" | "on" | "y" => Some(true),
                "false" | "0" | "no" | "off" | "n" => Some(false),
                _ => None,
            })
    })
}

/// Try to coerce a `serde_json::Value` to String
#[must_use]
pub fn coerce_string(val: &serde_json::Value) -> Option<String> {
    val.as_str()
        .map(std::string::ToString::to_string)
        .or_else(|| {
            if val.is_number() {
                Some(val.to_string())
            } else {
                None
            }
        })
}

/// Try to coerce a `serde_json::Value` to u64
#[must_use]
pub fn coerce_u64(val: &serde_json::Value) -> Option<u64> {
    val.as_u64()
        .or_else(|| val.as_str().and_then(|s| s.parse::<u64>().ok()))
        .or_else(|| {
            val.as_f64().and_then(|f| {
                if f >= 0.0 {
                    Some(unsafe { f.to_int_unchecked() })
                } else {
                    None
                }
            })
        })
}
