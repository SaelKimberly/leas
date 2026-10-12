use std::borrow::Cow;

use base64::Engine;
use bstr::ByteSlice;
use rustls::pki_types::ServerName;

use super::{HostSpec, PortSpec, SchemeX, TinyText};

/// Raw Url (no parsing, just splitting to parts)
///
/// [schema]://userinfo[@channel]@[host:port]/[path]?[query]#[fragment]
///
/// Only 'userinfo' parameter is required (opposite to [`url::Url`] behaviour, where hostport is required)
#[cfg_attr(test, derive(Debug))]
pub struct RawUrlX<'a> {
    /// `[schema]`
    pub schema: SchemeX,
    /// `userinfo`
    pub userinfo: &'a str,
    /// `[host:port]`
    pub hostport: Option<&'a str>,
    /// `[/path]`
    pub path: Option<&'a str>,
    /// `[query]`
    pub query: Option<&'a str>,
    /// `[fragment]`
    pub fragment: Option<&'a str>,
    /// Original URL string (zero-copy borrow)
    pub raw: &'a str,
}

impl<'a> RawUrlX<'a> {
    /// Extract userinfo if only userinfo is present
    ///
    /// ```rust
    /// # use std::str::FromStr;
    /// # use std::borrow::Cow;
    /// # use leas_proto::urlx::RawUrlX;
    /// let url = RawUrlX::from("vmess://userinfo");
    /// let Ok(Some(Cow::Borrowed(b"userinfo"))) = url.userinfo_only(false, false) else {
    ///     panic!("Url contains only userinfo");
    /// };
    /// let url = RawUrlX::from("vmess://dXNlcmluZm8=");
    /// let Ok(Some(Cow::Owned(userinfo))) = url.userinfo_only(true, false) else {
    ///     panic!("Url contains only userinfo");
    /// };
    /// assert_eq!(userinfo, b"userinfo");
    /// let url = RawUrlX::from("vmess://dXNlcmluZm8=@host:1234");
    /// let Ok(Cow::Owned(userinfo)) = url.userinfo(true) else {
    ///     panic!("Url contains userinfo and hostport");
    /// };
    /// assert_eq!(userinfo, b"userinfo");
    /// let Ok(None) = url.userinfo_only(true, false) else {
    ///     panic!("Url contains userinfo and hostport");
    /// };
    /// assert_eq!(userinfo, b"userinfo");
    /// ```
    ///
    /// # Errors
    ///
    /// If `expect_b64` is `true`, but the userinfo is not base64 encoded, this function will return an error.
    pub fn userinfo_only(
        &self,
        expect_b64: bool,
        allow_frag: bool,
    ) -> Result<Option<Cow<'a, [u8]>>, base64::DecodeError> {
        if let Self {
            schema: _,
            userinfo: _,
            hostport: None,
            path: None,
            query: None,
            fragment,
            raw: _,
        } = self
            && (fragment.is_none() || allow_frag)
        {
            self.userinfo(expect_b64).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Extract userinfo
    ///
    /// ```rust
    /// # use std::str::FromStr;
    /// # use std::borrow::Cow;
    /// # use leas_proto::urlx::RawUrlX;
    /// let url = RawUrlX::from("vmess://userinfo@host:1234");
    /// let Ok(Cow::Borrowed(b"userinfo")) = url.userinfo(false) else {
    ///     panic!("Url contains userinfo and hostport");
    /// };
    /// let url = RawUrlX::from("vmess://dXNlcmluZm8=@host:1234");
    /// let Ok(Cow::Owned(userinfo)) = url.userinfo(true) else {
    ///     panic!("Url contains userinfo and hostport");
    /// };
    /// assert_eq!(userinfo, b"userinfo");
    /// ```
    ///
    /// # Errors
    ///
    /// If `expect_b64` is true, but the userinfo is not base64 encoded, this function will return an error.
    pub fn userinfo(&self, expect_b64: bool) -> Result<Cow<'a, [u8]>, base64::DecodeError> {
        Self::userinfo_smart(self, |_| expect_b64)
    }

    /// # Errors
    ///
    /// If `b64_if` returns true, but the userinfo is not base64 encoded, this function will return an error.
    pub fn userinfo_smart(
        &self,
        b64_if: impl Fn(&[u8]) -> bool,
    ) -> Result<Cow<'a, [u8]>, base64::DecodeError> {
        let userinfo = urlencoding::decode_binary(self.userinfo.as_bytes());
        if b64_if(userinfo.as_ref()) {
            let userinfo = userinfo.as_ref().trim_end_with(|c| c == '=');

            let r = 'block: {
                let e = match base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(userinfo) {
                    Ok(r) => break 'block r,
                    Err(e) => e,
                };
                if let Ok(r) = base64::prelude::BASE64_STANDARD_NO_PAD.decode(userinfo) {
                    break 'block r;
                }
                // return error from url-safe version
                return Err(e);
            };
            Ok(Cow::Owned(r))
        } else {
            Ok(userinfo)
        }
    }

    /// Extract hostport (if present)
    ///
    /// ```rust
    /// # use std::str::FromStr;
    /// # use leas_proto::urlx::RawUrlX;
    /// let url = RawUrlX::from("vmess://userinfo@host.com:1234");
    /// let (host, port) = url.hostport().unwrap().unwrap();
    /// assert_eq!(host.to_str(), "host.com");
    /// assert_eq!(port.first(), Some(1234));
    /// ```
    ///
    /// # Errors
    ///
    /// If hostport is present but invalid, return error.
    pub fn hostport(&self) -> Result<Option<(HostSpec, PortSpec)>, Cow<'static, str>> {
        let Some(hostport) = self.hostport else {
            return Ok(None);
        };
        let (tail, (host, port)) = crate::utils::host_port_spec(hostport.as_bytes())
            .map_err(|e| format!("Invalid hostport: {hostport}: {e}"))?;
        if tail.is_empty() {
            Ok(Some((host.to_owned(), port)))
        } else {
            Err(format!(
                "Invalid hostport: {hostport} (non-empty tail found: {})",
                unsafe { str::from_utf8_unchecked(tail) }
            )
            .into())
        }
    }

    /// # Errors
    ///
    /// If path is present but invalid, return error.
    pub fn path(&self) -> Result<Option<TinyText>, std::string::FromUtf8Error> {
        Ok(self
            .path
            .map(urlencoding::decode)
            .transpose()?
            .map(Into::into))
    }

    /// # Errors
    ///
    /// If query is present but invalid, return error.
    pub fn query(&self) -> Result<Vec<(TinyText, Option<TinyText>)>, std::string::FromUtf8Error> {
        let Some(query) = self.query else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for pair in query.split('&') {
            let (raw_key, raw_value) = match pair.split_once('=') {
                Some((key, value)) => (key, Some(value)),
                None => (pair, None),
            };
            let key = urlencoding::decode(raw_key)?;
            let value = raw_value
                .filter(|value| !value.is_empty())
                .map(urlencoding::decode)
                .transpose()?;
            out.push((
                key.as_ref().into(),
                value.as_ref().map(|value| value.as_ref().into()),
            ));
        }
        Ok(out)
    }
    /// Returns the fragment part of the URL, if any.
    ///
    /// # Errors
    ///
    /// If the fragment is not valid UTF-8, an error is returned.
    pub fn fragment(&self) -> Result<Option<TinyText>, core::str::Utf8Error> {
        let Some(fragment) = self.fragment else {
            return Ok(None);
        };
        let decoded = urlencoding::decode_binary(fragment.as_bytes());
        let text = String::from_utf8_lossy(decoded.as_ref());
        Ok(Some(text.as_ref().into()))
    }

    fn from_str_impl(s: &'a str) -> Option<Self> {
        // we just parse this from sides to the center
        let mut unparsed = s.trim_end();

        // ? 1. Extract schema
        // * ==============================
        // * [scheme]:// <-split-> [userinfo]@[channel]@[host:port]/[path]?[query]#[fragment]
        // * ==============================
        let schema = {
            let (schema, rest) = unparsed.split_once("://")?;
            let Ok(schema) = <SchemeX as std::str::FromStr>::from_str(schema);

            unparsed = rest;
            schema
        };

        // ? 2. Extract userinfo
        // * ==============================
        // * [userinfo]@ <-split-> [channel]@[host:port]/[path]?[query]#[fragment]
        // * ==============================
        // ! When no '@' sign is present, all url body just is userinfo
        // ! Only split at '@' if it appears before any '#' or '?' — otherwise
        // ! the '@' is part of a query value or fragment, not a userinfo separator.
        let split_at = unparsed.find('@').filter(|pos| {
            let earliest = unparsed.find('#').or_else(|| unparsed.find('?'));
            earliest.map_or_else(
                || true,
                |early| {
                    if *pos < early {
                        return true;
                    }
                    // Trojan URLs may have '#' in the 16-byte ASCII password
                    // (e.g. "8r<[9'l6hAO#8ZQi@host:port").
                    // Check if after @ is a valid host:port.
                    if schema == SchemeX::Trojan && *pos == 16 && unparsed[..16].is_ascii() {
                        let after_at = &unparsed[*pos + 1..];
                        let host_end = after_at
                            .find('/')
                            .or_else(|| after_at.find('?'))
                            .or_else(|| after_at.find('#'))
                            .unwrap_or(after_at.len());
                        let candidate = &after_at[..host_end];
                        let span = candidate.as_bytes();
                        return crate::utils::host_port::host_port_spec(span).is_ok();
                    }
                    false
                },
            )
        });
        let (userinfo, rest) = match split_at {
            Some(_) => match unparsed.split_once('@') {
                Some((userinfo, "")) => (userinfo, None),
                Some((userinfo, rest)) => (userinfo, Some(rest)),
                None => (unparsed, None),
            },
            _ => (unparsed, None),
        };

        let Some(rest) = rest else {
            // ? Extract possible fragment
            // * ==============================
            // * [userinfo] <-split-> #[fragment]
            // * ==============================
            let (userinfo, fragment) = if let Some((userinfo, fragment)) = userinfo.split_once('#')
            {
                (userinfo, Some(fragment))
            } else {
                (userinfo, None)
            };

            // ? Userinfo may be a URL without credentials
            // * ==============================
            // * [host[:port]]/[path]?[query]
            // * ==============================
            unparsed = userinfo;

            // ?  Extract query
            // * ==============================
            // * [host[:port]]/[path] <-split-> ?[query]
            // * ==============================
            let query = if let Some((rest, query)) = unparsed.split_once('?') {
                unparsed = rest;

                (!query.is_empty()).then_some(query)
            } else {
                None
            };

            // ? Extract path
            // * ==============================
            // * [host[:port]] <-split-> [/path]
            // * ==============================
            let (rest, mut path) = unparsed.find('/').map_or_else(
                || {
                    let rest = unparsed;
                    (rest, None)
                },
                |pos| {
                    let (rest, path) = unparsed.split_at(pos);
                    (rest, Some(path))
                },
            );

            let hostport = if let Ok(host) = {
                let span = rest.as_bytes();
                crate::utils::host_port::host_port_spec(span)
                    .map(|(_, (h, _))| h)
                    .or_else(|_| crate::utils::host_port::host(span).map(|(_, h)| h))
            } && {
                // DNS names without a dot are not allowed
                if let ServerName::DnsName(ref n) = host {
                    n.as_ref().contains('.')
                } else {
                    true
                }
            } {
                unparsed = rest;
                Some(unparsed)
            } else {
                _ = path.take();
                None
            };

            return Some(Self {
                schema,
                userinfo: hostport.unwrap_or(unparsed),
                hostport,
                path,
                query,
                fragment,
                raw: s,
            });
        };
        unparsed = rest;

        // ? 3. Extract fragment
        // * ==============================
        // * [channel]@[host:port]/[path]?[query] <-split-> #[fragment]
        // * ==============================
        let fragment = if let Some((rest, fragment)) = unparsed.split_once('#') {
            unparsed = rest;
            Some(fragment)
        } else {
            None
        };

        // ? 4. Extract query
        // * ==============================
        // * [channel]@[host:port]/[path] <-split-> ?[query]
        // * ==============================
        let query = if let Some((rest, query)) = unparsed.split_once('?') {
            unparsed = rest;

            (!query.is_empty()).then_some(query)
        } else {
            None
        };

        // ? 5. Extract path
        // * ==============================
        // * [channel]@[host:port] <-split-> [/path]
        // * ==============================
        let path = unparsed.find('/').map(|pos| {
            let (rest, path) = unparsed.split_at(pos);
            unparsed = rest;
            path
        });

        // ? 6. Remove channel
        // * ==============================
        // * [channel]@ <-split-> [host:port]
        let host_port = if let Some((_, host_port)) = unparsed.split_once('@') {
            host_port
        } else {
            unparsed
        };
        let host_port = (!host_port.is_empty()).then_some(host_port);
        Some(RawUrlX {
            schema,
            userinfo,
            hostport: host_port,
            path,
            query,
            fragment,
            raw: s,
        })
    }
}

impl<'a> From<&'a str> for RawUrlX<'a> {
    fn from(s: &'a str) -> Self {
        Self::from_str_impl(s).expect("from_str_impl should always succeed for valid URL")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]

    fn test_vmess_standard_b64() {
        let url = "vmess://abc/def";
        let raw = RawUrlX::from(url);
        let RawUrlX {
            schema: SchemeX::Vmess,
            userinfo: "abc/def",
            hostport: None,
            path: None,
            query: None,
            fragment: None,
            raw: _,
        } = raw
        else {
            panic!("Should be vmess with only userinfo");
        };
    }
    #[test]
    fn test_vmess_standard_b64_trailing_slash() {
        let url = "vmess://abc/";
        let raw = RawUrlX::from(url);
        let RawUrlX {
            schema: SchemeX::Vmess,
            userinfo: "abc/",
            hostport: None,
            path: None,
            query: None,
            fragment: None,
            raw: _,
        } = raw
        else {
            panic!("Should be vmess with only userinfo");
        };
    }
}
