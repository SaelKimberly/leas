//! Subscription data parsing: chunked base64 decoder + URL splitting + batch parse.

use std::mem::MaybeUninit;

use crate::import_export::{
    ImportError, ParsedProfile, ValidationSettings, ValidationSummary, parse_share_url,
};
use aho_corasick::AhoCorasick;
use base64_simd::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use leas_proto::proto_spec::{ProtoSpec, SecurityConfig};

/// Maximum input chunk size for `StreamingDecoder::feed()`.
pub const INPUT_CHUNK_SIZE: usize = 65536;

/// Maximum bytes to carry over between chunks (incomplete lines).
const CARRY_OVER_SIZE: usize = 262_144;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodingState {
    Unknown,
    StdB64,
    UrlSafeB64,
    Raw,
}

/// Streaming base64 decoder with encoding auto-detection.
///
/// Handles chunked subscription data by aligning to 4-byte base64 boundaries,
/// auto-detecting encoding (URL-safe / standard / raw), and splitting on `\n`.
pub struct StreamingDecoder {
    state: EncodingState,
    pending_input: [MaybeUninit<u8>; 4],
    pending_input_len: usize,
    carry_over: Box<[MaybeUninit<u8>]>,
    carry_over_len: usize,
    /// Reused per-feed staging buffer (`clear` + `resize`, no fresh alloc):
    /// pending bytes + one chunk, 4-byte-aligned before decode.
    work: Vec<u8>,
}
impl StreamingDecoder {
    /// Create a new decoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: EncodingState::Unknown,
            pending_input: [MaybeUninit::uninit(); 4],
            pending_input_len: 0,
            carry_over: vec![MaybeUninit::uninit(); CARRY_OVER_SIZE].into_boxed_slice(),
            carry_over_len: 0,
            work: Vec::new(),
        }
    }

    /// Reset the decoder to initial state.
    pub fn reset(&mut self) {
        self.state = EncodingState::Unknown;
        self.pending_input = [MaybeUninit::uninit(); 4];
        self.pending_input_len = 0;
        self.carry_over.fill(MaybeUninit::uninit());
        self.carry_over_len = 0;
    }

    /// Feed one chunk of raw input data. Returns any complete URLs extracted.
    ///
    /// Internally aligns input to 4-byte base64 boundaries, detects encoding
    /// and decodes, splits on `\n`, and passes complete text regions through
    /// `subscription_url_split`.
    ///
    /// # Errors
    ///
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<String>, String> {
        if chunk.is_empty() && self.pending_input_len == 0 {
            return Ok(vec![]);
        }

        if chunk.len() > INPUT_CHUNK_SIZE {
            return Err(format!(
                "Input chunk too large: got {} bytes, max {}",
                chunk.len(),
                INPUT_CHUNK_SIZE,
            ));
        }

        // Reuse the staging allocation across feeds (`clear` + `resize` keeps
        // the buffer; the borrow below ends before `self` is touched again).
        let mut work = std::mem::take(&mut self.work);
        work.clear();
        work.resize(INPUT_CHUNK_SIZE + 4, 0);
        let total_len = self.pending_input_len + chunk.len();
        // Prepend pending bytes
        for (w, p) in work[..self.pending_input_len]
            .iter_mut()
            .zip(self.pending_input.iter())
        {
            *w = unsafe { p.assume_init() };
        }
        // Copy chunk bytes into remaining work area
        work[self.pending_input_len..total_len].copy_from_slice(chunk);
        self.pending_input_len = 0;

        // Align to 4-byte base64 boundary
        let aligned_len = (total_len / 4) * 4;
        let remainder = total_len - aligned_len;

        // Save trailing bytes as pending for next call
        for i in 0..remainder {
            self.pending_input[i] = MaybeUninit::new(work[aligned_len + i]);
        }
        self.pending_input_len = remainder;

        let input = &work[..aligned_len];
        let decoded = self.process_aligned(input)?;
        let urls = self.process_decoded(&decoded);
        drop(decoded);
        // Hand a possibly-grown buffer back so the next feed reuses it.
        self.work = work;
        Ok(urls)
    }

    /// Flush any remaining buffered data. Call once after the last `feed()`.
    /// Returns any final URLs from the last partial line.
    ///
    /// # Errors
    ///
    /// Returns an error if base64 decoding fails.
    pub fn finalize(&mut self) -> Result<Vec<String>, String> {
        let mut result = Vec::new();

        // Process leftover pending_input bytes (may be < 4)
        if self.pending_input_len > 0 {
            let mut buf = [0u8; 4];
            for (b, p) in buf[..self.pending_input_len]
                .iter_mut()
                .zip(self.pending_input.iter())
            {
                *b = unsafe { p.assume_init() };
            }
            let decoded = self.process_aligned(&buf[..self.pending_input_len])?;
            self.pending_input_len = 0;
            result.extend(self.process_decoded(&decoded));
        }

        // Flush remaining carry_over as complete text
        if self.carry_over_len > 0 {
            let carry = self.carry_over_slice();
            result.extend(process_text_std(carry));
            self.carry_over_len = 0;
        }

        Ok(result)
    }

    // ── internal helpers ──

    /// Detect encoding and decode one 4-byte-aligned portion. Raw text is
    /// borrowed from `data` (`Cow::Borrowed`) — no 64 KiB copy per chunk.
    fn process_aligned<'a>(
        &mut self,
        data: &'a [u8],
    ) -> Result<std::borrow::Cow<'a, [u8]>, String> {
        if data.is_empty() {
            return Ok(std::borrow::Cow::Borrowed(&[]));
        }

        // Trim trailing whitespace and '=' padding for base64 decode attempts.
        let trimmed = if matches!(self.state, EncodingState::Raw) {
            data
        } else if let Some(pos) = data
            .iter()
            .rposition(|&b| !(b.is_ascii_whitespace() || b == b'='))
        {
            &data[..=pos]
        } else {
            return Ok(std::borrow::Cow::Borrowed(&[]));
        };
        match self.state {
            EncodingState::Unknown => {
                let (encoding, decoded) = if memchr::memchr2(b'+', b'\\', trimmed).is_some() {
                    // Has standard-base64-specific characters
                    STANDARD_NO_PAD.decode_to_vec(trimmed).map_or_else(
                        |_| (EncodingState::Raw, std::borrow::Cow::Borrowed(data)),
                        |d| (EncodingState::StdB64, std::borrow::Cow::Owned(d)),
                    )
                } else if memchr::memchr2(b'-', b'_', trimmed).is_some() {
                    // Has URL-safe-base64-specific characters
                    URL_SAFE_NO_PAD.decode_to_vec(trimmed).map_or_else(
                        |_| (EncodingState::Raw, std::borrow::Cow::Borrowed(data)),
                        |d| (EncodingState::UrlSafeB64, std::borrow::Cow::Owned(d)),
                    )
                } else {
                    // Alphanumeric-only — try standard (most common)
                    STANDARD_NO_PAD.decode_to_vec(trimmed).map_or_else(
                        |_| (EncodingState::Raw, std::borrow::Cow::Borrowed(data)),
                        |d| (EncodingState::StdB64, std::borrow::Cow::Owned(d)),
                    )
                };
                self.state = encoding;
                Ok(decoded)
            }
            EncodingState::StdB64 => STANDARD_NO_PAD
                .decode_to_vec(trimmed)
                .map(std::borrow::Cow::Owned)
                .map_err(|e| format!("base64 decode error: {e}")),
            EncodingState::UrlSafeB64 => URL_SAFE_NO_PAD
                .decode_to_vec(trimmed)
                .map(std::borrow::Cow::Owned)
                .map_err(|e| format!("base64 decode error: {e}")),
            EncodingState::Raw => Ok(std::borrow::Cow::Borrowed(data)),
        }
    }

    /// Process decoded bytes: lossy UTF-8, prepend `carry_over`, split on last
    /// `\n`, extract URLs from complete portion, save remainder as `carry_over`.
    fn process_decoded(&mut self, decoded: &[u8]) -> Vec<String> {
        if decoded.is_empty() && self.carry_over_len == 0 {
            return Vec::new();
        }

        // Fast SIMD UTF-8 validation; fall back to lossy on invalid input
        let Ok(decoded_str) = simdutf8::basic::from_utf8(decoded) else {
            let s = String::from_utf8_lossy(decoded).into_owned();
            return self.process_text_owned(&s);
        };

        if self.carry_over_len == 0 {
            self.process_str(decoded_str)
        } else {
            let carry_bytes = self.carry_over_slice();
            let mut combined = String::with_capacity(self.carry_over_len + decoded_str.len());
            // SAFETY: carry_over bytes are valid UTF-8 (came from previous decoded chunks)
            unsafe {
                combined.as_mut_vec().extend_from_slice(carry_bytes);
            }
            combined.push_str(decoded_str);
            self.carry_over_len = 0;

            self.process_text_owned(&combined)
        }
    }
    /// Helper: split on last \n, extract URLs, save `carry_over`.
    /// Takes ownership of the string for splitting.
    fn process_text_owned(&mut self, full_text: &str) -> Vec<String> {
        if full_text.is_empty() {
            return Vec::new();
        }

        if let Some(last_nl) = memchr::memrchr(b'\n', full_text.as_bytes()) {
            let complete = &full_text[..last_nl];
            let remaining = &full_text[last_nl + 1..];
            let urls = process_text_std(complete.as_bytes());

            self.set_carry_over(remaining);

            urls
        } else {
            self.set_carry_over(full_text);
            Vec::new()
        }
    }

    /// Process a &str (no `carry_over` involved): split on last \n, extract URLs,
    /// save `carry_over`.
    fn process_str(&mut self, text: &str) -> Vec<String> {
        if text.is_empty() {
            return Vec::new();
        }
        if let Some(last_nl) = memchr::memrchr(b'\n', text.as_bytes()) {
            let complete = &text[..last_nl];
            let remaining = &text[last_nl + 1..];
            let urls = process_text_std(complete.as_bytes());
            self.set_carry_over(remaining);
            urls
        } else {
            self.set_carry_over(text);
            Vec::new()
        }
    }

    fn set_carry_over(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let len = bytes.len();
        if len > CARRY_OVER_SIZE {
            for (i, &b) in bytes[..CARRY_OVER_SIZE].iter().enumerate() {
                self.carry_over[i] = MaybeUninit::new(b);
            }
            self.carry_over_len = CARRY_OVER_SIZE;
            return;
        }
        for (i, &b) in bytes.iter().enumerate() {
            self.carry_over[i] = MaybeUninit::new(b);
        }
        self.carry_over_len = len;
    }

    fn carry_over_slice(&self) -> &[u8] {
        if self.carry_over_len == 0 {
            return &[];
        }
        // SAFETY: first carry_over_len bytes are initialized
        unsafe {
            std::slice::from_raw_parts(self.carry_over.as_ptr().cast::<u8>(), self.carry_over_len)
        }
    }
}

impl Default for StreamingDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Standard `process_text` that splits text by newlines and extracts URLs via
/// `subscription_url_split`. Lines are scanned with `memchr` ranges over the
/// raw bytes; each line is `from_utf8_lossy`-borrowed when valid (no String
/// copy) and only copied on genuinely invalid UTF-8 lines.
fn process_text_std(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut start = 0;
    while start <= data.len() {
        let end = memchr::memchr(b'\n', &data[start..]).map_or(data.len(), |rel| start + rel);
        let line = String::from_utf8_lossy(&data[start..end]);
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            result.extend(subscription_url_split(trimmed));
        }
        if end == data.len() {
            break;
        }
        start = end + 1;
    }
    result
}

/// File one parsed-URL outcome into `profiles`/`summary` (the shared
/// per-URL parse the streaming and finalized paths both funnel through, so
/// URLs are parsed then dropped — never held wholesale).
fn file_profile(
    profiles: &mut Vec<ParsedProfile>,
    summary: &mut ValidationSummary,
    url: &str,
    settings: &ValidationSettings,
) {
    match parse_share_url(url, settings) {
        Ok(profile) => profiles.push(profile),
        Err(ImportError::Validation(msg)) => {
            let lower = msg.to_lowercase();
            if lower.starts_with("missing field") {
                summary.missing_field_count += 1;
            } else if lower.starts_with("private ip")
                || lower.starts_with("loopback")
                || lower.starts_with("link-local")
                || lower.starts_with("unique-local")
                || lower.starts_with("localhost")
                || lower.starts_with("unspecified")
                || lower.starts_with("host has no registrable domain")
            {
                summary.host_validation_count += 1;
                summary.record_error(msg.as_str());
            } else {
                summary.other_count += 1;
                summary.record_error(msg.as_str());
            }
        }
        // NOT `other.to_string()`: `ImportError::Parse`'s Display embeds
        // `ParseError`, and several variants carry the raw URL or its userinfo
        // (`naive.rs` "missing host:port in {raw}", `ss.rs` "{userinfo}",
        // same shape in the hysteria parsers). That string would reach
        // `log_trace` and be PERSISTED to the LMDB store, writing a base64
        // method:password into the log. Classify by KIND instead, and say so.
        Err(other) => {
            summary.other_count += 1;
            summary.record_error(match &other {
                // The variants whose payload can carry the URL or its userinfo.
                ImportError::UnsupportedScheme => "unsupported URL scheme".to_owned(),
                ImportError::Parse(_) => {
                    "parse error (details withheld: the message can carry the URL)".to_owned()
                }
                ImportError::Json(_) | ImportError::Url(_) | ImportError::MissingField(_) => {
                    other.to_string()
                }
                ImportError::Validation(msg) => msg.clone(),
            });
        }
    }
}
/// Split concatenated subscription data into individual URLs using
/// Aho-Corasick to find all scheme boundaries.
///
/// Handles the case where multiple URLs are concatenated without newlines
/// (e.g., `vmess://...vless://...trojan://...`).
#[must_use]
pub fn subscription_url_split(text: &str) -> Vec<String> {
    static SCHEMA_AC: std::sync::LazyLock<AhoCorasick> = std::sync::LazyLock::new(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build([
                "vmess://",
                "vless://",
                "trojan://",
                "ss://",
                "ssr://",
                "hysteria2://",
                "hysteria://",
                "hy2://",
                "hy://",
                "tuic://",
                "socks://",
                "socks5://",
                "http://",
                "naive+https://",
                "naive+quic://",
                "anytls://",
                "shadowtls://",
                "wireguard://",
            ])
            .unwrap()
    });

    let mut last_start: Option<usize> = None;
    let mut chunks = Vec::new();

    for m in SCHEMA_AC.find_iter(text) {
        if let Some(start) = last_start.take() {
            let end = m.start();
            chunks.push(text[start..end].to_string());
        }
        last_start = Some(m.start());
    }

    if let Some(start) = last_start.take() {
        chunks.push(text[start..].to_string());
    }

    chunks
}

/// Decode subscription data into individual share URLs (no parsing).
///
/// Runs the same [`StreamingDecoder`] pass as [`parse_subscription_data`]
/// but stops at the URL level: the caller parses in bounded batches so a
/// 100k-URL feed never materializes 100k `ParsedProfile`s at once.
///
/// # Errors
///
/// Returns an error if the data cannot be decoded.
pub fn subscription_url_chunks(data: &[u8]) -> Result<Vec<String>, String> {
    let mut decoder = StreamingDecoder::new();
    let mut urls: Vec<String> = Vec::new();
    for chunk in data.chunks(INPUT_CHUNK_SIZE) {
        urls.extend(decoder.feed(chunk)?);
    }
    urls.extend(decoder.finalize()?);
    Ok(urls)
}

/// Parse one batch of share URLs into profiles with a complete per-batch summary.
///
/// The summary carries `total_errors` (candidates that could not be imported)
/// plus `security_warning_count` (imported profiles that disable certificate
/// verification) as separate counters. This is the funnel shared by
/// [`parse_subscription_data`] and the TUI's chunked import.
///
/// # Errors
///
/// None — parse failures are counted in the summary, never propagated.
#[must_use]
pub fn parse_url_batch(
    urls: &[String],
    settings: &ValidationSettings,
) -> (Vec<ParsedProfile>, ValidationSummary) {
    let mut profiles: Vec<ParsedProfile> = Vec::new();
    let mut summary = ValidationSummary::default();
    for url in urls {
        file_profile(&mut profiles, &mut summary, url, settings);
    }
    // Scan parsed profiles for allow_insecure / insecure settings (typed
    // security accessor — the full flow rework lands in T12).
    summary.security_warning_count = profiles
        .iter()
        .filter(|p| {
            p.parsed
                .protocol
                .config
                .security()
                .and_then(SecurityConfig::insecure)
                == Some(true)
        })
        .count();

    summary.total_errors =
        summary.missing_field_count + summary.host_validation_count + summary.other_count;
    (profiles, summary)
}

/// Parse base64-encoded subscription data into a list of Profiles.
///
/// Returns `(profiles, summary)` on success, where `summary` is a
/// `ValidationSummary` counting the types of errors encountered.
///
/// # Errors
///
/// Returns an error if the data cannot be decoded.
pub fn parse_subscription_data(
    data: &[u8],
    settings: &ValidationSettings,
) -> Result<(Vec<ParsedProfile>, ValidationSummary), String> {
    let mut decoder = StreamingDecoder::new();
    let mut profiles: Vec<ParsedProfile> = Vec::new();
    let mut summary = ValidationSummary::default();

    // Stream: parse each chunk's URLs via the shared batch funnel, then drop
    // them — no `all_urls` hold-all, peak transient is one chunk's URLs plus
    // `profiles`.
    for chunk in data.chunks(INPUT_CHUNK_SIZE) {
        let urls = decoder.feed(chunk)?;
        let (batch, batch_summary) = parse_url_batch(&urls, settings);
        profiles.extend(batch);
        summary.merge(&batch_summary);
    }

    // Finalize
    let urls = decoder.finalize()?;
    let (batch, batch_summary) = parse_url_batch(&urls, settings);
    profiles.extend(batch);
    summary.merge(&batch_summary);

    Ok((profiles, summary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use leas_proto::proto_spec::ProtocolKind;

    #[test]
    fn test_subscription_url_split_single() {
        let urls = subscription_url_split("vmess://abc123");
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "vmess://abc123");
    }

    #[test]
    fn test_subscription_url_split_multiple() {
        let urls = subscription_url_split("vmess://abc123vless://def456trojan://ghi789");
        assert_eq!(urls.len(), 3);
        assert!(urls[0].starts_with("vmess://"));
        assert!(urls[1].starts_with("vless://"));
        assert!(urls[2].starts_with("trojan://"));
    }

    #[test]
    fn test_subscription_url_split_with_newlines() {
        let input = "vmess://abc123\nvless://def456\ntrojan://ghi789\n";
        let urls = subscription_url_split(input);
        assert_eq!(urls.len(), 3);
    }

    #[test]
    fn test_streaming_decoder_empty() {
        let mut decoder = StreamingDecoder::new();
        let result = decoder.feed(b"").unwrap();
        assert_eq!(result.len(), 0);
        let result = decoder.finalize().unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_subscription_data_empty() {
        let settings = crate::import_export::ValidationSettings::default();
        let (profiles, summary) = parse_subscription_data(b"", &settings).unwrap();
        assert!(profiles.is_empty());
        assert_eq!(summary.total_errors, 0);
        assert_eq!(summary.missing_field_count, 0);
        assert_eq!(summary.host_validation_count, 0);
        assert_eq!(summary.security_warning_count, 0);
        assert_eq!(summary.other_count, 0);
    }

    #[test]
    fn test_streaming_decoder_partial_chunks() {
        // Feed data split at non-4-byte base64 boundary (3 bytes first, rest later)
        let mut decoder = StreamingDecoder::new();
        let input = b"vmess://abc123\nvless://def456\n";
        let b64 = base64_simd::STANDARD.encode_to_string(input);

        let part1 = &b64.as_bytes()[..3];
        let part2 = &b64.as_bytes()[3..];

        // First feed with 3 bytes: pending only, nothing processed
        let result1 = decoder.feed(part1).unwrap();
        assert!(
            result1.is_empty(),
            "partial chunk (3 bytes) should yield nothing"
        );

        // Second feed with remaining + pending 3 = 4-byte aligned, processes both
        let result2 = decoder.feed(part2).unwrap();
        let result3 = decoder.finalize().unwrap();
        let all_urls: Vec<String> = result2.into_iter().chain(result3).collect();
        assert!(!all_urls.is_empty(), "complete chunk should yield URLs");
        assert!(all_urls.iter().any(|u| u.starts_with("vmess://")));
        assert!(all_urls.iter().any(|u| u.starts_with("vless://")));
    }

    #[test]
    fn test_streaming_decoder_partial_at_alignment() {
        // Feed data split exactly at a 4-byte boundary
        let mut decoder = StreamingDecoder::new();
        let input = b"vmess://abc123\nvless://def456\n";
        let b64 = base64_simd::STANDARD.encode_to_string(input);

        let mid = b64.len() / 2;
        let mid_aligned = (mid / 4) * 4;
        let (part1, part2) = b64.split_at(mid_aligned);

        let r1 = decoder.feed(part1.as_bytes()).unwrap();
        let r2 = decoder.feed(part2.as_bytes()).unwrap();
        let r3 = decoder.finalize().unwrap();
        let all: Vec<_> = r1.into_iter().chain(r2).chain(r3).collect();
        assert!(all.iter().any(|u| u.starts_with("vmess://")));
        assert!(all.iter().any(|u| u.starts_with("vless://")));
    }

    #[test]
    fn test_streaming_decoder_encoding_transition_mid_stream() {
        // Data whose standard base64 contains '/' (standard-only character)
        // 3 bytes 0x3effff -> standard: Pv//, url-safe: Pv__
        let data = b"\x3e\xff\xff";
        let std_b64 = base64_simd::STANDARD_NO_PAD.encode_to_string(data);
        let url_b64 = base64_simd::URL_SAFE_NO_PAD.encode_to_string(data);

        assert!(
            std_b64.contains('/'),
            "std base64 must contain / for test validity"
        );
        assert!(
            url_b64.contains('_'),
            "url-safe base64 must contain _ for test validity"
        );

        // Phase 1: lock decoder to StdB64 by feeding standard base64
        let mut decoder = StreamingDecoder::new();
        let _r1 = decoder.feed(std_b64.as_bytes()).unwrap();

        // Phase 2: feed URL-safe data — should fail since locked to StdB64
        let r2 = decoder.feed(url_b64.as_bytes());
        assert!(
            r2.is_err(),
            "URL-safe input after standard lock should fail: {r2:?}"
        );
    }

    #[test]
    fn test_streaming_decoder_encoding_transition_reverse() {
        // Lock to URL-safe first, then try standard
        let data = b"\x3e\xff\xff";
        let url_b64 = base64_simd::URL_SAFE_NO_PAD.encode_to_string(data);
        let std_b64 = base64_simd::STANDARD_NO_PAD.encode_to_string(data);

        let mut decoder = StreamingDecoder::new();
        let _r1 = decoder.feed(url_b64.as_bytes()).unwrap();

        let r2 = decoder.feed(std_b64.as_bytes());
        assert!(
            r2.is_err(),
            "standard input after URL-safe lock should fail: {r2:?}"
        );
    }

    #[test]
    fn test_streaming_decoder_whitespace_only_chunks() {
        let mut decoder = StreamingDecoder::new();
        let r1 = decoder.feed(b"   \n  \n  ").unwrap();
        assert_eq!(r1.len(), 0);
        let r2 = decoder.feed(b"\t\n\r\n").unwrap();
        assert_eq!(r2.len(), 0);
        let r3 = decoder.finalize().unwrap();
        assert_eq!(r3.len(), 0);
    }

    #[test]
    fn test_subscription_url_split_empty_input() {
        let urls = subscription_url_split("");
        assert_eq!(urls.len(), 0);
    }

    #[test]
    fn test_subscription_url_split_no_scheme() {
        let urls = subscription_url_split("just-some-text-without-scheme");
        assert_eq!(urls.len(), 0);
    }

    #[test]
    fn test_subscription_url_split_mixed_newlines_and_concatenated() {
        // Mix of newline-separated and concatenated URLs
        let input = "vmess://abc\nvless://defvless://ghitrojan://jkl\n";
        let urls = subscription_url_split(input);
        assert_eq!(urls.len(), 4);
        assert!(urls[0].starts_with("vmess://"));
        assert!(urls[1].starts_with("vless://"));
        assert!(urls[2].starts_with("vless://"));
        assert!(urls[3].starts_with("trojan://"));
    }

    #[test]
    fn test_subscription_url_split_single_scheme() {
        // Only a scheme prefix, no meaningful content after it
        let urls = subscription_url_split("vmess://");
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "vmess://");
    }

    /// Canonical valid vmess URL (parses through `parse_share_url`).
    fn valid_vmess_url() -> String {
        let qr = serde_json::json!({
            "v": "2", "ps": "test", "add": "1.2.3.4", "port": "443",
            "id": "550e8400-e29b-41d4-a716-446655440000", "aid": "0", "scy": "auto",
            "net": "tcp", "type": "none", "host": "", "path": "", "tls": "",
            "sni": "", "alpn": "", "fp": "", "insecure": "0",
        });
        let b64 = base64_simd::STANDARD.encode_to_string(serde_json::to_string(&qr).unwrap());
        format!("vmess://{b64}")
    }

    /// A failure must carry its REASON, not only a counter. The 2026-10-01 run
    /// had a subscription that reported `1 links, 1 errors` four times with
    /// every bucket zero except `other: 1`, and nothing said why.
    #[test]
    fn a_failed_entry_records_why_it_failed() {
        let settings = crate::import_export::ValidationSettings::default();
        let good =
            "vless://11111111-1111-1111-1111-111111111111@a.example:443?security=tls&type=tcp#ok"
                .to_owned();
        let garbage = "not-a-url-at-all".to_owned();
        let (_, summary) = parse_url_batch(&[good, garbage], &settings);
        assert_eq!(summary.other_count, 1);
        assert!(
            !summary.sample_errors.is_empty(),
            "the reason must survive to the summary",
        );
    }

    /// The recorded reason must NEVER carry credentials. `ImportError::Parse`'s
    /// Display embeds `ParseError`, and several variants include the raw URL or
    /// its userinfo — which `log_trace` would then PERSIST to the LMDB store.
    #[test]
    fn a_recorded_reason_never_carries_the_url_or_userinfo() {
        let settings = crate::import_export::ValidationSettings::default();
        // An ss URL with a real base64 userinfo: `ss.rs` reports it as
        // `InvalidUserInfo("{userinfo}")`, so the raw value is in the error.
        let url = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@x.example:8388#n".to_owned();
        let (_, summary) = parse_url_batch(std::slice::from_ref(&url), &settings);
        for reason in &summary.sample_errors {
            assert!(
                !reason.contains("YWVzLTI1Ni1nY206cGFzc3dvcmQ"),
                "a credential leaked into the persisted log: {reason}",
            );
            assert!(
                !reason.contains("x.example"),
                "the host leaked into the persisted log: {reason}",
            );
        }
    }

    /// The sample is bounded, and says how much it dropped rather than
    /// pretending the list is complete.
    #[test]
    fn the_error_sample_is_bounded_and_counts_what_it_dropped() {
        let mut summary = ValidationSummary::default();
        for i in 0..20 {
            summary.record_error(format!("reason {i}"));
        }
        assert_eq!(
            summary.sample_errors.len(),
            ValidationSummary::SAMPLE_ERROR_CAP
        );
        assert_eq!(summary.sample_errors_omitted, 15);
    }

    #[test]
    fn parse_url_batch_counts_valid_and_invalid() {
        let urls = vec![
            valid_vmess_url(),
            // Garbage that cannot parse: lands in other_count.
            "vmess://!!!not-base64!!!".to_string(),
        ];
        let settings = crate::import_export::ValidationSettings::default();
        let (profiles, summary) = parse_url_batch(&urls, &settings);
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].parsed.protocol.proto_kind, ProtocolKind::Vmess);
        assert_eq!(summary.other_count, 1);
        assert_eq!(summary.total_errors, 1);
        assert_eq!(summary.missing_field_count, 0);
        assert_eq!(summary.host_validation_count, 0);
    }

    #[test]
    fn url_chunks_matches_parse_subscription_data_profile_count() {
        let settings = crate::import_export::ValidationSettings::default();
        // Plain-text body (no base64).
        let plain = format!(
            "{}\n{}\nvless://bad-url-!\n",
            valid_vmess_url(),
            valid_vmess_url()
        );
        let (profiles, _) = parse_subscription_data(plain.as_bytes(), &settings).unwrap();
        let urls = subscription_url_chunks(plain.as_bytes()).unwrap();
        // 3 URLs split, but `vless://bad-url-!` fails to parse → 2 profiles.
        assert_eq!(urls.len(), 3);
        assert_eq!(profiles.len(), 2);

        // Base64-encoded body.
        let b64 = base64_simd::STANDARD.encode_to_string(plain.as_bytes());
        let (profiles_b64, _) = parse_subscription_data(b64.as_bytes(), &settings).unwrap();
        let urls_b64 = subscription_url_chunks(b64.as_bytes()).unwrap();
        assert_eq!(
            urls_b64.len(),
            urls.len(),
            "both encodings split identically"
        );
        assert_eq!(
            profiles_b64.len(),
            profiles.len(),
            "both encodings parse identically"
        );
    }

    #[test]
    fn url_chunks_empty_input_yields_empty() {
        assert_eq!(subscription_url_chunks(b"").unwrap().len(), 0);
    }
}
