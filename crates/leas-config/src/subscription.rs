//! Subscription data parsing: chunked base64 decoder + URL splitting + batch parse.

use crate::import_export::{
    ImportError, ParsedProfile, ValidationSettings, ValidationSummary, parse_share_url,
};
use base64_simd::STANDARD_NO_PAD;
use daachorse::{DoubleArrayAhoCorasick, DoubleArrayAhoCorasickBuilder, MatchKind};
use leas_proto::proto_spec::{ProtoSpec, SecurityConfig};

/// Bounded feed step for [`StreamingDecoder::feed`].
///
/// `feed` splits any larger slice into steps of this size, so no single
/// internal buffer grows with the caller's chunk. The decoder is
/// chunking-invariant, so the value only bounds work per step — it never
/// changes the result.
pub const INPUT_CHUNK_SIZE: usize = 65536;

/// Upper bound on one incomplete line kept between feeds. A line that grows
/// past it is cut at the last scheme boundary (concatenated `a://..b://..`
/// feeds); a single URL longer than this is dropped and counted.
const MAX_LINE: usize = 262_144;

/// Significant (non-whitespace) bytes needed before the encoding is decided.
/// Every scheme has its `:` within the first 14 bytes (`naive+https:`), and
/// header/comment lines start with `#`, so 16 base64-only bytes are a safe
/// signal — without guessing on a 4-byte first chunk.
const DETECT_WINDOW: usize = 16;

/// UTF-8 byte-order mark some feeds prepend.
const BOM: &[u8] = b"\xEF\xBB\xBF";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Buffering the first bytes into `head` until the encoding is clear.
    Detecting,
    /// Base64 in either alphabet (`+/` or `-_`), padded or not, wrapped or not.
    Base64,
    Raw,
}

/// Streaming subscription decoder: bytes → (base64 | raw) → lines → URLs.
///
/// Two independent stages, each with its own carry:
/// 1. **byte stage** — base64 is normalized to the standard alphabet with
///    whitespace dropped, so line-wrapped (MIME) and URL-safe input decode
///    the same way; only an incomplete 4-char quantum is carried.
/// 2. **line stage** (`LineStage`) — works on *bytes*, not `str`. A line is
///    only turned into text once its `\n` arrives; `\n` is ASCII, so a
///    complete line can never end inside a UTF-8 sequence. No `unsafe`, no
///    lossy chunk path.
///
/// The output does not depend on how the input is split into chunks.
pub struct StreamingDecoder {
    mode: Mode,
    /// Detection buffer (only non-empty while `Mode::Detecting`).
    head: Vec<u8>,
    /// Normalized base64 chars not yet decoded (< 4 after each step).
    b64: Vec<u8>,
    /// Alphabet locked by the first `+`/`/` (`Some(false)`) or `-`/`_`
    /// (`Some(true)`); mixing both is rejected as corrupt input.
    url_safe: Option<bool>,
    /// Decoded-bytes scratch, reused across feeds.
    decoded: Vec<u8>,
    /// Line assembly and URL emission.
    lines: LineStage,
}

/// The line stage: whole lines out of a byte stream, one URL each.
///
/// A separate owner so the byte stage can read its own scratch (`decoded`)
/// while this one is written — no take/restore dance, no `unsafe`.
#[derive(Debug)]
struct LineStage {
    /// Incomplete trailing line, raw bytes (may end mid-codepoint).
    line: Vec<u8>,
    /// Dropping the rest of an over-long single URL until the next `\n`.
    skipping: bool,
    /// Single URLs dropped for exceeding [`MAX_LINE`].
    overlong: usize,
}

impl LineStage {
    const fn new() -> Self {
        Self {
            line: Vec::new(),
            skipping: false,
            overlong: 0,
        }
    }

    /// Reset the carry, keeping allocations. `overlong` is a run counter, not
    /// decode state: [`StreamingDecoder::finalize`] restores it across the
    /// reset it performs.
    fn reset(&mut self) {
        self.line.clear();
        self.skipping = false;
        self.overlong = 0;
    }

    /// Feed one run of text bytes, emit every URL that is now complete.
    fn push(&mut self, mut data: &[u8], out: &mut Vec<String>) {
        // Finish the pending line first.
        if self.skipping || !self.line.is_empty() {
            let Some(nl) = memchr::memchr(b'\n', data) else {
                if !self.skipping {
                    self.line.extend_from_slice(data);
                    self.enforce_limit(out);
                }
                return;
            };
            if !self.skipping {
                self.line.extend_from_slice(&data[..nl]);
                // Same limit as for a still-open line, so the result does not
                // depend on where the chunk boundary fell.
                self.enforce_limit(out);
            }
            if !self.skipping {
                process_text_std(&self.line, out);
            }
            // The over-long line ended here, so the drop ends with it.
            self.skipping = false;
            self.line.clear();
            data = &data[nl + 1..];
        }
        // Whole lines straight from the input slice, no copy.
        if let Some(last) = memchr::memrchr(b'\n', data) {
            process_text_std(&data[..last], out);
            data = &data[last + 1..];
        }
        self.line.extend_from_slice(data);
        self.enforce_limit(out);
    }

    /// Cap the pending line.
    ///
    /// A line is only complete at its `\n`, so a feed that concatenates URLs
    /// without newlines would otherwise grow one line without bound. Cut it at
    /// the last scheme start — an ASCII boundary, so UTF-8 stays intact — and
    /// emit the part before it. A single URL longer than [`MAX_LINE`] has no
    /// such boundary: drop it, and count it rather than silently shrinking it.
    ///
    /// The scheme machine is ASCII-case-insensitive; since `self.line` is raw
    /// bytes, fold a copy (`[u8]::to_ascii_lowercase`, byte-length-preserving)
    /// so cut offsets map 1:1 onto `self.line`. This path only runs past
    /// `MAX_LINE`, so the copy never touches the per-line hot loop.
    fn enforce_limit(&mut self, out: &mut Vec<String>) {
        if self.line.len() <= MAX_LINE {
            return;
        }
        if let Some(cut) = SCHEMA_AC
            .leftmost_find_iter(&self.line[..].to_ascii_lowercase())
            .map(|m| m.start())
            .filter(|&s| s > 0)
            .last()
        {
            process_text_std(&self.line[..cut], out);
            self.line.drain(..cut);
        }
        if self.line.len() > MAX_LINE {
            self.overlong += 1;
            self.line.clear();
            self.skipping = true;
        }
    }
}

impl StreamingDecoder {
    /// Create a new decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mode: Mode::Detecting,
            head: Vec::new(),
            b64: Vec::new(),
            url_safe: None,
            decoded: Vec::new(),
            lines: LineStage::new(),
        }
    }

    /// Reset to the initial state, keeping allocations.
    pub fn reset(&mut self) {
        self.mode = Mode::Detecting;
        self.head.clear();
        self.b64.clear();
        self.url_safe = None;
        self.decoded.clear();
        self.lines.reset();
    }

    /// Number of single URLs dropped for exceeding the line limit.
    ///
    /// Cumulative over the decoder's life: [`Self::finalize`] resets the
    /// decoding state but deliberately keeps this counter, so a decoder reused
    /// for several runs reports the total. Read it, then [`Self::reset`] to
    /// clear it.
    #[must_use]
    pub const fn overlong_lines(&self) -> usize {
        self.lines.overlong
    }

    /// Feed one chunk of any size. Returns the URLs completed by it.
    ///
    /// # Errors
    ///
    /// Returns an error if base64 input contains a byte outside both alphabets
    /// or an impossible quantum (a single trailing char before `=`).
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for part in chunk.chunks(INPUT_CHUNK_SIZE) {
            self.feed_part(part, false, &mut out)?;
        }
        Ok(out)
    }

    /// Flush buffered data. Call once after the last `feed()`; the decoder is
    /// reset afterwards and can be reused.
    ///
    /// # Errors
    ///
    /// Returns an error if the final base64 quantum is invalid.
    pub fn finalize(&mut self) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        self.feed_part(&[], true, &mut out)?;
        if !self.lines.skipping && !self.lines.line.is_empty() {
            process_text_std(&self.lines.line, &mut out);
        }
        let overlong = self.lines.overlong;
        self.reset();
        self.lines.overlong = overlong;
        Ok(out)
    }

    // ── byte stage ──

    fn feed_part(&mut self, part: &[u8], eof: bool, out: &mut Vec<String>) -> Result<(), String> {
        let head;
        let input: &[u8] = if self.mode == Mode::Detecting {
            self.head.extend_from_slice(part);
            match detect(&self.head, eof) {
                Some(mode) => self.mode = mode,
                None => return Ok(()),
            }
            head = std::mem::take(&mut self.head);
            strip_bom(&head)
        } else {
            part
        };
        match self.mode {
            Mode::Raw => self.lines.push(input, out),
            Mode::Base64 => self.push_decoded(input, eof, out)?,
            Mode::Detecting => unreachable!("mode decided above"),
        }
        Ok(())
    }

    /// Decode one run of base64 input and emit its text: clear, decode, flush
    /// the quantum tail at `eof`, then push EXACTLY once.
    ///
    /// One decode site for both `feed` and `finalize`. Splitting the push — one
    /// in `feed_part`, one in `finalize` for the tail — emitted the same bytes
    /// twice for any body still under the detection window at `finalize`.
    fn push_decoded(
        &mut self,
        input: &[u8],
        eof: bool,
        out: &mut Vec<String>,
    ) -> Result<(), String> {
        self.decoded.clear();
        self.decode_b64(input)?;
        if eof {
            self.flush_b64_tail()?;
        }
        self.lines.push(&self.decoded, out);
        Ok(())
    }

    /// Normalize into `self.b64`, decode whole quanta into `self.decoded`.
    /// `=` ends a block (also handles several padded blocks back to back).
    fn decode_b64(&mut self, input: &[u8]) -> Result<(), String> {
        self.b64.reserve(input.len());
        for &b in input {
            let n = match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => b,
                b'+' | b'/' => {
                    self.lock_alphabet(false)?;
                    b
                }
                b'-' | b'_' => {
                    self.lock_alphabet(true)?;
                    if b == b'-' { b'+' } else { b'/' }
                }
                b'=' => {
                    self.flush_b64_tail()?;
                    continue;
                }
                b if b.is_ascii_whitespace() => continue,
                other => {
                    return Err(format!(
                        "base64 decode error: unexpected byte 0x{other:02x}"
                    ));
                }
            };
            self.b64.push(n);
        }
        let aligned = self.b64.len() / 4 * 4;
        if aligned > 0 {
            STANDARD_NO_PAD
                .decode_append(&self.b64[..aligned], &mut self.decoded)
                .map_err(|e| format!("base64 decode error: {e}"))?;
            self.b64.drain(..aligned);
        }
        Ok(())
    }

    fn lock_alphabet(&mut self, url_safe: bool) -> Result<(), String> {
        match self.url_safe.replace(url_safe) {
            Some(prev) if prev != url_safe => {
                Err("base64 decode error: standard and URL-safe alphabets mixed".to_owned())
            }
            _ => Ok(()),
        }
    }

    /// Decode a final partial quantum (2 or 3 chars); 1 char is invalid.
    fn flush_b64_tail(&mut self) -> Result<(), String> {
        if self.b64.len() % 4 == 1 {
            return Err("base64 decode error: dangling quantum".to_owned());
        }
        if !self.b64.is_empty() {
            STANDARD_NO_PAD
                .decode_append(&self.b64, &mut self.decoded)
                .map_err(|e| format!("base64 decode error: {e}"))?;
            self.b64.clear();
        }
        Ok(())
    }
}

impl Default for StreamingDecoder {
    fn default() -> Self {
        Self::new()
    }
}

fn strip_bom(data: &[u8]) -> &[u8] {
    data.strip_prefix(BOM).unwrap_or(data)
}

/// Decide the encoding from the buffered head, or `None` if more is needed.
///
/// Raw as soon as any byte outside base64 ∪ whitespace ∪ `=` shows up (every
/// share URL has `:`), base64 once `DETECT_WINDOW` significant bytes are all
/// base64 — or at EOF with whatever arrived.
fn detect(head: &[u8], eof: bool) -> Option<Mode> {
    // A BOM split across feeds must not be read as a non-base64 byte.
    if !eof && !head.is_empty() && BOM.starts_with(head) {
        return None;
    }
    let (mut significant, mut std_seen, mut url_seen) = (0, false, false);
    for &b in strip_bom(head) {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'=' => significant += 1,
            b'+' | b'/' => (significant, std_seen) = (significant + 1, true),
            b'-' | b'_' => (significant, url_seen) = (significant + 1, true),
            b if b.is_ascii_whitespace() => {}
            _ => return Some(Mode::Raw),
        }
        // Enough evidence — or both alphabets already: let the base64 stage
        // report the corruption now instead of buffering it.
        if significant >= DETECT_WINDOW || (std_seen && url_seen) {
            return Some(Mode::Base64);
        }
    }
    eof.then_some(if significant == 0 {
        Mode::Raw
    } else {
        Mode::Base64
    })
}

/// Scheme prefixes that start a share URL, matched case-insensitively.
static SCHEMA_AC: std::sync::LazyLock<DoubleArrayAhoCorasick<u32>> =
    std::sync::LazyLock::new(|| {
        DoubleArrayAhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
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
            .expect("static scheme patterns")
    });

/// Standard `process_text`: append every URL in `data` (newline-separated, then
/// scheme-split within each line) to `out`.
///
/// Lines are scanned with `memchr` ranges over the raw bytes; each line is
/// `from_utf8_lossy`-borrowed when valid (no String copy) and only copied on
/// genuinely invalid UTF-8 lines. Appending into the caller's buffer rather
/// than returning one drops a per-line `Vec` — the streaming decoder calls this
/// once per completed line, so that throwaway dominated its allocation count.
fn process_text_std(data: &[u8], out: &mut Vec<String>) {
    let mut start = 0;
    while start <= data.len() {
        let end = memchr::memchr(b'\n', &data[start..]).map_or(data.len(), |rel| start + rel);
        let line = String::from_utf8_lossy(&data[start..end]);
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            subscription_url_split_into(trimmed, out);
        }
        if end == data.len() {
            break;
        }
        start = end + 1;
    }
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
/// Aho-Corasick to find all scheme boundaries, appending to `out`.
///
/// Handles the case where multiple URLs are concatenated without newlines
/// (e.g., `vmess://...vless://...trojan://...`). The append form exists so the
/// streaming path reuses one output buffer instead of allocating a fresh `Vec`
/// per completed line.
fn subscription_url_split_into(text: &str, out: &mut Vec<String>) {
    let mut last_start: Option<usize> = None;

    // daachorse has no `ascii_case_insensitive` option; the fold runs on a
    // copy. `to_ascii_lowercase` is byte-length-preserving (non-ASCII passes
    // through), so byte ranges stay valid on the original `text`. The borrowed
    // arm avoids a copy for the (common) already-lowercase input.
    let lowered: std::borrow::Cow<'_, str> = if text.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(text.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(text)
    };

    for m in SCHEMA_AC.leftmost_find_iter(lowered.as_ref()) {
        if let Some(start) = last_start.take() {
            let end = m.start();
            out.push(text[start..end].to_string());
        }
        last_start = Some(m.start());
    }

    if let Some(start) = last_start.take() {
        out.push(text[start..].to_string());
    }
}

/// Split concatenated subscription data into individual URLs using
/// Aho-Corasick to find all scheme boundaries.
#[must_use]
pub fn subscription_url_split(text: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    subscription_url_split_into(text, &mut chunks);
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

    /// Case-insensitive scheme matching: uppercase and mixed-case schemes split
    /// exactly like lowercase ones, and the chunks keep the ORIGINAL casing
    /// (the ASCII fold happens on a lowered copy; slicing uses `text`).
    #[test]
    fn test_subscription_url_split_matching_is_ascii_case_insensitive() {
        let urls = subscription_url_split("VMESS://abc12");
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "VMESS://abc12");

        let urls = subscription_url_split("VMeSs...");
        assert_eq!(urls.len(), 0);

        let input = "VMESS://PayLoadVlEsS://xY";
        let urls = subscription_url_split(input);
        assert_eq!(urls, vec!["VMESS://PayLoad", "VlEsS://xY"]);
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
