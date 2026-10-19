//! Chunking-invariance and encoding coverage for [`StreamingDecoder`].
//!
//! The decoder used to be split-sensitive: a base64 body that arrived in
//! different chunk sizes produced different URLs, MIME-wrapped input decoded to
//! nothing, and a multi-byte codepoint straddling the 64 KiB boundary was
//! replaced with U+FFFD. Every test here fails on that implementation.

use leas_config::subscription::{INPUT_CHUNK_SIZE, StreamingDecoder};
use rstest::rstest;

/// Feed `chunks`, then finalize. An error is surfaced in-band so a test can
/// assert on it rather than unwrapping.
fn run(chunks: &[&[u8]]) -> Vec<String> {
    let mut decoder = StreamingDecoder::new();
    let mut out = Vec::new();
    for chunk in chunks {
        match decoder.feed(chunk) {
            Ok(urls) => out.extend(urls),
            Err(e) => {
                out.push(format!("ERR {e}"));
                return out;
            }
        }
    }
    match decoder.finalize() {
        Ok(urls) => out.extend(urls),
        Err(e) => out.push(format!("ERR {e}")),
    }
    out
}

/// Assert the one-shot result is reproduced by every 2-way split AND by
/// byte-by-byte feeding.
fn invariant(body: &[u8], expected: usize) {
    let whole = run(&[body]);
    assert_eq!(whole.len(), expected, "whole={whole:?}");
    for cut in 0..=body.len() {
        assert_eq!(run(&[&body[..cut], &body[cut..]]), whole, "cut {cut}");
    }
    let bytes: Vec<&[u8]> = body.chunks(1).collect();
    assert_eq!(run(&bytes), whole, "byte-by-byte");
}

/// CRLF + LF, a Cyrillic tag and an astral-plane emoji: every line is
/// multi-byte, so any byte-level mangling shows up in the comparison.
fn sample() -> String {
    "trojan://pw@a.example:443#Привет-мир-ёжик\r\nvless://u@b.example:443?security=tls#🇩🇪 Germany\ntrojan://pw@c.example:443#c\n".into()
}

/// MIME-style wrapping: 76 base64 chars, then CRLF.
fn mime_wrapped(b64: &str) -> String {
    let mut out = String::with_capacity(b64.len() + b64.len() / 76 * 2);
    for chunk in b64.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).expect("ascii"));
        out.push_str("\r\n");
    }
    out
}

/// Two base64 blocks with padding, concatenated (several padded blocks back to
/// back, which a naive quantum decoder stops at the first `=`).
fn concatenated_padded_blocks() -> String {
    let s = sample();
    let (a, b) = s.split_at(s.find("vless").expect("scheme"));
    format!(
        "{}{}",
        base64_simd::STANDARD.encode_to_string(a),
        base64_simd::STANDARD.encode_to_string(b)
    )
}

/// Every encoding of the same body must decode to the same 3 URLs at every
/// chunk split — this is the regression for the old split-sensitive decoder.
#[rstest]
#[case::raw_utf8(sample().into_bytes(), 3)]
#[case::raw_with_bom_no_trailing_nl(
    format!("\u{FEFF}{}", sample().trim_end()).into_bytes(),
    3
)]
#[case::std_b64(base64_simd::STANDARD.encode_to_string(sample()).into_bytes(), 3)]
#[case::urlsafe_nopad(
    base64_simd::URL_SAFE_NO_PAD.encode_to_string(sample()).into_bytes(),
    3
)]
#[case::wrapped_mime(mime_wrapped(&base64_simd::STANDARD.encode_to_string(sample())).into_bytes(), 3)]
#[case::concatenated_padded_blocks(concatenated_padded_blocks().into_bytes(), 3)]
fn every_split_of_every_encoding_decodes_identically(
    #[case] body: Vec<u8>,
    #[case] expected: usize,
) {
    invariant(&body, expected);
}

/// A complete base64 body whose significant bytes stay under the detection
/// window is only decoded at `finalize`. That path used to emit its URLs twice:
/// once while decoding the head, again for the quantum tail.
#[test]
fn tiny_base64_body_decided_at_finalize_is_emitted_once() {
    let body = "ss://a\n";
    for encoded in [
        base64_simd::STANDARD.encode_to_string(body),
        base64_simd::URL_SAFE_NO_PAD.encode_to_string(body),
    ] {
        assert!(
            encoded.len() < 16,
            "the case must stay under the detection window: {encoded:?}"
        );
        let out = run(&[encoded.as_bytes()]);
        assert_eq!(out, vec!["ss://a".to_string()], "encoded={encoded:?}");
    }
}
/// A raw body's BOM split across feeds must not be read as a non-base64 byte.
/// Locking `Raw` on the first byte would prepend a lone `0xEF` to the first
/// line, and `from_utf8_lossy` would then corrupt the URL with a leading U+FFFD.
#[test]
fn bom_split_across_feeds_does_not_corrupt_the_first_url() {
    let body = format!("\u{FEFF}{}", sample().trim_end());
    let mut decoder = StreamingDecoder::new();
    // The first feed carries only the BOM's first byte.
    let mut out = decoder.feed(&body.as_bytes()[..1]).expect("feed");
    out.extend(decoder.feed(&body.as_bytes()[1..]).expect("feed"));
    out.extend(decoder.finalize().expect("finalize"));
    assert_eq!(out.len(), 3, "{out:?}");
    assert_eq!(
        out[0], "trojan://pw@a.example:443#Привет-мир-ёжик",
        "no leading U+FFFD: {out:?}"
    );
}
/// A multi-byte codepoint straddling the decoder's internal `INPUT_CHUNK_SIZE`
/// boundary must survive intact — the old implementation replaced it with
/// U+FFFD, corrupting the URL tag.
#[test]
fn multibyte_codepoint_at_the_internal_chunk_boundary_survives() {
    // One full input chunk decodes to exactly this many bytes.
    let boundary = INPUT_CHUNK_SIZE / 4 * 3;
    let url = "vless://u@b.example:443#tag";
    // Start the URL line so its trailing 3-byte codepoint begins one byte
    // before `boundary`: bytes boundary-1, boundary, boundary+1.
    let filler_len = boundary - url.len() - 1;
    let mut body = "z".repeat(filler_len - 1);
    body.push('\n');
    body.push_str(url);
    body.push('ё');
    body.push('\n');

    let encoded = base64_simd::STANDARD.encode_to_string(&body);
    let mut decoder = StreamingDecoder::new();
    let mut out = Vec::new();
    for chunk in encoded.as_bytes().chunks(INPUT_CHUNK_SIZE) {
        out.extend(decoder.feed(chunk).expect("feed"));
    }
    out.extend(decoder.finalize().expect("finalize"));

    assert_eq!(out, vec![format!("{url}ё")], "no U+FFFD substitution");
    assert!(!out.iter().any(|u| u.contains('\u{FFFD}')));
}

/// URLs concatenated on ONE line (no `\n`) exceed the line cap: the line is cut
/// at the last scheme start, so none of them is lost or truncated.
#[test]
fn long_concatenated_line_is_cut_at_a_scheme_boundary() {
    let one = "trojan://pw@h.example:443#Узел";
    let count = 20_000; // ~700 KiB on one line
    let all = one.repeat(count);
    let chunks: Vec<&[u8]> = all.as_bytes().chunks(INPUT_CHUNK_SIZE).collect();
    let out = run(&chunks);
    assert_eq!(out.len(), count);
    assert!(out.iter().all(|u| u.as_str() == one));
}

/// A single URL longer than the cap has no scheme boundary to cut at: it is
/// dropped and COUNTED, and the lines around it are kept.
#[test]
fn overlong_single_url_is_dropped_and_counted() {
    let big = format!("vless://u@x.example:443?p={}#big\n", "a".repeat(300_000));
    let all = format!("trojan://pw@a.example:443#a\n{big}trojan://pw@c.example:443#c\n");
    let mut decoder = StreamingDecoder::new();
    let mut out = Vec::new();
    for chunk in all.as_bytes().chunks(INPUT_CHUNK_SIZE) {
        out.extend(decoder.feed(chunk).expect("feed"));
    }
    out.extend(decoder.finalize().expect("finalize"));
    assert_eq!(out.len(), 2, "{out:?}");
    assert_eq!(decoder.overlong_lines(), 1);
}

/// The overlong-line cut machine matches schemes ASCII-case-insensitively: an
/// overlong line whose only repeating boundary is an UPPERCASE scheme is cut
/// at every URL, not dropped. A case-sensitive search on the raw bytes would
/// find no qualifying cut (>0) and drop the whole line as overlong.
#[test]
fn overlong_line_cut_is_ascii_case_insensitive() {
    let lower = "trojan://pw@h.example:443#z";
    let upper = "VMESS://eyJ2IjoiMiIsInBzIjoidCIsImFkZCI6IjEuMi4zLjQifQ==";
    let count = 10_000; // ~500 KiB on one line
    let all = format!("{lower}{}", upper.repeat(count)); // single line, no `\n`
    let chunks: Vec<&[u8]> = all.as_bytes().chunks(INPUT_CHUNK_SIZE).collect();
    let mut decoder = StreamingDecoder::new();
    let mut out = Vec::new();
    for chunk in &chunks {
        out.extend(decoder.feed(chunk).expect("feed"));
    }
    out.extend(decoder.finalize().expect("finalize"));
    assert_eq!(out.len(), count + 1, "{out:?}");
    assert_eq!(out[0], lower);
    assert!(out[1..].iter().all(|u| u == upper), "{out:?}");
    assert_eq!(decoder.overlong_lines(), 0, "cut, never dropped");
}
