use std::borrow::Cow;

/// Decode base64 with trailing annotation stripping and URL-safe/Standard fallback.
///
/// Stray backtick characters filtered, then percent-decoded (handles %XX in base64
/// content), trailing non-base64 annotation text stripped, tries
/// `BASE64_URL_SAFE_NO_PAD` first then `BASE64_STANDARD_NO_PAD`.
///
/// Stray backtick characters filtered, then percent-decoded (handles %XX in base64
/// content), trailing non-base64 annotation text stripped, tries
/// `URL_SAFE_NO_PAD` first then `STANDARD_NO_PAD`.
///
/// # Errors
///
/// Returns a `base64_simd::Error` if neither encoding produces valid output,
/// or if the input is empty after cleaning.
pub fn decode_base64(data: &str) -> Result<Vec<u8>, base64_simd::Error> {
    // Strip stray backtick characters
    let cleaned: String = data.chars().filter(|&c| c != '`').collect();

    // Percent-decode first (handles %XX sequences that may represent base64 chars)
    let decoded = simple_percent_decode(&cleaned);

    // Find end of valid base64 characters in the decoded string
    let end = decoded
        .as_ref()
        .find(|c: char| !c.is_ascii_alphanumeric() && !matches!(c, '+' | '/' | '-' | '_' | '='))
        .unwrap_or_else(|| decoded.as_ref().len());
    let mut data = &decoded.as_ref()[..end];

    // After the last padding marker (`==` or `=`), strip trailing annotation text.
    if let Some(pos) = data.rfind("==") {
        data = &data[..pos + 2];
    } else if let Some(pos) = data.rfind('=') {
        data = &data[..=pos];
    }

    let trimmed = data.trim_end_matches(|c: char| c == '=' || c.is_whitespace());

    if trimmed.is_empty() {
        return Err(base64_simd::STANDARD_NO_PAD
            .decode_to_vec(b"!")
            .unwrap_err());
    }

    'block: {
        let e = match base64_simd::URL_SAFE_NO_PAD.decode_to_vec(trimmed.as_bytes()) {
            Ok(r) => break 'block Ok(r),
            Err(e) => e,
        };
        if let Ok(r) = base64_simd::STANDARD_NO_PAD.decode_to_vec(trimmed.as_bytes()) {
            break 'block Ok(r);
        }
        Err(e)
    }
}

/// Percent-decode a string, replacing %XX sequences with decoded bytes.
fn simple_percent_decode(s: &str) -> Cow<'_, str> {
    urlencoding::decode(s).map_or(Cow::Borrowed(s), |d| Cow::Owned(d.into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_base64() {
        let result = decode_base64("aGVsbG8=").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_url_safe_base64() {
        let result = decode_base64("aGVsbG8").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_trailing_annotation() {
        let result = decode_base64("aGVsbG8=Irancell").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_backtick_filtering() {
        let result = decode_base64("aGVs`bG8=").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_url_safe_no_pad() {
        let result = decode_base64("Pj4-Pj4-Pj4").unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_invalid_base64() {
        assert!(decode_base64("!!!not-base64!!!").is_err());
    }

    #[test]
    fn test_empty_input() {
        assert!(decode_base64("").is_err());
    }

    #[test]
    fn test_percent_encoded_chars() {
        // %2F = / (standard base64 valid), %2B = + (standard base64 valid)
        // After percent-decoding: "aGVs/G8+" which contains standard base64 chars
        let result = decode_base64("aGVs%2FG8%2B").unwrap();
        // 011010 000110 010101 111111 000110 111100 111110 (with empty pad)
        // aGVs/G8+ in standard = 3 bytes + 3 bytes = 6 bytes
        assert_eq!(result.len(), 6);
        assert!(result.starts_with(b"hel"));
    }

    #[test]
    fn test_url_safe_vs_standard_auto_detect_ambiguous() {
        // String valid in both URL-safe and standard: alphanumeric only
        let result = decode_base64("aGVsbG8").unwrap(); // "hello" in both encodings
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_url_safe_vs_standard_auto_detect_standard_specific() {
        // Contains '+' (standard-only): must auto-detect as standard
        // base64(">\xff\xff") in standard = Pv//, but we need '+'
        // '>' = 0x3E = 62 in base64 = '+' in standard
        // Let's use a string whose standard encoding contains '+'
        let data = [0xFB, 0xFB, 0xFB]; // 3 bytes that produce base62 values
        let std_b64 = base64_simd::STANDARD_NO_PAD.encode_to_string(data);
        assert!(
            std_b64.contains('+') || std_b64.contains('/'),
            "must contain standard-only chars: {std_b64}"
        );
        let result = decode_base64(&std_b64).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_percent_encoded_plus_sign() {
        // %2B is '+' (standard base64 char). The decoder percent-decodes then
        // tries to decode as base64. Standard decode should work.
        let data = b"hello+world";
        let std_b64 = base64_simd::STANDARD_NO_PAD.encode_to_string(data);
        // Double-encode: percent-encode the '+' in the base64
        let double_encoded = std_b64.replace('+', "%2B");
        let result = decode_base64(&double_encoded).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_trailing_annotation_single_pad() {
        // String with single = padding and trailing annotation text
        let result = decode_base64("aGVsbG8=Irancell").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_trailing_annotation_double_pad() {
        // String with double == padding and trailing annotation
        // "hm" base64 = "aG0=" (1 pad), "hma" base64 = "aG1h" (no pad), "hmab" base64 = "aG1hYg==" (2 pads)
        let result = decode_base64("aG1hYg==annotation").unwrap();
        assert_eq!(result, b"hmab");
    }

    #[test]
    fn test_trailing_annotation_no_pad() {
        // No padding, annotation separated by space (acts as delimiter)
        let result = decode_base64("aGVsbG8= annotation").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_mixed_padding_single_eq() {
        // Single = padding
        let result = decode_base64("aGVsbG8=").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_mixed_padding_double_eq() {
        // Double == padding — base64 of 1 byte = 2 base64 chars + "=="
        // 'h' = 0x68 = 01101000 -> 011010 000000 -> aA==
        let result = decode_base64("aA==").unwrap();
        assert_eq!(result, b"h");
    }

    #[test]
    fn test_trailing_annotation_truncated_pad() {
        // Annotation containing '=' after padding — '=' in annotation doesn't break
        // because the decoder stops at the first non-base64 delimiter after padding
        let result = decode_base64("aGVsbG8= foo=bar").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_very_long_base64() {
        // Generate a 20KB base64 string, verify decode succeeds
        let large_data: Vec<u8> = (0..15000usize)
            .map(|i| {
                u8::try_from(i % 256)
                    .expect("mod 256 fits u8")
                    .wrapping_mul(17)
            })
            .collect();
        let b64 = base64_simd::STANDARD_NO_PAD.encode_to_string(&large_data);
        assert!(b64.len() > 10000, "should be a long string: {}", b64.len());
        let result = decode_base64(&b64).unwrap();
        assert_eq!(result, large_data);
    }
}
