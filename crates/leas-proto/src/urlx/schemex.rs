use std::{borrow::Cow, str::FromStr, sync::LazyLock};

use daachorse::{DoubleArrayAhoCorasick, DoubleArrayAhoCorasickBuilder, MatchKind};

use super::TinyText;

#[derive(Debug, Clone, Hash, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[allow(
    clippy::unsafe_derive_deserialize,
    reason = "unsafe is confined to constructor/accessor methods; it never runs during deserialization"
)]
pub enum SchemeX {
    Vless,
    Vmess,
    Hysteria,
    Hysteria2,
    SS,
    SSR,
    Trojan,
    TUIC,
    Warp,
    AnyTLS,
    Https,
    Tg,
    SlipnetEnc,
    Slipnet,
    Stormdns,
    WireGuard,
    Socks,
    Http,
    Naive,
    ShadowTls,
    Tor,
    Ssh,
    Tailscale,
    Undefined,
    Unknown(TinyText),
}
impl SchemeX {
    #[must_use]
    pub const fn as_known_str(&self) -> Option<&'static str> {
        let schema = match self {
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::SS => "ss",
            Self::SSR => "ssr",
            Self::Hysteria2 => "hy2",
            Self::Hysteria => "hy",
            Self::Trojan => "trojan",
            Self::TUIC => "tuic",
            Self::Warp => "warp",
            Self::AnyTLS => "anytls",
            Self::Https => "https",
            Self::Tg => "tg",
            Self::Slipnet => "slipnet",
            Self::SlipnetEnc => "slipnet-enc",
            Self::Stormdns => "stormdns",
            Self::Socks => "socks",
            Self::Http => "http",
            Self::Naive => "naive+https",
            Self::ShadowTls => "shadowtls",
            Self::Tor => "tor",
            Self::Ssh => "ssh",
            Self::Tailscale => "tailscale",
            Self::WireGuard => "wireguard",
            Self::Undefined | Self::Unknown(_) => return None,
        };
        Some(schema)
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Unknown(s) => s.as_str(),
            _ => unsafe { self.as_known_str().unwrap_unchecked() },
        }
    }

    pub fn slice_input(s: &str) -> Vec<(Self, Cow<'_, str>)> {
        static SCHEMA_AC: LazyLock<DoubleArrayAhoCorasick<u32>> = LazyLock::new(|| {
            DoubleArrayAhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostFirst)
                .build([
                    "vless://",
                    "vmess://",
                    "trojan://",
                    "hhysteria2://",
                    "hhysteria://",
                    "hysteria2://",
                    "hysteria://",
                    "hy2://",
                    "hy://",
                    "warp://",
                    "anytls://",
                    "ss://",
                    "ssr://",
                    "https://",
                    "tg://",
                    "slipnet://",
                    "stormdns://",
                    "socks://",
                    "http://",
                    "naive+https://",
                    "naive+quic://",
                    "shadowtls://",
                    "tuic://",
                ])
                .expect("valid daachorse patterns")
        });

        let mut last = None;

        let mut chunks = Vec::new();
        // daachorse has no `ascii_case_insensitive` option; matches are found on
        // an ASCII-folded copy instead. The fold preserves byte length (non-ASCII
        // passes through), so every range stays valid on the original `s`.
        let lowered: Cow<'_, str> = if s.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(s.to_ascii_lowercase())
        } else {
            Cow::Borrowed(s)
        };
        for m in SCHEMA_AC.leftmost_find_iter(lowered.as_ref()) {
            let (cur_start, cur_end) = (m.start(), m.end());
            let schema_area = s
                .get(cur_start..cur_end)
                .expect("daachorse range should be valid")
                .split_once("://")
                .expect("schema pattern always contains ://")
                .0;
            let Ok(schema) = Self::from_str(schema_area);

            if let Some((schema, prev_start)) = last.replace((schema, cur_start)) {
                chunks.push((
                    schema,
                    Cow::Borrowed(s.get(prev_start..cur_start).expect("contiguous range")),
                ));
            }
        }

        if let Some((schema, begin)) = last.take() {
            chunks.push((
                schema,
                Cow::Borrowed(s.get(begin..).expect("remaining range from daachorse")),
            ));
        }
        if chunks.is_empty() {
            let s = match s.find("://") {
                Some(0) => &s[3..],
                None => s,
                _ => return vec![],
            };
            return if s
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii() && !c.is_ascii_whitespace() && !matches!(c, '<'))
            {
                vec![(Self::Undefined, Cow::Owned(format!("undefined://{s}")))]
            } else {
                vec![]
            };
        }
        chunks
    }
}

impl std::fmt::Display for SchemeX {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SchemeX {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        macro_rules! checked_enum {
            (
                $input: expr,
                $variant: ident => $pat: literal $(, $pat2: literal)*;
                $($variant2: ident => $pat3: literal $(, $pat4:literal)*;)*
            ) => {{
                let scheme = match s.to_ascii_lowercase().as_str() {
                    $pat $(| $pat2)* => Self::$variant,
                    $($pat3 $(| $pat4)* => Self::$variant2,)*
                    _ => Self::Unknown(s.into()),
                };
                #[cfg(test)]
                match scheme { Self::$variant => (), $(Self::$variant2 => (),)* Self::Unknown(_) => (), }
                scheme
            }}
        }

        let scheme = checked_enum!(
            s.strip_suffix("://").unwrap_or(s),
            Vless => "vless";
            Vmess => "vmess";
            Trojan => "trojan";
            SS => "shadowsocks", "ss";
            SSR => "shadowsocksr", "ssr";
            TUIC => "tuic";
            Hysteria => "hysteria", "hy";
            Hysteria2 => "hysteria2", "hy2";
            AnyTLS => "anytls";
            Http => "http";
            Socks => "socks", "socks5";
            Naive => "naive+https", "naive+quic", "naive";
            ShadowTls => "shadowtls";
            Tor => "tor";
            Ssh => "ssh";
            Tailscale => "tailscale";
            Https => "https";
            Tg => "tg";
            Slipnet => "slipnet";
            SlipnetEnc => "slipnet-enc";
            Stormdns => "stormdns";
            Undefined => "undefined";
            Warp => "warp";
            WireGuard => "wireguard";
        );

        Ok(scheme)
    }
}

#[cfg(test)]
mod tests {
    use super::SchemeX;
    use rstest::rstest;

    use std::borrow::Cow;

    /// Case-insensitive prefix detection: the automaton matches on an
    /// ASCII-folded copy while every returned chunk spans the ORIGINAL `s`,
    /// so uppercase payload bytes must reach the caller untouched.
    #[rstest]
    #[case::uppercase_schemes("VLESS://PayloadVMESS://rest")]
    #[case::mixed_case_scheme("vMeSs://ahttps://b")]
    #[case::lower_scheme_upcased_payload("vmess://PAYLOAD")]
    fn ascii_fold_only_folds_detection_not_output(#[case] input: &str) {
        let chunks = SchemeX::slice_input(input);
        for (_, area) in &chunks {
            assert!(matches!(area, Cow::Borrowed(_)), "{input}: {area:?}");
            assert!(input.contains(area.as_ref()), "{input}: {area:?}");
        }
    }

    #[test]
    fn uppercase_two_schemes_split_like_lowercase() {
        let chunks = SchemeX::slice_input("VLESS://PayloadVMESS://rest");
        assert_eq!(chunks.len(), 2, "{chunks:?}");
        assert_eq!(chunks[0].0, SchemeX::Vless);
        assert_eq!(chunks[0].1.as_ref(), "VLESS://Payload");
        assert_eq!(chunks[1].0, SchemeX::Vmess);
        assert_eq!(chunks[1].1.as_ref(), "VMESS://rest");
    }

    #[test]
    fn lowercase_scheme_with_uppercase_payload_single_url() {
        let chunks = SchemeX::slice_input("vmess://PAYLOAD");
        assert_eq!(chunks.len(), 1, "{chunks:?}");
        assert_eq!(chunks[0].0, SchemeX::Vmess);
        assert_eq!(chunks[0].1.as_ref(), "vmess://PAYLOAD");
    }

    /// Lowered haystack ranges map 1:1 onto `s`: non-ASCII bytes (never folded
    /// by `to_ascii_lowercase`) keep their length, so slicing stays byte-correct.
    #[test]
    fn multibyte_non_ascii_payload_keeps_byte_ranges() {
        let chunks = SchemeX::slice_input("Vmess://条件条件Anytls://x");
        assert_eq!(chunks.len(), 2, "{chunks:?}");
        assert_eq!(chunks[0].0, SchemeX::Vmess);
        assert_eq!(chunks[0].1.as_ref(), "Vmess://条件条件");
        assert_eq!(chunks[1].0, SchemeX::AnyTLS);
        assert_eq!(chunks[1].1.as_ref(), "Anytls://x");
    }
}
