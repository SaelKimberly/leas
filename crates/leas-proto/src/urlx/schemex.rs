use std::{borrow::Cow, str::FromStr, sync::LazyLock};

use aho_corasick::AhoCorasick;

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
        static SCHEMA_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .match_kind(aho_corasick::MatchKind::LeftmostFirst)
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
                .expect("valid AhoCorasick patterns")
        });

        let mut last = None;

        let mut chunks = Vec::new();
        for m in SCHEMA_AC.find_iter(s) {
            let schema_area = s
                .get(m.range())
                .expect("AhoCorasick range should be valid")
                .split_once("://")
                .expect("schema pattern always contains ://")
                .0;
            let Ok(schema) = Self::from_str(schema_area);

            if let Some((schema, begin)) = last.replace((schema, m.range().start)) {
                let end = m.range().start;
                chunks.push((
                    schema,
                    Cow::Borrowed(
                        s.get(begin..end)
                            .expect("contiguous range from AhoCorasick"),
                    ),
                ));
            }
        }

        if let Some((schema, begin)) = last.take() {
            chunks.push((
                schema,
                Cow::Borrowed(s.get(begin..).expect("remaining range from AhoCorasick")),
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
    use super::*;

    #[test]
    fn test_slice_input() {
        let input = include_str!("/home/user/oss/sub-healer/v2ray.txt");

        let chunks = SchemeX::slice_input(input);
        for (schema, c) in &chunks {
            let c = c.lines().collect::<Vec<_>>().join("");
            eprintln!("{schema:>15}| {c}");
        }
        eprintln!("Total: {}", chunks.len());
    }
}
