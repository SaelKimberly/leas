/// Protocol security ranking (lower = more secure = shown first).
#[must_use]
pub fn protocol_security_rank(proto_kind: &str) -> u8 {
    match proto_kind {
        "wireguard" => 0,
        "vmess" => 1,
        "vless" => 2,
        "trojan" => 3,
        "ss-2022" => 4,
        "ss" => 5,
        "hysteria2" => 6,
        "tuic" => 7,
        "hysteria" => 8,
        "anytls" => 9,
        "shadowtls" => 10,
        "naive" => 11,
        "socks" => 12,
        "http" => 13,
        "ssr" => 14,
        _ => 255,
    }
}
