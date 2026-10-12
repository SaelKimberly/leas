//! Typed per-core server-config and client-param builders. Both core dialects
//! live in one place per protocol; a variant only supplies the security
//! strings (see `variant.rs`).

use std::net::SocketAddr;

use base64::Engine as _;
use leas_proto::proto_spec::ProtocolConfig;
use leas_proto::proto_spec::endpoint::EndpointEssentials;
use ring::rand::SecureRandom as _;
use std::fmt::Write as _;

use super::{CoreKind, Flow, ServerEnv, TlsVariant};
use crate::NativeConnectParams;
use crate::addr::{Host, TargetAddr};

pub const UUID: &str = "00000000-0000-0000-0000-000000000000";
pub const BODY: &str = "hello native core";

// ── REALITY keypair / short-id generation ─────────────────────────────────

/// Generate a fresh REALITY keypair: `(server private key, client `pbk`)`,
/// both base64url-encoded (Xray's `privateKey` encoding).
///
/// ring 0.17 cannot serialize the private half of a generated
/// `EphemeralPrivateKey` (its `bytes()` is test-gated — see the Task 13
/// report, concern 2), so the private key is drawn as 32 raw bytes and the
/// public half is derived with x25519-dalek (the same X25519 math both cores
/// run). The client only ever sees `pbk`; the server inbound needs the raw
/// private key.
#[must_use]
pub fn reality_keypair() -> (String, String) {
    let mut private = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut private)
        .expect("x25519 private key rng");
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    (enc.encode(private), enc.encode(public.as_bytes()))
}

/// A fresh REALITY short id: 8 hex chars (4 random bytes).
#[must_use]
pub fn reality_sid() -> String {
    let mut bytes = [0u8; 4];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("short id rng");
    let mut out = String::with_capacity(8);
    for b in bytes {
        write!(out, "{b:02x}").expect("writing to a String never fails");
    }
    out
}

/// Fresh VLESS `mlkem768x25519plus` account key material.
///
/// Returns `(client encryption, server decryption)` strings sharing one
/// keypair set — an X25519 keypair plus an ML-KEM-768 keypair derived from a
/// random 64-byte FIPS 203 seed (`d || z`, Go `mlkem.NewDecapsulationKey768`'s
/// format). The client string carries the PUBLIC halves (32-B X25519 pub +
/// 1184-B encapsulation key); the server string the PRIVATE halves (32-B
/// X25519 priv + the 64-B seed) — exactly the segment lengths xray's
/// parsers accept (infra/conf/vless.go: 32/1184 outbound, 32/64 inbound).
///
/// Padding: the documented example triplets (first block probability ≥100,
/// min ≥35 per `ParsePadding`); identical on both sides (each side pads its
/// own output from its own spec).
#[must_use]
pub fn mlkem_enc_pair() -> (String, String) {
    const PAD: &str = "100-111-1111.75-0-111.50-0-3333";
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let b64 = |b: &[u8]| URL_SAFE_NO_PAD.encode(b);
    let mut x_priv = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut x_priv)
        .expect("x25519 private key rng");
    let x_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(x_priv));
    let mut seed = [0u8; 64];
    ring::rand::SystemRandom::new()
        .fill(&mut seed)
        .expect("mlkem seed rng");
    let (ek, _) = leas_tls::crypto::mlkem::Mlkem768::keypair_from_seed(&seed);
    let client = format!(
        "mlkem768x25519plus.native.1rtt.{PAD}.{}.{}",
        b64(x_pub.as_bytes()),
        b64(ek.as_bytes())
    );
    let server = format!(
        "mlkem768x25519plus.native.0.{PAD}.{}.{}",
        b64(&x_priv),
        b64(&seed)
    );
    (client, server)
}

/// Inject the VLESS flow name into an inbound server JSON: xray's
/// `settings.clients[0].flow`, sing-box's `users[0].flow`.
///
/// The server validates the flow against the request's wire addon, which
/// is always `xtls-rprx-vision` (the udp443 suffix truncates away at
/// encode time — spec §4.3), so [`Flow::server_str`] is emitted here, not
/// the client-facing [`Flow::as_str`].
fn set_flow(json: &mut serde_json::Value, core: CoreKind, flow: Flow) {
    match core {
        CoreKind::Xray => {
            json["inbounds"][0]["settings"]["clients"][0]["flow"] =
                serde_json::json!(flow.server_str());
        }
        CoreKind::SingBox => {
            json["inbounds"][0]["users"][0]["flow"] = serde_json::json!(flow.server_str());
        }
    }
}

// ── Server configs ────────────────────────────────────────────────────────

/// `VMess` inbound JSON for `core`.
///
/// `security` is the xray user security string (mirrors intent; cosmetic for
/// AEAD); sing-box never receives it. `tls` selects certificate TLS vs
/// REALITY; `network` selects the transport (tcp/ws/grpc/httpupgrade/xhttp/h2).
/// For REALITY the transport runs inside the reality tunnel (xray-core serves
/// reality over raw/grpc/xhttp only; sing-box also over ws).
#[must_use]
pub fn vmess_inbound(
    core: CoreKind,
    env: &ServerEnv,
    security: Option<&str>,
    tls: &dyn TlsVariant,
    network: &str,
) -> String {
    if let Some(private_key) = tls.reality_private_key() {
        let sid = tls
            .reality_sid()
            .expect("reality variant carries a short id");
        return vmess_reality_inbound(core, env, security, tls.sni(), private_key, sid, network);
    }
    // Configs below reference the PEM FILES on disk, not the byte buffers.
    let cert_path = env.tmp.join("server.crt").to_string_lossy().into_owned();
    let key_path = env.tmp.join("server.key").to_string_lossy().into_owned();
    // grpc, xhttp and v2rayhttp ("h2") ride HTTP/2 (need h2 ALPN);
    // ws/httpupgrade upgrade with http/1.1 (the default below).
    let alpn = match network {
        "grpc" | "xhttp" | "h2" => serde_json::json!(["h2"]),
        // xhttp/h3 (SP5): exactly-one ALPN "h3" flips xray's splithttp
        // listener to the QUIC/HTTP-3 mode (hub.go `isH3`).
        "xhttp3" => serde_json::json!(["h3"]),
        _ => serde_json::json!(["http/1.1"]),
    };
    let json = match core {
        CoreKind::Xray => {
            let mut stream = serde_json::json!({
                "network": network,
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        { "certificateFile": cert_path, "keyFile": key_path }
                    ],
                    "alpn": alpn
                }
            });
            if let Some(curves) = tls.curves() {
                stream["tlsSettings"]["curvePreferences"] = serde_json::json!([curves]);
            }
            match network {
                "ws" => {
                    stream["wsSettings"] = serde_json::json!({ "path": "/ws" });
                }
                "grpc" => {
                    stream["grpcSettings"] = serde_json::json!({ "serviceName": "gun" });
                }
                "httpupgrade" => {
                    stream["httpupgradeSettings"] =
                        serde_json::json!({ "path": "/hu", "host": "localhost" });
                }
                // xray's splithttp dialect: network "splithttp" + settings
                // key "splithttpSettings". Server mode defaults to auto
                // (accepts packet-up + stream-up POSTs).
                "xhttp" | "xhttp3" => {
                    stream["network"] = serde_json::json!("splithttp");
                    stream["splithttpSettings"] =
                        serde_json::json!({ "path": "/x", "host": "localhost" });
                }
                // xray-core removed the h2 transport in 26.x — these rows
                // are sing-box single-core, so this arm is unreachable; a
                // loud panic beats emitting a broken config.
                "h2" => panic!("h2 (v2rayhttp) transport is sing-box only"),
                // mKCP: network "kcp" is already set by the template; an
                // empty kcpSettings exercises the server's getter defaults
                // (mtu 1350, tti 50, … — spec §4.5) exactly like omitting
                // the key.
                "kcp" => {
                    stream["kcpSettings"] = serde_json::json!({});
                }
                _ => {}
            }
            serde_json::json!({
                "inbounds": [{
                    "listen": "127.0.0.1", "port": env.port, "protocol": "vmess",
                    "settings": { "clients": [{
                        "id": UUID,
                        "security": security.unwrap_or("aes-128-gcm")
                    }] },
                    "streamSettings": stream
                }],
                "outbounds": [{ "protocol": "freedom" }]
            })
        }
        CoreKind::SingBox => {
            let mut inbound = serde_json::json!({
                "type": "vmess", "listen": "127.0.0.1", "listen_port": env.port,
                "users": [{ "uuid": UUID }],
                "tls": { "enabled": true, "certificate_path": cert_path, "key_path": key_path,
                    "alpn": alpn }
            });
            if let Some(curves) = tls.curves() {
                inbound["tls"]["curve_preferences"] = serde_json::json!([curves]);
            }
            match network {
                "ws" => {
                    inbound["transport"] = serde_json::json!({ "type": "ws", "path": "/ws" });
                }
                "grpc" => {
                    inbound["transport"] =
                        serde_json::json!({ "type": "grpc", "service_name": "gun" });
                }
                "httpupgrade" => {
                    inbound["transport"] = serde_json::json!({
                        "type": "httpupgrade", "path": "/hu", "host": "localhost"
                    });
                }
                // v2rayhttp: sing-box `type: http`, the h2 single-stream
                // tunnel (xray-core dropped the h2 transport in 26.x).
                "h2" => {
                    inbound["transport"] = serde_json::json!({
                        "type": "http", "path": "/h2", "host": "localhost"
                    });
                }
                _ => {}
            }
            serde_json::json!({
                "log": { "level": "warn" },
                "inbounds": [inbound],
                "outbounds": [{ "type": "direct" }]
            })
        }
    };
    serde_json::to_string(&json).expect("vmess server config serializes")
}

/// VLESS inbound JSON for `core` (no payload security dimension).
///
/// `flow` selects the VLESS flow control: `Flow::Vision` emits
/// `"flow": "xtls-rprx-vision"` in xray's `settings.clients[0]` /
/// sing-box's `users[0]`, `None` omits it. `tls` selects certificate TLS vs
/// REALITY — or [`NoTls`] for a genuinely plain row (server `streamSettings`
/// without `tlsSettings`, client params without a `security` key); `network`
/// selects the transport (tcp/ws/grpc/httpupgrade/xhttp/h2). For REALITY
/// the transport runs inside the reality tunnel (reality over raw/grpc/xhttp;
/// the ws/httpupgrade reality arms are sing-box-gated).
#[must_use]
pub fn vless_inbound(
    core: CoreKind,
    env: &ServerEnv,
    flow: Option<Flow>,
    tls: &dyn TlsVariant,
    network: &str,
    // The inbound `settings.decryption` value; `None` → `"none"`. The
    // `mlkem768x25519plus` string (pq-enc row) carries the server's
    // PRIVATE key segments (xray-only — sing-box has no VLESS account
    // encryption).
    decryption: Option<&str>,
) -> String {
    if let Some(private_key) = tls.reality_private_key() {
        let sid = tls
            .reality_sid()
            .expect("reality variant carries a short id");
        return vless_reality_inbound(core, env, flow, tls.sni(), private_key, sid, network);
    }
    // Configs below reference the PEM FILES on disk, not the byte buffers.
    let cert_path = env.tmp.join("server.crt").to_string_lossy().into_owned();
    let key_path = env.tmp.join("server.key").to_string_lossy().into_owned();
    // grpc, xhttp and v2rayhttp ("h2") ride HTTP/2 (need h2 ALPN);
    // ws/httpupgrade upgrade with http/1.1 (the default below).
    let alpn = match network {
        "grpc" | "xhttp" | "h2" => serde_json::json!(["h2"]),
        // xhttp/h3 (SP5): exactly-one ALPN "h3" flips xray's splithttp
        // listener to the QUIC/HTTP-3 mode (hub.go `isH3`).
        "xhttp3" => serde_json::json!(["h3"]),
        _ => serde_json::json!(["http/1.1"]),
    };
    let json = match core {
        CoreKind::Xray => {
            // `NoTls` (the kcp_plain row) emits streamSettings WITHOUT
            // tlsSettings — genuinely no security layer, not cert TLS.
            let mut stream = if tls.tls_enabled() {
                serde_json::json!({
                    "network": network,
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [
                            { "certificateFile": cert_path, "keyFile": key_path }
                        ],
                        "alpn": alpn
                    }
                })
            } else {
                serde_json::json!({ "network": network })
            };
            if let Some(curves) = tls.curves() {
                stream["tlsSettings"]["curvePreferences"] = serde_json::json!([curves]);
            }
            match network {
                "ws" => {
                    stream["wsSettings"] = serde_json::json!({ "path": "/ws" });
                }
                "grpc" => {
                    stream["grpcSettings"] = serde_json::json!({ "serviceName": "gun" });
                }
                "httpupgrade" => {
                    stream["httpupgradeSettings"] =
                        serde_json::json!({ "path": "/hu", "host": "localhost" });
                }
                // xray's splithttp dialect: network "splithttp" + settings
                // key "splithttpSettings". Server mode defaults to auto
                // (accepts packet-up + stream-up POSTs).
                "xhttp" | "xhttp3" => {
                    stream["network"] = serde_json::json!("splithttp");
                    stream["splithttpSettings"] =
                        serde_json::json!({ "path": "/x", "host": "localhost" });
                }
                // xray-core removed the h2 transport in 26.x — these rows
                // are sing-box single-core, so this arm is unreachable; a
                // loud panic beats emitting a broken config.
                "h2" => panic!("h2 (v2rayhttp) transport is sing-box only"),
                // mKCP: network "kcp" is already set by the template; an
                // empty kcpSettings exercises the server's getter defaults
                // (mtu 1350, tti 50, … — spec §4.5) exactly like omitting
                // the key.
                "kcp" => {
                    stream["kcpSettings"] = serde_json::json!({});
                }
                _ => {}
            }
            serde_json::json!({
                "inbounds": [{
                    "listen": "127.0.0.1", "port": env.port, "protocol": "vless",
                    "settings": {
                        "clients": [{ "id": UUID }],
                        "decryption": decryption.unwrap_or("none")
                    },
                    "streamSettings": stream
                }],
                "outbounds": [{ "protocol": "freedom" }]
            })
        }
        CoreKind::SingBox => {
            // NoTls: no `tls` object at all — the raw transport stream.
            let mut inbound = if tls.tls_enabled() {
                serde_json::json!({
                    "type": "vless", "listen": "127.0.0.1", "listen_port": env.port,
                    "users": [{ "uuid": UUID }],
                    "tls": { "enabled": true, "certificate_path": cert_path, "key_path": key_path,
                        "alpn": alpn }
                })
            } else {
                serde_json::json!({
                    "type": "vless", "listen": "127.0.0.1", "listen_port": env.port,
                    "users": [{ "uuid": UUID }]
                })
            };
            if let Some(curves) = tls.curves() {
                inbound["tls"]["curve_preferences"] = serde_json::json!([curves]);
            }
            match network {
                "ws" => {
                    inbound["transport"] = serde_json::json!({ "type": "ws", "path": "/ws" });
                }
                "grpc" => {
                    inbound["transport"] =
                        serde_json::json!({ "type": "grpc", "service_name": "gun" });
                }
                "httpupgrade" => {
                    inbound["transport"] = serde_json::json!({
                        "type": "httpupgrade", "path": "/hu", "host": "localhost"
                    });
                }
                // v2rayhttp: sing-box `type: http`, the h2 single-stream
                // tunnel (xray-core dropped the h2 transport in 26.x).
                "h2" => {
                    inbound["transport"] = serde_json::json!({
                        "type": "http", "path": "/h2", "host": "localhost"
                    });
                }
                _ => {}
            }
            serde_json::json!({
                "log": { "level": "warn" },
                "inbounds": [inbound],
                "outbounds": [{ "type": "direct" }]
            })
        }
    };
    let mut json = json;
    if let Some(flow) = flow {
        set_flow(&mut json, core, flow);
    }
    serde_json::to_string(&json).expect("vless server config serializes")
}

/// The REALITY block per core dialect: xray's `streamSettings` object,
/// sing-box's `tls.reality` object. `dest`/`handshake` point at the local
/// TLS echo server — xtls/reality borrows the dest's TLS 1.3 `ServerHello`
/// flight for its own handshake, so a plain-HTTP echo cannot serve as the
/// fallback. (sing-box ≥1.13 nests reality inside `tls`; a top-level
/// `reality` field is rejected with "unknown field".)
fn reality_stream(
    core: CoreKind,
    env: &ServerEnv,
    sni: &str,
    private_key: &str,
    sid: &str,
) -> serde_json::Value {
    match core {
        CoreKind::Xray => serde_json::json!({
            "network": "tcp", "security": "reality",
            "realitySettings": {
                "show": false,
                "dest": format!("{}:{}", env.tls_echo.ip(), env.tls_echo.port()),
                "serverNames": [sni],
                "privateKey": private_key,
                "shortIds": [sid]
            }
        }),
        CoreKind::SingBox => serde_json::json!({
            "enabled": true,
            "server_name": sni,
            "reality": {
                "enabled": true,
                "handshake": {
                    "server": env.tls_echo.ip().to_string(),
                    "server_port": env.tls_echo.port()
                },
                "private_key": private_key,
                "short_id": [sid]
            }
        }),
    }
}

/// VLESS REALITY inbound JSON for `core`. `flow` selects the VLESS flow
/// control (see [`vless_inbound`]). `network` selects the transport
/// declared INSIDE the reality tunnel (tcp/ws/grpc/httpupgrade/xhttp/h2) —
/// reality is the outermost layer, the transport framing runs beneath it.
/// Reality serves over raw/grpc/xhttp; the ws/httpupgrade reality arms are
/// sing-box-gated (xray-core: "REALITY only supports RAW, XHTTP and gRPC").
fn vless_reality_inbound(
    core: CoreKind,
    env: &ServerEnv,
    flow: Option<Flow>,
    sni: &str,
    private_key: &str,
    sid: &str,
    network: &str,
) -> String {
    let mut stream = reality_stream(core, env, sni, private_key, sid);
    let mut transport = None;
    match network {
        "ws" if core == CoreKind::SingBox => {
            transport = Some(serde_json::json!({ "type": "ws", "path": "/ws" }));
        }
        // xray-core refuses reality over httpupgrade ("REALITY only supports
        // RAW, XHTTP and gRPC"), so the httpupgrade reality row runs on
        // sing-box only.
        "httpupgrade" if core == CoreKind::SingBox => {
            transport = Some(serde_json::json!({
                "type": "httpupgrade", "path": "/hu", "host": "localhost"
            }));
        }
        "grpc" => {
            transport = Some(serde_json::json!({ "type": "grpc", "service_name": "gun" }));
            if core == CoreKind::Xray {
                stream["network"] = serde_json::json!("grpc");
                stream["grpcSettings"] = serde_json::json!({ "serviceName": "gun" });
            }
        }
        // xray reality serves splithttp (XHTTP is in its allowlist).
        "xhttp" if core == CoreKind::Xray => {
            stream["network"] = serde_json::json!("splithttp");
            stream["splithttpSettings"] = serde_json::json!({ "path": "/x", "host": "localhost" });
        }
        _ => {}
    }
    let json = match core {
        CoreKind::Xray => serde_json::json!({
            "inbounds": [{
                "listen": "127.0.0.1", "port": env.port, "protocol": "vless",
                "settings": { "clients": [{ "id": UUID }], "decryption": "none" },
                "streamSettings": stream
            }],
            "outbounds": [{ "protocol": "freedom" }]
        }),
        CoreKind::SingBox => {
            let mut inbound = serde_json::json!({
                "type": "vless", "listen": "127.0.0.1", "listen_port": env.port,
                "users": [{ "uuid": UUID }],
                "tls": stream
            });
            if let Some(t) = transport {
                inbound["transport"] = t;
            }
            serde_json::json!({
                "log": { "level": "warn" },
                "inbounds": [inbound],
                "outbounds": [{ "type": "direct" }]
            })
        }
    };
    let mut json = json;
    if let Some(flow) = flow {
        set_flow(&mut json, core, flow);
    }
    serde_json::to_string(&json).expect("vless reality server config serializes")
}

/// `VMess` REALITY inbound JSON for `core`. `network` selects the transport
/// declared INSIDE the reality tunnel (tcp/ws/grpc/xhttp) — reality is the
/// outermost layer, the transport framing runs beneath it. xray-core only
/// accepts reality over raw/grpc/xhttp ("REALITY only supports RAW, XHTTP
/// and gRPC for now"), so xray's reality inbound stays tcp-only for
/// ws/httpupgrade; sing-box serves reality+ws.
fn vmess_reality_inbound(
    core: CoreKind,
    env: &ServerEnv,
    security: Option<&str>,
    sni: &str,
    private_key: &str,
    sid: &str,
    network: &str,
) -> String {
    let mut stream = reality_stream(core, env, sni, private_key, sid);
    let mut transport = None;
    match network {
        "ws" if core == CoreKind::SingBox => {
            transport = Some(serde_json::json!({ "type": "ws", "path": "/ws" }));
        }
        // xray-core refuses reality over httpupgrade ("REALITY only supports
        // RAW, XHTTP and gRPC"), so the httpupgrade reality row runs on
        // sing-box only.
        "httpupgrade" if core == CoreKind::SingBox => {
            transport = Some(serde_json::json!({
                "type": "httpupgrade", "path": "/hu", "host": "localhost"
            }));
        }
        "grpc" => {
            transport = Some(serde_json::json!({ "type": "grpc", "service_name": "gun" }));
            if core == CoreKind::Xray {
                stream["network"] = serde_json::json!("grpc");
                stream["grpcSettings"] = serde_json::json!({ "serviceName": "gun" });
            }
        }
        // xray reality serves splithttp (XHTTP is in its allowlist).
        "xhttp" if core == CoreKind::Xray => {
            stream["network"] = serde_json::json!("splithttp");
            stream["splithttpSettings"] = serde_json::json!({ "path": "/x", "host": "localhost" });
        }
        _ => {}
    }
    let json = match core {
        CoreKind::Xray => serde_json::json!({
            "inbounds": [{
                "listen": "127.0.0.1", "port": env.port, "protocol": "vmess",
                "settings": { "clients": [{
                    "id": UUID,
                    "security": security.unwrap_or("aes-128-gcm")
                }] },
                "streamSettings": stream
            }],
            "outbounds": [{ "protocol": "freedom" }]
        }),
        CoreKind::SingBox => {
            let mut inbound = serde_json::json!({
                "type": "vmess", "listen": "127.0.0.1", "listen_port": env.port,
                "users": [{ "uuid": UUID }],
                "tls": stream
            });
            if let Some(t) = transport {
                inbound["transport"] = t;
            }
            serde_json::json!({
                "log": { "level": "warn" },
                "inbounds": [inbound],
                "outbounds": [{ "type": "direct" }]
            })
        }
    };
    serde_json::to_string(&json).expect("vmess reality server config serializes")
}

// ── Client params ─────────────────────────────────────────────────────────

/// The `security` object for `tls`: `reality` (with pbk/sid) when the
/// variant is REALITY, else plain `tls` with an optional `fp`.
fn client_security(tls: &dyn TlsVariant, network: &str) -> serde_json::Value {
    tls.reality_pbk().map_or_else(
        || plain_client_security(tls, network),
        |pbk| reality_client_security(tls, pbk),
    )
}

/// The plain-TLS client `security` object, with an optional `fp`. ALPN is
/// transport-aware: grpc rides h2, everything else upgrades with http/1.1.
fn plain_client_security(tls: &dyn TlsVariant, network: &str) -> serde_json::Value {
    let alpn = match network {
        "grpc" | "xhttp" | "h2" => "h2",
        // xhttp/h3 (SP5): the h3 ALPN is the QUIC trigger client-side
        // (`http_version` == "3" → `connect_quic`).
        "xhttp3" => "h3",
        // ws and httpupgrade both upgrade over HTTP/1.1 (the default below).
        _ => "http/1.1",
    };
    let mut security = serde_json::json!({
        "type": "tls", "sni": tls.sni(), "alpn": alpn
    });
    if let Some(fp) = tls.fingerprint() {
        security["fp"] = serde_json::json!(fp);
    }
    if let Some(curves) = tls.curves() {
        security["curves"] = serde_json::json!(curves);
    }
    security
}

/// The REALITY client `security` object: pbk/sid with the Chrome provisioner.
fn reality_client_security(tls: &dyn TlsVariant, pbk: &str) -> serde_json::Value {
    // The client presents its own sid when the variant overrides it (the
    // wrong-sid fallback scenario), else the server's sid.
    let sid = tls
        .reality_client_sid()
        .or_else(|| tls.reality_sid())
        .expect("reality variant carries a short id");
    serde_json::json!({
        "type": "reality",
        "sni": tls.sni(),
        "pbk": pbk,
        "sid": sid,
        "fp": "chrome"
    })
}

/// Native client params dialing a `VMess` listener with payload security `enc`.
///
/// `xhttp_mode` selects the client-side xhttp dialect ("stream-up"; `None` →
/// auto (packet-up, stream-one under reality)) — ignored for non-xhttp networks.
#[must_use]
pub fn client_params_vmess(
    enc: &str,
    port: u16,
    target: SocketAddr,
    tls: &dyn TlsVariant,
    network: &str,
    xhttp_mode: Option<&'static str>,
) -> NativeConnectParams {
    let transport = match network {
        "ws" => serde_json::json!({ "type": "ws", "path": "/ws" }),
        "grpc" => serde_json::json!({ "type": "grpc", "service_name": "gun" }),
        // The proto's `TransportConfig` serde tag is snake_case
        // (`http_upgrade`); `transport_type()` reports the wire name
        // `httpupgrade` that the dispatch arms match on.
        "httpupgrade" => {
            serde_json::json!({ "type": "http_upgrade", "path": "/hu", "host": "localhost" })
        }
        // Same snake_case tag for xhttp: the variant parses as `x_http`
        // (wire/type_str name `xhttp`). The xray server dialect is
        // `splithttp`; the CLIENT mode drives the client-side dialect.
        // An explicit mode is passed through; no mode → the key is omitted
        // and the native dial auto-selects (xray `dialer.go`, spec §4.1):
        // no reality → packet-up, reality → stream-one, + download settings
        // → stream-up.
        "xhttp" | "xhttp3" => {
            let mut x = serde_json::json!({
                "type": "x_http", "path": "/x", "host": "localhost"
            });
            if let Some(m) = xhttp_mode {
                x["mode"] = serde_json::json!(m);
            }
            x
        }
        // v2rayhttp: proto `type: http` (the `h2` network string is only
        // for the test rows/dispatch; the wire name is `http`).
        "h2" => serde_json::json!({ "type": "http", "path": "/h2", "host": "localhost" }),
        // mKCP: proto `type: kcp`; all params None → the native dial's
        // spec §4.5 defaults (mtu 1350, tti 50).
        "kcp" => serde_json::json!({ "type": "kcp" }),
        _ => serde_json::json!({ "type": "tcp" }),
    };
    let mut security = client_security(tls, network);
    security["enc"] = serde_json::json!(enc);
    let protocol: ProtocolConfig = serde_json::from_value(serde_json::json!({
        "schema": "Vmess",
        "uuid": UUID,
        "security": security,
        "transport": transport
    }))
    .expect("vmess client config parses");
    let server = EndpointEssentials::new("127.0.0.1", port);
    NativeConnectParams::new(
        protocol,
        server,
        TargetAddr::new(Host::Ip(target.ip()), target.port()),
    )
}

/// Native client params dialing a VLESS listener.
///
/// `flow` selects the VLESS flow control: `Flow::Vision` emits
/// `"flow": "xtls-rprx-vision"` in the outbound (the native client
/// dispatches on `VlessConfig.flow`), `None` omits it. `xhttp_mode` selects
/// the client-side xhttp dialect ("stream-up"; `None` → auto (packet-up,
/// stream-one under reality)) — ignored for non-xhttp networks.
#[must_use]
pub fn client_params_vless(
    port: u16,
    target: SocketAddr,
    flow: Option<Flow>,
    tls: &dyn TlsVariant,
    network: &str,
    xhttp_mode: Option<&'static str>,
) -> NativeConnectParams {
    let transport = match network {
        "ws" => serde_json::json!({ "type": "ws", "path": "/ws" }),
        "grpc" => serde_json::json!({ "type": "grpc", "service_name": "gun" }),
        // The proto's `TransportConfig` serde tag is snake_case
        // (`http_upgrade`); `transport_type()` reports the wire name
        // `httpupgrade` that the dispatch arms match on.
        "httpupgrade" => {
            serde_json::json!({ "type": "http_upgrade", "path": "/hu", "host": "localhost" })
        }
        // Same snake_case tag for xhttp: the variant parses as `x_http`
        // (wire/type_str name `xhttp`). The xray server dialect is
        // `splithttp`; the CLIENT mode drives the client-side dialect.
        // An explicit mode is passed through; no mode → the key is omitted
        // and the native dial auto-selects (xray `dialer.go`, spec §4.1):
        // no reality → packet-up, reality → stream-one, + download settings
        // → stream-up.
        "xhttp" | "xhttp3" => {
            let mut x = serde_json::json!({
                "type": "x_http", "path": "/x", "host": "localhost"
            });
            if let Some(m) = xhttp_mode {
                x["mode"] = serde_json::json!(m);
            }
            x
        }
        // v2rayhttp: proto `type: http` (the `h2` network string is only
        // for the test rows/dispatch; the wire name is `http`).
        "h2" => serde_json::json!({ "type": "http", "path": "/h2", "host": "localhost" }),
        // mKCP: proto `type: kcp`; all params None → the native dial's
        // spec §4.5 defaults (mtu 1350, tti 50).
        "kcp" => serde_json::json!({ "type": "kcp" }),
        _ => serde_json::json!({ "type": "tcp" }),
    };
    let mut protocol_value = serde_json::json!({
        "schema": "Vless",
        "uuid": UUID,
        "transport": transport
    });
    // NoTls omits the `security` key entirely (`SecurityConfig` has no null
    // representation) — the native `wrap` passthrough (`None => Ok(stream)`)
    // leaves the transport stream raw, so the row is genuinely no-TLS.
    if tls.tls_enabled() {
        protocol_value["security"] = client_security(tls, network);
    }
    if let Some(flow) = flow {
        protocol_value["flow"] = serde_json::json!(flow.as_str());
    }
    let protocol: ProtocolConfig =
        serde_json::from_value(protocol_value).expect("vless client config parses");
    let server = EndpointEssentials::new("127.0.0.1", port);
    NativeConnectParams::new(
        protocol,
        server,
        TargetAddr::new(Host::Ip(target.ip()), target.port()),
    )
}

/// The trojan outbound password shared by the serve-side configs and the
/// client params.
pub const TROJAN_PASSWORD: &str = "trojan-test-password";
/// The classic Shadowsocks password (arbitrary string; both cores derive the
/// key with MD5 `EVP_BytesToKey`).
pub const SS_PASSWORD: &str = "ss-test-password";
/// The 2022-blake3 PSK for the 32-byte key length methods
/// (`2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`): 32 zero
/// bytes, base64.
pub const SS_2022_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// The 2022-blake3 PSK for `2022-blake3-aes-128-gcm` (16-byte key length).
pub const SS_2022_KEY_128: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

/// The password a Shadowsocks row must carry for `method`: the method's key
/// length is fixed by the 2022 spec (16 B AES-128, 32 B AES-256/ChaCha20), so
/// a 2022 row needs a base64 PSK of exactly that length while classic AEAD
/// rows take an arbitrary string.
///
/// An explicit table over the known 2022 names, not a `2022-blake3-` prefix
/// test: an unknown `2022-blake3-*` name must not silently receive a
/// plausible-looking key. It falls through to [`SS_PASSWORD`], which is not a
/// valid PSK, so `password_key` fails closed at connect/gate time.
fn ss_password(method: &str) -> &'static str {
    match method {
        "2022-blake3-aes-128-gcm" => SS_2022_KEY_128,
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => SS_2022_KEY,
        _ => SS_PASSWORD,
    }
}

/// The hysteria2 auth password shared by the server config and client params.
pub const HYSTERIA2_AUTH: &str = "hy2-test-auth-token";
/// The salamander obfuscation PSK (≥4 bytes) for the obfs row.
pub const HYSTERIA2_OBFS_PSK: &str = "obfs-shared-secret";

/// Trojan inbound JSON for `core` (`protocol`/`type` "trojan", password
/// `clients[0]`/`users[0]`, `tls`/`streamSettings` per dialect).
#[must_use]
pub fn trojan_inbound(core: CoreKind, env: &ServerEnv, network: &str) -> String {
    let cert_path = env.tmp.join("server.crt").to_string_lossy().into_owned();
    let key_path = env.tmp.join("server.key").to_string_lossy().into_owned();
    let alpn = match network {
        "grpc" => serde_json::json!(["h2"]),
        _ => serde_json::json!(["http/1.1"]),
    };
    let json = match core {
        CoreKind::Xray => {
            let mut stream = serde_json::json!({
                "network": network,
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        { "certificateFile": cert_path, "keyFile": key_path }
                    ],
                    "alpn": alpn
                }
            });
            match network {
                "ws" => {
                    stream["wsSettings"] = serde_json::json!({ "path": "/ws" });
                }
                "grpc" => {
                    stream["grpcSettings"] = serde_json::json!({ "serviceName": "gun" });
                }
                "httpupgrade" => {
                    stream["httpupgradeSettings"] =
                        serde_json::json!({ "path": "/hu", "host": "localhost" });
                }
                _ => {}
            }
            serde_json::json!({
                "inbounds": [{
                    "listen": "127.0.0.1", "port": env.port, "protocol": "trojan",
                    "settings": { "clients": [{ "password": TROJAN_PASSWORD }] },
                    "streamSettings": stream
                }],
                "outbounds": [{ "protocol": "freedom" }]
            })
        }
        CoreKind::SingBox => {
            let mut inbound = serde_json::json!({
                "type": "trojan", "listen": "127.0.0.1", "listen_port": env.port,
                "users": [{ "password": TROJAN_PASSWORD }],
                "tls": { "enabled": true, "certificate_path": cert_path, "key_path": key_path,
                    "alpn": alpn }
            });
            match network {
                "ws" => {
                    inbound["transport"] = serde_json::json!({ "type": "ws", "path": "/ws" });
                }
                "grpc" => {
                    inbound["transport"] =
                        serde_json::json!({ "type": "grpc", "service_name": "gun" });
                }
                "httpupgrade" => {
                    inbound["transport"] = serde_json::json!({
                        "type": "httpupgrade", "path": "/hu", "host": "localhost"
                    });
                }
                _ => {}
            }
            serde_json::json!({
                "log": { "level": "warn" },
                "inbounds": [inbound],
                "outbounds": [{ "type": "direct" }]
            })
        }
    };
    serde_json::to_string(&json).expect("trojan server config serializes")
}

/// Native client params dialing a Trojan listener (TCP stream family; the
/// transport + security ride the uniform pipeline).
#[must_use]
pub fn client_params_trojan(
    port: u16,
    target: SocketAddr,
    tls: &dyn TlsVariant,
    network: &str,
) -> NativeConnectParams {
    let transport = match network {
        "ws" => serde_json::json!({ "type": "ws", "path": "/ws" }),
        "grpc" => serde_json::json!({ "type": "grpc", "service_name": "gun" }),
        "httpupgrade" => {
            serde_json::json!({ "type": "http_upgrade", "path": "/hu", "host": "localhost" })
        }
        _ => serde_json::json!({ "type": "tcp" }),
    };
    let mut protocol_value = serde_json::json!({
        "schema": "Trojan",
        "password": TROJAN_PASSWORD,
        "transport": transport
    });
    if tls.tls_enabled() {
        protocol_value["security"] = client_security(tls, network);
    }
    let protocol: ProtocolConfig =
        serde_json::from_value(protocol_value).expect("trojan client config parses");
    let server = EndpointEssentials::new("127.0.0.1", port);
    NativeConnectParams::new(
        protocol,
        server,
        TargetAddr::new(Host::Ip(target.ip()), target.port()),
    )
}

/// Hysteria2 inbound JSON — sing-box only (xray-core has no hysteria2
/// inbound). `obfs` enables Salamander when `Some(password)`.
#[must_use]
pub fn hysteria2_inbound(env: &ServerEnv, obfs: Option<&str>) -> String {
    let cert_path = env.tmp.join("server.crt").to_string_lossy().into_owned();
    let key_path = env.tmp.join("server.key").to_string_lossy().into_owned();
    let mut inbound = serde_json::json!({
        "type": "hysteria2", "listen": "127.0.0.1", "listen_port": env.port,
        "users": [{ "password": HYSTERIA2_AUTH }],
        "tls": { "enabled": true, "certificate_path": cert_path, "key_path": key_path }
    });
    if let Some(psk) = obfs {
        inbound["obfs"] = serde_json::json!({ "type": "salamander", "password": psk });
    }
    let json = serde_json::json!({
        "log": { "level": "warn" },
        "inbounds": [inbound],
        "outbounds": [{ "type": "direct" }]
    });
    serde_json::to_string(&json).expect("hysteria2 server config serializes")
}

/// Native client params dialing a Hysteria2 listener (QUIC dial; requires
/// TLS — hysteria2 has no no-TLS mode). `obfs` enables Salamander.
#[must_use]
pub fn client_params_hysteria2(
    port: u16,
    target: SocketAddr,
    obfs: Option<&'static str>,
) -> NativeConnectParams {
    let mut protocol_value = serde_json::json!({
        "schema": "Hysteria2",
        "auth": HYSTERIA2_AUTH,
        "security": { "tls": { "enabled": true, "insecure": false } }
    });
    if let Some(psk) = obfs {
        protocol_value["obfs"] = serde_json::json!("salamander");
        protocol_value["obfs_password"] = serde_json::json!(psk);
    }
    let protocol: ProtocolConfig =
        serde_json::from_value(protocol_value).expect("hysteria2 client config parses");
    let server = EndpointEssentials::new("127.0.0.1", port);
    NativeConnectParams::new(
        protocol,
        server,
        TargetAddr::new(Host::Ip(target.ip()), target.port()),
    )
}

/// Shadowsocks inbound JSON for `core`.
///
/// The password is method-derived ([`ss_password`]): classic AEAD rows take
/// [`SS_PASSWORD`], 2022 rows a base64 PSK of exactly the method's key length.
/// `udp` widens xray's `settings.network` to `tcp,udp` (the default is
/// TCP-only); sing-box serves both by default. `tls` adds the stream/TLS layer
/// — xray only: sing-box 1.13's shadowsocks inbound has no `tls` field
/// (`inbounds[0].tls: json: unknown field "tls"`), so a TLS SS row is
/// single-cored to xray (see `tests/shadowsocks.rs`).
#[must_use]
pub fn ss_inbound(
    core: CoreKind,
    env: &ServerEnv,
    tls: &dyn TlsVariant,
    network: &str,
    method: &str,
    udp: bool,
) -> String {
    let cert_path = env.tmp.join("server.crt").to_string_lossy().into_owned();
    let key_path = env.tmp.join("server.key").to_string_lossy().into_owned();
    let password = ss_password(method);
    let alpn = match network {
        "grpc" => serde_json::json!(["h2"]),
        _ => serde_json::json!(["http/1.1"]),
    };
    let json = match core {
        CoreKind::Xray => {
            let mut stream = serde_json::json!({ "network": network });
            if tls.tls_enabled() {
                stream["security"] = serde_json::json!("tls");
                stream["tlsSettings"] = serde_json::json!({
                    "certificates": [
                        { "certificateFile": cert_path, "keyFile": key_path }
                    ],
                    "alpn": alpn
                });
            }
            serde_json::json!({
                "inbounds": [{
                    "listen": "127.0.0.1", "port": env.port, "protocol": "shadowsocks",
                    "settings": {
                        "method": method,
                        "password": password,
                        "network": if udp { "tcp,udp" } else { "tcp" }
                    },
                    "streamSettings": stream
                }],
                "outbounds": [{ "protocol": "freedom" }]
            })
        }
        CoreKind::SingBox => {
            let mut inbound = serde_json::json!({
                "type": "shadowsocks", "listen": "127.0.0.1", "listen_port": env.port,
                "method": method, "password": password
            });
            if tls.tls_enabled() {
                inbound["tls"] = serde_json::json!({
                    "enabled": true,
                    "certificate_path": cert_path,
                    "key_path": key_path,
                    "alpn": alpn
                });
            }
            serde_json::json!({
                "log": { "level": "warn" },
                "inbounds": [inbound],
                "outbounds": [{ "type": "direct" }]
            })
        }
    };
    serde_json::to_string(&json).expect("shadowsocks server config serializes")
}

/// Native client params dialing a Shadowsocks listener.
///
/// `SsConfig` has no transport field: the row is a plain TCP dial, plus the
/// optional TLS layer the chain applies when `tls.tls_enabled()` (the SS UDP
/// relay dials the server's own UDP port, so a UDP row never carries a
/// security layer — `ss::udp::connect_udp` refuses one).
#[must_use]
pub fn client_params_ss(
    port: u16,
    target: SocketAddr,
    tls: &dyn TlsVariant,
    network: &str,
    method: &str,
) -> NativeConnectParams {
    let mut protocol_value = serde_json::json!({
        "schema": "Ss",
        "method": method,
        "password": ss_password(method)
    });
    if tls.tls_enabled() {
        protocol_value["security"] = client_security(tls, network);
    }
    let protocol: ProtocolConfig =
        serde_json::from_value(protocol_value).expect("ss client config parses");
    let server = EndpointEssentials::new("127.0.0.1", port);
    NativeConnectParams::new(
        protocol,
        server,
        TargetAddr::new(Host::Ip(target.ip()), target.port()),
    )
}

#[cfg(test)]
mod tests {
    use super::super::harness::generate_certs;
    use super::super::variant::{FingerprintTls, NoTls, RealityTls, StandardTls};
    use super::*;
    use leas_proto::proto_spec::{ProtoSpec, SecurityConfig};
    use rstest::rstest;

    /// The boxed TLS input the `client_params_security_per_tls_variant` table
    /// carries, so one case list can hold the heterogeneous fixtures
    /// (`RealityTls::fresh`, `FingerprintTls`, `StandardTls`, `NoTls`).
    type Tls = Box<dyn TlsVariant>;

    #[test]
    fn reality_keypair_round_trips() {
        let (private, pbk) = reality_keypair();
        let priv_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&private)
            .unwrap();
        let pbk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&pbk)
            .unwrap();
        assert_eq!(priv_bytes.len(), 32);
        assert_eq!(pbk_bytes.len(), 32);
        // The public key must be the X25519 of the private key (base point).
        let expected = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
            <[u8; 32]>::try_from(priv_bytes.as_slice()).unwrap(),
        ));
        assert_eq!(expected.as_bytes().as_slice(), pbk_bytes.as_slice());
    }

    #[test]
    fn reality_sid_is_8_hex_chars() {
        let sid = reality_sid();
        assert_eq!(sid.len(), 8);
        assert!(sid.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn reality_inbound_serializes_per_core_dialect() {
        let tls = RealityTls::fresh();
        let env = ServerEnv {
            port: 12345,
            certs: &generate_certs(),
            tmp: std::path::Path::new("/tmp"),
            echo: "127.0.0.1:9999".parse().unwrap(),
            tls_echo: "127.0.0.1:9443".parse().unwrap(),
            inner_tls_echo: None,
            udp_echo: None,
        };
        let xray: serde_json::Value = serde_json::from_str(&vless_inbound(
            CoreKind::Xray,
            &env,
            None,
            &tls,
            "tcp",
            None,
        ))
        .unwrap();
        let settings = &xray["inbounds"][0]["streamSettings"]["realitySettings"];
        assert_eq!(settings["show"], false);
        assert_eq!(settings["dest"], "127.0.0.1:9443");
        assert_eq!(settings["serverNames"][0], "localhost");
        assert_eq!(settings["privateKey"], tls.reality_private_key().unwrap());
        assert_eq!(settings["shortIds"][0], tls.reality_sid().unwrap());

        let sing: serde_json::Value = serde_json::from_str(&vless_inbound(
            CoreKind::SingBox,
            &env,
            None,
            &tls,
            "tcp",
            None,
        ))
        .unwrap();
        let tls_block = &sing["inbounds"][0]["tls"];
        let reality = &tls_block["reality"];
        assert_eq!(tls_block["server_name"], "localhost");
        assert_eq!(reality["enabled"], true);
        assert_eq!(reality["handshake"]["server"], "127.0.0.1");
        assert_eq!(reality["handshake"]["server_port"], 9443);
        assert_eq!(reality["private_key"], tls.reality_private_key().unwrap());
        assert_eq!(reality["short_id"][0], tls.reality_sid().unwrap());
    }

    /// Every `TlsVariant` drives the client `security` object: REALITY carries
    /// the server's pbk/sid, the fingerprint engine sets `fp`, stock TLS leaves
    /// it unset, and `NoTls` omits the object entirely.
    #[rstest]
    #[case::reality(Box::new(RealityTls::fresh()) as Tls, Some("reality"), None)]
    #[case::fingerprint(Box::new(FingerprintTls("chrome")) as Tls, Some("tls"), Some("chrome"))]
    #[case::standard(Box::new(StandardTls) as Tls, Some("tls"), None)]
    #[case::no_tls(Box::new(NoTls) as Tls, None, None)]
    fn client_params_security_per_tls_variant(
        #[case] tls: Tls,
        #[case] expected_type: Option<&str>,
        #[case] expected_fp: Option<&str>,
    ) {
        let target = "1.2.3.4:80".parse().unwrap();
        // `NoTls` omits the `security` key entirely, so the object is absent;
        // every other variant carries its own security object (kcp vs tcp does
        // not matter for the non-reality ALPN dialect here).
        let network = if tls.tls_enabled() { "tcp" } else { "kcp" };
        let params = client_params_vless(12345, target, None, &*tls, network, None);
        let sec = params.protocol.security();
        assert_eq!(sec.and_then(SecurityConfig::type_str), expected_type);
        assert_eq!(sec.and_then(SecurityConfig::fp), expected_fp);
        // REALITY carries the server's pbk/sid pair (the client consumes it).
        if expected_type == Some("reality") {
            let sec = sec.expect("reality params carry a security object");
            assert_eq!(sec.pbk(), tls.reality_pbk());
            assert_eq!(sec.sid(), tls.reality_sid());
        }
    }

    #[test]
    fn client_params_xhttp_mode_drives_dialect() {
        use crate::context::LinkContext;

        let target = "1.2.3.4:80".parse().unwrap();
        let dest = TargetAddr::new(Host::Domain("dest.test".into()), 80);
        let mode_of = |params: NativeConnectParams| {
            LinkContext::new(params, dest.clone())
                .transport_xhttp()
                .and_then(|c| c.mode.as_deref())
                .map(str::to_string)
        };
        // Default (None) → the mode key is omitted (the native dial
        // auto-selects: packet-up, stream-one under reality); an explicit
        // mode passes through.
        let packet = client_params_vless(12345, target, None, &StandardTls, "xhttp", None);
        assert_eq!(mode_of(packet).as_deref(), None);
        let stream = client_params_vless(
            12345,
            target,
            None,
            &StandardTls,
            "xhttp",
            Some("stream-up"),
        );
        assert_eq!(mode_of(stream).as_deref(), Some("stream-up"));
    }

    #[test]
    fn xhttp3_emits_h3_alpn_both_sides_and_dispatches_quic() {
        use crate::transport::xhttp::http_version;

        // Server: xray splithttp listener with exactly-one ALPN "h3" → the
        // QUIC/HTTP-3 mode (hub.go isH3; no quic_settings needed).
        let env = ServerEnv {
            port: 12345,
            certs: &generate_certs(),
            tmp: std::path::Path::new("/tmp"),
            echo: "127.0.0.1:9999".parse().unwrap(),
            tls_echo: "127.0.0.1:9443".parse().unwrap(),
            inner_tls_echo: None,
            udp_echo: None,
        };
        let server: serde_json::Value = serde_json::from_str(&vless_inbound(
            CoreKind::Xray,
            &env,
            None,
            &StandardTls,
            "xhttp3",
            None,
        ))
        .unwrap();
        assert_eq!(
            server["inbounds"][0]["streamSettings"]["network"],
            "splithttp"
        );
        assert_eq!(
            server["inbounds"][0]["streamSettings"]["tlsSettings"]["alpn"],
            serde_json::json!(["h3"])
        );

        // Client: xhttp transport + the h3 ALPN → the QUIC dispatch decision.
        let target = "1.2.3.4:80".parse().unwrap();
        let params = client_params_vless(12345, target, None, &StandardTls, "xhttp3", None);
        assert_eq!(params.protocol.transport_type(), Some("xhttp"));
        let sec = params.protocol.security().unwrap();
        assert_eq!(sec.alpn(), Some("h3"));
        assert_eq!(http_version(Some(sec)), "3");
    }

    /// A `Flow::Vision` row lands the flow in xray's `settings.clients[0].flow`.
    #[test]
    fn vless_flow_in_xray_clients() {
        let env = ServerEnv {
            port: 12345,
            certs: &generate_certs(),
            tmp: std::path::Path::new("/tmp"),
            echo: "127.0.0.1:9999".parse().unwrap(),
            tls_echo: "127.0.0.1:9443".parse().unwrap(),
            inner_tls_echo: None,
            udp_echo: None,
        };
        let xray: serde_json::Value = serde_json::from_str(&vless_inbound(
            CoreKind::Xray,
            &env,
            Some(Flow::Vision),
            &StandardTls,
            "tcp",
            None,
        ))
        .unwrap();
        assert_eq!(
            xray["inbounds"][0]["settings"]["clients"][0]["flow"],
            "xtls-rprx-vision"
        );
    }

    /// The same row lands the flow in sing-box's `users[0].flow`.
    #[test]
    fn vless_flow_in_sing_box_users() {
        let env = ServerEnv {
            port: 12345,
            certs: &generate_certs(),
            tmp: std::path::Path::new("/tmp"),
            echo: "127.0.0.1:9999".parse().unwrap(),
            tls_echo: "127.0.0.1:9443".parse().unwrap(),
            inner_tls_echo: None,
            udp_echo: None,
        };
        let sing: serde_json::Value = serde_json::from_str(&vless_inbound(
            CoreKind::SingBox,
            &env,
            Some(Flow::Vision),
            &StandardTls,
            "tcp",
            None,
        ))
        .unwrap();
        assert_eq!(sing["inbounds"][0]["users"][0]["flow"], "xtls-rprx-vision");
    }

    /// The REALITY inbound carries the flow too.
    #[test]
    fn vless_flow_in_reality_inbound() {
        let env = ServerEnv {
            port: 12345,
            certs: &generate_certs(),
            tmp: std::path::Path::new("/tmp"),
            echo: "127.0.0.1:9999".parse().unwrap(),
            tls_echo: "127.0.0.1:9443".parse().unwrap(),
            inner_tls_echo: None,
            udp_echo: None,
        };
        let reality = RealityTls::fresh();
        let xray_reality: serde_json::Value = serde_json::from_str(&vless_inbound(
            CoreKind::Xray,
            &env,
            Some(Flow::Vision),
            &reality,
            "tcp",
            None,
        ))
        .unwrap();
        assert_eq!(
            xray_reality["inbounds"][0]["settings"]["clients"][0]["flow"],
            "xtls-rprx-vision"
        );
    }

    /// Client JSON: the flow reaches the native client's `VlessConfig`.
    #[test]
    fn vless_flow_in_client_params() {
        let target = "1.2.3.4:80".parse().unwrap();
        let params =
            client_params_vless(12345, target, Some(Flow::Vision), &StandardTls, "tcp", None);
        let ProtocolConfig::Vless(vless) = &params.protocol else {
            panic!("expected a vless client config");
        };
        assert_eq!(vless.flow.as_deref(), Some("xtls-rprx-vision"));
    }

    #[test]
    fn udp443_flow_server_truncates_client_full() {
        let env = ServerEnv {
            port: 12345,
            certs: &generate_certs(),
            tmp: std::path::Path::new("/tmp"),
            echo: "127.0.0.1:9999".parse().unwrap(),
            tls_echo: "127.0.0.1:9443".parse().unwrap(),
            inner_tls_echo: None,
            udp_echo: None,
        };
        let target = "1.2.3.4:80".parse().unwrap();

        // Server JSON: the udp443 suffix is client-side only — the server
        // validates the request's wire addon (`xtls-rprx-vision`, the
        // truncated form — spec §4.3), so both cores get the truncated
        // flow (xray clients[] / sing-box users[]).
        for core in [CoreKind::Xray, CoreKind::SingBox] {
            let server: serde_json::Value = serde_json::from_str(&vless_inbound(
                core,
                &env,
                Some(Flow::Udp443),
                &StandardTls,
                "tcp",
                None,
            ))
            .unwrap();
            let flow = &server["inbounds"][0]["settings"]["clients"][0]["flow"];
            let flow_sing = &server["inbounds"][0]["users"][0]["flow"];
            let emitted = match core {
                CoreKind::Xray => flow,
                CoreKind::SingBox => flow_sing,
            };
            assert_eq!(emitted, "xtls-rprx-vision");
        }

        // Client JSON: the native client's VlessConfig keeps the full
        // udp443 name — connect_udp dispatches on it (mux-forced XUDP).
        let params =
            client_params_vless(12345, target, Some(Flow::Udp443), &StandardTls, "tcp", None);
        let ProtocolConfig::Vless(vless) = &params.protocol else {
            panic!("expected a vless client config");
        };
        assert_eq!(vless.flow.as_deref(), Some("xtls-rprx-vision-udp443"));
    }

    #[test]
    fn vless_flow_omitted_when_none() {
        let env = ServerEnv {
            port: 12345,
            certs: &generate_certs(),
            tmp: std::path::Path::new("/tmp"),
            echo: "127.0.0.1:9999".parse().unwrap(),
            tls_echo: "127.0.0.1:9443".parse().unwrap(),
            inner_tls_echo: None,
            udp_echo: None,
        };
        let target = "1.2.3.4:80".parse().unwrap();

        // Neither xray's clients[0] nor sing-box's users[0] carry a flow key.
        for core in [CoreKind::Xray, CoreKind::SingBox] {
            let server: serde_json::Value =
                serde_json::from_str(&vless_inbound(core, &env, None, &StandardTls, "tcp", None))
                    .unwrap();
            assert!(server["inbounds"][0]["settings"]["clients"][0]["flow"].is_null());
            assert!(server["inbounds"][0]["users"][0]["flow"].is_null());
        }

        let params = client_params_vless(12345, target, None, &StandardTls, "tcp", None);
        let ProtocolConfig::Vless(vless) = &params.protocol else {
            panic!("expected a vless client config");
        };
        assert!(vless.flow.is_none());
    }

    #[test]
    fn no_tls_inbound_has_no_security_layer() {
        // The kcp_plain row's server config must be GENUINELY no-TLS: xray
        // streamSettings without `security`/`tlsSettings`, sing-box without
        // a `tls` object — not cert TLS in disguise.
        let env = ServerEnv {
            port: 12345,
            certs: &generate_certs(),
            tmp: std::path::Path::new("/tmp"),
            echo: "127.0.0.1:9999".parse().unwrap(),
            tls_echo: "127.0.0.1:9443".parse().unwrap(),
            inner_tls_echo: None,
            udp_echo: None,
        };
        let xray: serde_json::Value = serde_json::from_str(&vless_inbound(
            CoreKind::Xray,
            &env,
            None,
            &NoTls,
            "kcp",
            None,
        ))
        .unwrap();
        let stream = &xray["inbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "kcp");
        assert!(stream.get("security").is_none());
        assert!(stream.get("tlsSettings").is_none());
        assert!(stream.get("kcpSettings").is_some());

        let sing: serde_json::Value = serde_json::from_str(&vless_inbound(
            CoreKind::SingBox,
            &env,
            None,
            &NoTls,
            "kcp",
            None,
        ))
        .unwrap();
        let inbound = &sing["inbounds"][0];
        assert!(inbound.get("tls").is_none());
        assert!(inbound["users"][0]["uuid"].is_string());
    }

    #[test]
    fn ss_password_matches_the_method_key_length() {
        // Classic rows take an arbitrary string (MD5 EVP_BytesToKey); a 2022
        // row's PSK must decode to exactly the method's key length — any
        // other length is a fatal `password_key` error in the connect path.
        let len = |pw: &str| {
            base64::engine::general_purpose::STANDARD
                .decode(pw)
                .map(|b| b.len())
        };
        assert_eq!(ss_password("aes-128-gcm"), SS_PASSWORD);
        assert_eq!(ss_password("xchacha20-ietf-poly1305"), SS_PASSWORD);
        assert_eq!(len(ss_password("2022-blake3-aes-128-gcm")), Ok(16));
        assert_eq!(len(ss_password("2022-blake3-aes-256-gcm")), Ok(32));
        assert_eq!(len(ss_password("2022-blake3-chacha20-poly1305")), Ok(32));
        // Fail-closed, not prefix-matched: an unknown 2022 name does NOT get
        // a plausible 32-byte PSK — it gets the non-base64 classic password,
        // so `password_key` refuses it.
        assert_eq!(ss_password("2022-blake3-aes-192-gcm"), SS_PASSWORD);
    }

    /// Plain TCP row, xray dialect: `settings.{method,password,network}` and a
    /// streamSettings WITHOUT a security layer.
    #[test]
    fn ss_xray_inbound_omits_the_security_layer() {
        let env = ServerEnv {
            port: 12345,
            certs: &generate_certs(),
            tmp: std::path::Path::new("/tmp"),
            echo: "127.0.0.1:9999".parse().unwrap(),
            tls_echo: "127.0.0.1:9443".parse().unwrap(),
            inner_tls_echo: None,
            udp_echo: None,
        };
        let xray: serde_json::Value = serde_json::from_str(&ss_inbound(
            CoreKind::Xray,
            &env,
            &NoTls,
            "tcp",
            "aes-128-gcm",
            false,
        ))
        .unwrap();
        let settings = &xray["inbounds"][0]["settings"];
        assert_eq!(settings["method"], "aes-128-gcm");
        assert_eq!(settings["password"], SS_PASSWORD);
        assert_eq!(settings["network"], "tcp");
        let stream = &xray["inbounds"][0]["streamSettings"];
        assert!(stream.get("security").is_none());
        assert!(stream.get("tlsSettings").is_none());
    }

    /// Plain TCP row, sing-box dialect: the same values top-level and no `tls`
    /// object.
    #[test]
    fn ss_sing_box_inbound_takes_the_values_top_level() {
        let env = ServerEnv {
            port: 12345,
            certs: &generate_certs(),
            tmp: std::path::Path::new("/tmp"),
            echo: "127.0.0.1:9999".parse().unwrap(),
            tls_echo: "127.0.0.1:9443".parse().unwrap(),
            inner_tls_echo: None,
            udp_echo: None,
        };
        let sing: serde_json::Value = serde_json::from_str(&ss_inbound(
            CoreKind::SingBox,
            &env,
            &NoTls,
            "tcp",
            "aes-128-gcm",
            false,
        ))
        .unwrap();
        let inbound = &sing["inbounds"][0];
        assert_eq!(inbound["type"], "shadowsocks");
        assert_eq!(inbound["method"], "aes-128-gcm");
        assert_eq!(inbound["password"], SS_PASSWORD);
        assert!(inbound.get("tls").is_none());
    }

    /// Client params parse as an Ss config: the method/password pair and the
    /// omitted-vs-present `security` key.
    #[test]
    fn ss_client_params_round_trip_the_security_key() {
        let target = "1.2.3.4:80".parse().unwrap();
        let params = client_params_ss(12345, target, &NoTls, "tcp", "2022-blake3-aes-256-gcm");
        match &params.protocol {
            ProtocolConfig::Ss(cfg) => {
                assert_eq!(cfg.method.as_str(), "2022-blake3-aes-256-gcm");
                assert_eq!(cfg.password, SS_2022_KEY);
                assert!(cfg.security.is_empty());
            }
            other => panic!("expected an Ss config, got {other:?}"),
        }
        let tls_params = client_params_ss(12345, target, &StandardTls, "tcp", "aes-128-gcm");
        match &tls_params.protocol {
            ProtocolConfig::Ss(cfg) => {
                assert_eq!(cfg.security.type_str(), Some("tls"));
            }
            other => panic!("expected an Ss config, got {other:?}"),
        }
    }

    /// The UDP row widens ONLY xray's `network` to `tcp,udp` (sing-box serves
    /// both networks by default) and the 2022 method carries its PSK.
    #[test]
    fn ss_udp_row_widens_only_xray_network() {
        let env = ServerEnv {
            port: 12345,
            certs: &generate_certs(),
            tmp: std::path::Path::new("/tmp"),
            echo: "127.0.0.1:9999".parse().unwrap(),
            tls_echo: "127.0.0.1:9443".parse().unwrap(),
            inner_tls_echo: None,
            udp_echo: None,
        };
        let udp: serde_json::Value = serde_json::from_str(&ss_inbound(
            CoreKind::Xray,
            &env,
            &NoTls,
            "tcp",
            "2022-blake3-aes-256-gcm",
            true,
        ))
        .unwrap();
        assert_eq!(udp["inbounds"][0]["settings"]["network"], "tcp,udp");
        assert_eq!(udp["inbounds"][0]["settings"]["password"], SS_2022_KEY);
        // sing-box is UDP-capable by default and carries no `network` field.
        let sing: serde_json::Value = serde_json::from_str(&ss_inbound(
            CoreKind::SingBox,
            &env,
            &NoTls,
            "tcp",
            "2022-blake3-aes-256-gcm",
            true,
        ))
        .unwrap();
        assert!(sing["inbounds"][0].get("network").is_none());
    }
}
