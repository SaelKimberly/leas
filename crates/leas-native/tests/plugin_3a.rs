//! **Tier 3a — the differential**: does a real second implementation emit the same
//! framing ours does?
//!
//! One direction only, because only one exists: sing-box is a plugin **client**
//! (`Plugin` is `DialContext` only, `transport/sip003/plugin.go:15-17`, and its SS
//! inbound has no plugin field), so it cannot be a server we dial. Both clients are
//! pointed at the same **recording peer** — a plain TCP listener that keeps whatever
//! bytes arrive — and the two streams are compared.
//!
//! **The comparison is structural, and spec §9 tier 3a says why a raw diff cannot
//! pass.** From the captures this row produced:
//!
//! - the ws `Sec-WebSocket-Key` is random, so it is masked;
//! - **our** client sends a *payload-less* `New` (option `00`, no data) and puts the SS
//!   handshake in a following `Keep`/`Data` frame, while **sing-box** packs the handshake
//!   *into* its `New` (option `01`, `data_len` 81) — so the frame count, the frame
//!   lengths and the `option` byte all differ on a correct pair and none is compared;
//! - the mux target's *port* differs (ours 9527, sing-box 666) though the domain
//!   `v1.mux.cool` is the same, so the port is masked and the domain is not;
//! - the SS ciphertext has a fresh random salt per connection, so its bytes are not
//!   comparable — only its *length*, via the summed `data_len` (81 on both sides).
//!
//! The recording peer is a real WebSocket peer (`accept_hdr_async`): both clients
//! block until a valid `101` arrives, so a peer that only read would capture the
//! head and nothing else — and tungstenite validates `Sec-WebSocket-Accept`, so the
//! accept header has to be right. Its callback is also how the head is captured, and
//! the messages it then yields are already unmasked (client frames are masked with a
//! random key, so a raw byte diff would compare two random masks).
//!
//! `Stream::next` would come from `futures-util`, which this crate does not depend
//! on; rather than add a dependency (and re-cut the hakari hack) for one `next`,
//! the poll is driven inline — six lines, in the test that needs it.
//!
//! Opt-in and operator-supplied, like tier 3b: `#[ignore]`d, and it needs
//! `LEAS_CORE_BIN_DIR` to hold a `sing-box`, whose **version is asserted into the
//! failure messages** so a green run names which implementation it compared.
#![allow(clippy::future_not_send)]
#![cfg(feature = "native-e2e")]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use leas_native::NativeConnectParams;
use leas_native::addr::{Host, TargetAddr};
use leas_proto::proto_spec::common::SecurityConfig;
use leas_proto::proto_spec::endpoint::EndpointEssentials;
use leas_proto::proto_spec::{PluginSpec, ProtocolConfig, SsConfig};

const METHOD: &str = "aes-256-gcm";
const PASSWORD: &str = "hunter2";
/// Identical on both sides, or the row compares two different conversations
/// (sing-box would otherwise default `host=cloudfront.com`, `path=/`).
const HOST: &str = "cdn.example";
const PATH: &str = "/kpnzyxsj";

fn core_bin_dir() -> PathBuf {
    let dir = std::env::var("LEAS_CORE_BIN_DIR").unwrap_or_else(|_| {
        panic!("LEAS_CORE_BIN_DIR is not set — 3a needs an operator-supplied sing-box")
    });
    PathBuf::from(dir)
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

/// A recording **WebSocket peer**: completes the upgrade, then records what arrives.
///
/// Completing it is not incidental — both clients block until a valid `101` arrives
/// (tungstenite validates `Sec-WebSocket-Accept` against the `Sec-WebSocket-Key` it
/// sent), so a peer that only reads would capture the head and nothing else, and the
/// frame comparison below could never run. `accept_hdr_async` is the tool that fits:
/// its callback hands us the request *before* the handshake completes (that is the
/// head capture) and lets tungstenite compute the accept header, and the messages it
/// then yields are already unmasked — which matters, because client frames are masked
/// with a random 4-byte key and a raw byte diff would compare two random masks.
async fn recorder() -> (u16, tokio::task::JoinHandle<(Vec<String>, Vec<Vec<u8>>)>) {
    use std::sync::{Arc, Mutex};

    use futures_core::Stream as _;
    use tokio_tungstenite::tungstenite::Message;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind recorder");
    let port = listener.local_addr().expect("addr").port();
    let handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let head: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&head);
        // `accept_hdr_async`'s callback error type is tungstenite's large enum, and this
        // callback never fails; boxing it to satisfy the lint would obscure the shape.
        #[allow(clippy::result_large_err)]
        let accepted = tokio_tungstenite::accept_hdr_async(
            socket,
            move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                  resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                let request_line = format!("{} {}", req.method(), req.uri());
                // Header NAMES are compared case-insensitively and the lines are
                // SORTED, because neither property is on the wire: HTTP defines both
                // as insignificant, the plugin server (gorilla) reads them
                // case-insensitively, and the two clients legitimately differ on both
                // — our request goes through `http::HeaderMap`, which lowercases a
                // standard name, and sing-box's `sagernet/ws` emits the upgrade pair
                // in the other order. Normalizing here is what keeps the comparator
                // from inviting a "fix" to our client that the wire does not require.
                let mut headers: Vec<String> = req
                    .headers()
                    .iter()
                    .map(|(name, value)| {
                        let name = name.as_str().to_ascii_lowercase();
                        if name == "sec-websocket-key" {
                            format!("{name}: <masked>")
                        } else {
                            format!("{name}: {}", value.to_str().unwrap_or("<binary>"))
                        }
                    })
                    .collect();
                headers.sort();
                let mut lines = vec![request_line];
                lines.extend(headers);
                if let Ok(mut slot) = sink.lock() {
                    *slot = lines;
                }
                // The callback never fails; its error type is the response type, and
                // naming it inline keeps the closure's `Err` from being inferred large.
                Ok::<_, tokio_tungstenite::tungstenite::handshake::server::ErrorResponse>(resp)
            },
        )
        .await;
        let Ok(mut ws) = accepted else {
            return (Vec::new(), Vec::new());
        };
        let mut payloads = Vec::new();
        // Both clients send their head and first frames, then wait for a reply this
        // peer never sends — so the idle bound, not EOF, ends the read.
        // `Stream::next` comes from `futures_util`, which this crate does not depend
        // on, so the poll is driven directly.
        loop {
            let polled = tokio::time::timeout(
                Duration::from_millis(400),
                std::future::poll_fn(|cx| std::pin::Pin::new(&mut ws).poll_next(cx)),
            )
            .await;
            if let Ok(Some(Ok(Message::Binary(bytes)))) = polled {
                payloads.push(bytes.to_vec());
            } else if polled.is_err() || matches!(polled, Ok(None)) {
                // An idle timeout or a clean end.
                break;
            } else if matches!(polled, Ok(Some(Err(_)))) {
                break;
            }
            if payloads.len() > 8 {
                break;
            }
        }
        let head = head.lock().map(|h| h.clone()).unwrap_or_default();
        (head, payloads)
    });
    (port, handle)
}

/// sing-box's stream: an SS outbound with the same plugin options, driven through
/// its SOCKS inbound.
async fn singbox_stream(singbox: &PathBuf, recorder_port: u16) -> String {
    let socks_port = free_port();
    let config = format!(
        r#"{{
  "log": {{"level": "error"}},
  "inbounds": [{{"type": "socks", "listen": "127.0.0.1", "listen_port": {socks_port}}}],
  "outbounds": [{{
    "type": "shadowsocks",
    "server": "127.0.0.1",
    "server_port": {recorder_port},
    "method": "{METHOD}",
    "password": "{PASSWORD}",
    "plugin": "v2ray-plugin",
    "plugin_opts": "mode=websocket;host={HOST};path={PATH};mux=1"
  }}]
}}"#
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = dir.path().join("config.json");
    std::fs::write(&config_path, &config).expect("write config");

    let version = Command::new(singbox)
        .arg("version")
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .unwrap_or_default();

    let child: Child = Command::new(singbox)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sing-box");
    let mut child = child;

    // Wait for the SOCKS inbound, then drive one connection through it: sing-box
    // dials the recorder with the plugin wrappers.
    let mut connected = false;
    for _ in 0..60 {
        if tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
            .await
            .is_ok()
        {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(connected, "sing-box never listened on its SOCKS inbound");
    if let Ok(mut socks) = tokio::net::TcpStream::connect(("127.0.0.1", socks_port)).await {
        // Minimal SOCKS5 CONNECT; the answer is irrelevant, the dial is the point.
        let _ = socks
            .write_all(&[
                0x05, 0x01, 0x00, // greeting
            ])
            .await;
        let mut reply = [0u8; 64];
        let _ = tokio::time::timeout(Duration::from_millis(500), socks.read(&mut reply)).await;
        let _ = socks
            .write_all(&[
                0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o',
                b'r', b'g', 0x00, 0x50,
            ])
            .await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    version
}

/// What a mux `New` frame exposes that is **comparable across implementations**.
///
/// `[2B meta_len][sid 2B][status 1][option 1][network 1][port 2][addr]…`
///
/// Three fields are deliberately absent:
/// - the **session id** is a per-connection counter (ours starts at 1, sing-box's at 0);
/// - the **target port** is a value no two clients agree on — ours is `v1.mux.cool:9527`
///   (v2ray-plugin's own client), sing-box's is `v1.mux.cool:666`
///   (`vmess.MuxDestination`), mihomo's is `127.0.0.1:0`. Spec §2.4 records that none is
///   wrong, and §7 pins ours; observing a different one is an expected result, never a
///   reason to change our constant;
/// - the **option** byte, because it *follows from the packing difference*: our client
///   emits a payload-less `New` and puts the SS handshake in a following `Keep` frame
///   (`option = None`), while sing-box's wrapper packs the handshake into the `New`
///   itself (`option = Data`). Same bytes on the wire, two frames.
///
/// What is left is the framing class — status, network, and the target's address form
/// and name — which is exactly what a divergence would break.
struct MuxNew {
    status: u8,
    network: u8,
    domain: Option<String>,
}

fn mux_new_frame(payload: &[u8]) -> Option<MuxNew> {
    if payload.len() < 7 {
        return None;
    }
    let meta_len = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
    if payload.len() < 2 + meta_len || meta_len < 7 {
        return None;
    }
    let status = payload[4];
    let network = payload[6];
    let atyp = payload[9];
    let domain = if atyp == 0x02 {
        let len = usize::from(*payload.get(10)?);
        let name = payload.get(11..11 + len)?;
        Some(String::from_utf8_lossy(name).into_owned())
    } else {
        None
    };
    Some(MuxNew {
        status,
        network,
        domain,
    })
}

/// The bytes the mux layer actually **carries**, summed over every frame.
///
/// This is the one measure that survives both documented differences. Raw payload
/// bytes cannot be compared (the SS ciphertext has a fresh random salt per connection),
/// and neither can raw frame bytes or frame counts — our client emits a payload-less
/// `New`, puts the SS handshake in a following `Keep`, and adds an `End` when the
/// session drops, while sing-box packs the handshake into its `New` and stops there.
/// Summing each frame's `data_len` (only for frames whose option carries data) counts
/// the transported payload and nothing else: framing overhead, control frames and the
/// packing difference all fall out.
fn mux_data_total(payloads: &[Vec<u8>]) -> usize {
    let mut total = 0;
    for payload in payloads {
        if payload.len() < 2 {
            continue;
        }
        let meta_len = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
        let Some(meta) = payload.get(2..2 + meta_len) else {
            continue;
        };
        // meta = sid(2) status(1) option(1) [network(1) port(2) addr… when New]
        let Some(option) = meta.get(3) else { continue };
        if option & 0x01 == 0 {
            // No data in this frame (New, End, KeepAlive).
            continue;
        }
        let Some(len_bytes) = payload.get(2 + meta_len..4 + meta_len) else {
            continue;
        };
        total += usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]]));
    }
    total
}

#[tokio::test]
#[ignore = "needs an operator-supplied sing-box in LEAS_CORE_BIN_DIR"]
async fn both_clients_emit_the_same_ws_framing() {
    let dir = core_bin_dir();
    let singbox = dir.join("sing-box");
    assert!(
        singbox.exists(),
        "{} is missing from {}",
        singbox.display(),
        dir.display()
    );

    // Two recorders: each client needs a peer of its own, since each records one stream.
    let (our_port, our_handle) = recorder().await;
    let (their_port, their_handle) = recorder().await;

    let params = NativeConnectParams::new(
        ProtocolConfig::Ss(SsConfig {
            method: METHOD.into(),
            password: PASSWORD.to_string(),
            security: SecurityConfig::default(),
            remarks: None,
            plugin: Some(PluginSpec::from_parts(
                Some("obfs-local"),
                &format!("mode=websocket;host={HOST};path={PATH};mux=1"),
            )),
        }),
        EndpointEssentials::new("127.0.0.1", our_port),
        TargetAddr::new(Host::Domain("example.org".into()), 80),
    );
    // The SAME dispatch the app's inbound uses: a mux-resolved link goes through the
    // mux protocol phase and opens one session. Calling `connect` here would bypass it
    // (the chain has no mux arm) and the recorder would capture a plain SS stream with
    // no mux frame at all — which is what the first run of this row did, and it read as
    // a framing divergence rather than the plumbing mistake it was.
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        let mux = leas_native::connect_mux(&params).await?;
        leas_native::mux_session::open_session(mux, &params.target).await
    })
    .await;
    let (our_head, our_payloads) = our_handle.await.expect("our recorder");

    let version = singbox_stream(&singbox, their_port).await;
    let (their_head, their_payloads) = their_handle.await.expect("their recorder");

    assert!(!our_head.is_empty(), "our client sent no upgrade request");
    assert!(
        !their_head.is_empty(),
        "sing-box sent no upgrade request (version: {version})"
    );
    assert_eq!(
        our_head, their_head,
        "the ws upgrade heads must match with the key masked (sing-box {version})"
    );

    // The frames. AEAD is length-preserving, so the payload TOTAL is comparable even
    // though the ciphertext is not, and it survives the packing difference: our client
    // emits the SS handshake as its own `Keep` frame while sing-box packs it into the
    // `New`. Per-frame lengths are therefore NOT compared — they legitimately differ.
    assert!(!our_payloads.is_empty(), "our client sent no ws frames");
    assert!(
        !their_payloads.is_empty(),
        "sing-box sent no ws frames (version: {version})"
    );
    assert_eq!(
        mux_data_total(&our_payloads),
        mux_data_total(&their_payloads),
        "the mux DATA total must match — the bytes the layer carries, not the framing \
         (sing-box {version})"
    );
    assert!(
        mux_data_total(&our_payloads) > 0,
        "and it must be non-zero, or the measure proves nothing"
    );

    // The first frame's framing class: status New + a TCP network, and the target's
    // address form and name. The port and the session id stay masked (spec §9 tier 3a).
    let ours_new = mux_new_frame(&our_payloads[0]).expect("our first frame is a mux New");
    let theirs_new = mux_new_frame(&their_payloads[0]).expect("their first frame is a mux New");
    assert_eq!(
        ours_new.status, 1,
        "the first frame is a New frame (status 0x01)"
    );
    assert_eq!(
        ours_new.status, theirs_new.status,
        "both clients open with a New frame"
    );
    assert_eq!(
        ours_new.network, 1,
        "ours carries a TCP (network 0x01) target"
    );
    assert_eq!(
        ours_new.network, theirs_new.network,
        "and sing-box's does too"
    );
    assert_eq!(
        ours_new.domain.as_deref(),
        Some("v1.mux.cool"),
        "our target is the pinned v2ray-plugin value"
    );
    assert_eq!(
        ours_new.domain, theirs_new.domain,
        "both clients name the same mux destination (the PORT is the part they disagree on)"
    );
}
