//! Amiabot (Cloudflare) verification sweep over the kept 71-profile roster.
//!
//! For each of the 71 kept profiles (69 `profiles::generated::GENERATED` +
//! the 2 wire-exact hand profiles `chrome_130` / `edge_106`) this drives the
//! engine TLS (`leas_tls::handshake::connect` with the profile's exact
//! `spec!` hello), speaks HTTP/1.1 or HTTP/2 over the resulting `TlsStream`
//! via hyper, and sends a browser-shaped `GET https://amiabot.app/api/check`.
//! The response's `verdict` and `cloudflareBotManagement` score are parsed
//! and one row is printed per profile, plus flags:
//!
//! - `library_user_agent` — amiabot flags the User-Agent as a known library.
//! - `cf>=99` — Cloudflare Bot Management score ≥ 99 (bot-like).
//! - `handshake` — TLS or HTTP handshake failed.
//! - `echo` — the server's header echo does not contain our User-Agent.
//!
//! IP caveat: this host's IP is datacenter/VPN, so amiabot's absolute scores
//! are inflated (~+48 points) regardless of TLS/header fidelity. Compare
//! profiles relatively and prefer the Cloudflare score. See
//! `docs/amiabot-roster-report.md`.
//!
//! Run a single profile:
//! ```text
//! cargo run -p leas-native --example amiabot_sweep -- --sample chrome_130
//! ```
//! Run the full sweep:
//! ```text
//! cargo run -p leas-native --example amiabot_sweep
//! ```

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::{http1, http2};
use hyper::{Method, Request};
use hyper_util::rt::{TokioExecutor, TokioIo};
use leas_native::headers;
use leas_tls::fingerprints::{Browser, Device, Os};
use leas_tls::handshake::{HandshakeParams, connect};
use leas_tls::profiles::generated::{GENERATED, GenEntry};
use leas_tls::spec::{ClientHelloSpec, ExtensionSpec};
use leas_tls::verify::WebPkiVerifier;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const HOST: &str = "amiabot.app";
const PORT: u16 = 443;
const API_PATH: &str = "/api/check";
/// Bounded concurrency across the roster (amiabot throttles under bursts).
const CONCURRENCY: usize = 4;
const TIMEOUT: Duration = Duration::from_secs(15);

/// One sweep result row, printed per profile.
struct Row {
    name: &'static str,
    protocol: &'static str,
    verdict_score: Option<f64>,
    classification: String,
    cf_score: Option<f64>,
    http_protocol: String,
    user_agent_echoed: bool,
    raw: Option<String>,
    flags: Vec<&'static str>,
}

/// The kept 71-profile roster: the 69 generated `GenEntry`s plus the 2
/// wire-exact hand profiles synthesized as `GenEntry`s (mirrors the
/// peet.ws test's `combined_roster`).
fn combined_roster() -> Vec<GenEntry> {
    let mut entries: Vec<GenEntry> = GENERATED.to_vec();
    entries.push(GenEntry {
        name: "chrome_130",
        browser: Browser::Chrome,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 130,
        ja4: "",
        spec_fn: leas_tls::profiles::hand_selected::chrome_130,
    });
    entries.push(GenEntry {
        name: "edge_106",
        browser: Browser::Edge,
        os: Some(Os::Windows),
        device: Device::Desktop,
        major: 106,
        ja4: "",
        spec_fn: leas_tls::profiles::hand_selected::edge_106,
    });
    entries
}

/// The ALPN protocols a profile's `spec!` offers.
fn spec_alpn(spec: &ClientHelloSpec) -> Vec<String> {
    spec.extensions
        .iter()
        .find_map(|e| match e {
            ExtensionSpec::Alpn(protos) => Some(protos.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let sample = args
        .iter()
        .position(|a| a == "--sample")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str);

    let roster = combined_roster();
    let roster: Vec<GenEntry> = match sample {
        Some(name) => roster
            .into_iter()
            .filter(|e| e.name == name || format!("{}@{}", e.browser.name(), e.major) == name)
            .collect(),
        None => roster,
    };
    if roster.is_empty() {
        eprintln!("no profile matches the --sample filter");
        std::process::exit(2);
    }

    // Bounded concurrency with a semaphore + JoinSet (tokio-only; no
    // futures-util dependency needed).
    let sem = Arc::new(Semaphore::new(CONCURRENCY));
    let mut set: JoinSet<Row> = JoinSet::new();
    for entry in roster {
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem
                .acquire_owned()
                .await
                .expect("semaphore closed while sweep running");
            // One retry on transient failure (timeout / throttling).
            match sweep_one(entry).await {
                Ok(row) => row,
                Err(e) => match sweep_one(entry).await {
                    Ok(row) => row,
                    Err(e2) => Row {
                        name: entry.name,
                        protocol: "err",
                        verdict_score: None,
                        classification: String::new(),
                        cf_score: None,
                        http_protocol: String::new(),
                        user_agent_echoed: false,
                        raw: Some(format!("{e}; retry: {e2}")),
                        flags: vec!["handshake"],
                    },
                },
            }
        });
    }

    let mut rows: Vec<Row> = Vec::new();
    while let Some(res) = set.join_next().await {
        match res {
            Ok(row) => rows.push(row),
            Err(e) => eprintln!("sweep task panicked: {e}"),
        }
    }
    rows.sort_by_key(|r| r.name);

    println!(
        "profile\tproto\tclassification\tverdict_score\tcf_score\thttp_protocol\tua_echo\tflags"
    );
    for r in &rows {
        let classification = if r.classification.is_empty() {
            "-"
        } else {
            &r.classification
        };
        let verdict = r
            .verdict_score
            .map_or_else(|| "-".to_string(), |s| format!("{s:.1}"));
        let http_proto = if r.http_protocol.is_empty() {
            "-"
        } else {
            &r.http_protocol
        };
        let cf = r
            .cf_score
            .map_or_else(|| "-".to_string(), |s| format!("{s:.1}"));
        let flags = if r.flags.is_empty() {
            "-".to_string()
        } else {
            r.flags.join(",")
        };
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            r.name, r.protocol, classification, verdict, cf, http_proto, r.user_agent_echoed, flags,
        );
    }
    for r in rows.iter().filter(|r| r.raw.is_some()) {
        eprintln!("(raw error for {}: {})", r.name, r.raw.as_deref().unwrap());
    }
}

/// Build the browser-shaped `GET /api/check` request for a profile.
fn build_request(
    hdrs: &headers::HeadersFor,
) -> Result<Request<Empty<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(format!("https://{HOST}{API_PATH}"))
        .header("host", HOST)
        .header("user-agent", &hdrs.user_agent)
        .header("accept", hdrs.accept)
        .header("accept-language", hdrs.accept_language)
        .header("sec-fetch-site", hdrs.sec_fetch_site)
        .header("sec-fetch-mode", hdrs.sec_fetch_mode)
        .header("sec-fetch-user", hdrs.sec_fetch_user)
        .header("sec-fetch-dest", hdrs.sec_fetch_dest)
        .header("upgrade-insecure-requests", "1");
    if let Some(scu) = &hdrs.sec_ch_ua {
        req = req.header("sec-ch-ua", scu);
    }
    Ok(req.body(Empty::<Bytes>::new())?)
}

/// One full round-trip for a roster entry: TLS connect (exact profile
/// hello) → HTTP/1.1 or HTTP/2 → `GET /api/check` → parse verdict.
async fn sweep_one(entry: GenEntry) -> Result<Row, Box<dyn std::error::Error + Send + Sync>> {
    let spec = (entry.spec_fn)();
    let use_h2 = spec_alpn(&spec).iter().any(|p| p == "h2");
    let os = entry.os.unwrap_or(Os::Windows);
    let hdrs = headers::for_identity(entry.browser, os, entry.device, entry.major);

    // amiabot (Cloudflare) responds to a `compress_certificate` offer with a
    // cert-less server flight (EncryptedExtensions, NewSessionTicket,
    // CertificateVerify, Finished — no Certificate), which no client can
    // consume. Strip the extension for the sweep so every kept profile
    // completes the handshake and yields a verdict; the engine still
    // decompresses RFC 8879 certs from servers that do send them. See
    // `docs/amiabot-roster-report.md` §Limitations.
    let mut spec = spec;
    spec.extensions
        .retain(|e| !matches!(e, ExtensionSpec::CompressCertificate(_)));

    let tcp = TcpStream::connect((HOST, PORT)).await?;
    let verifier = WebPkiVerifier::webpki_roots();
    let stream = connect(
        tcp,
        HandshakeParams {
            spec: &spec,
            server_name: HOST,
            alpn: None,
            verifier: &verifier,
            rng: &ring::rand::SystemRandom::new(),
        },
    )
    .await?;

    let io = TokioIo::new(stream);
    let req = build_request(&hdrs)?;

    // Both branches produce `hyper::Response<Incoming>`, so the shared body
    // read below is uniform. HTTP/2 applies the profile family's SETTINGS;
    // HTTP/1.1 has none.
    let resp = if use_h2 {
        let (sw, cw, mhl) = headers::h2_settings(entry.browser);
        let (mut sender, conn) = http2::Builder::new(TokioExecutor::new())
            .initial_stream_window_size(sw)
            .initial_connection_window_size(cw)
            .max_header_list_size(mhl)
            .handshake(io)
            .await?;
        tokio::spawn(conn);
        tokio::time::timeout(TIMEOUT, sender.send_request(req))
            .await
            .map_err(|_| "amiabot h2 request timed out")??
    } else {
        let (mut sender, conn) = http1::Builder::new().handshake(io).await?;
        tokio::spawn(conn);
        tokio::time::timeout(TIMEOUT, sender.send_request(req))
            .await
            .map_err(|_| "amiabot h1 request timed out")??
    };

    let raw: Bytes = tokio::time::timeout(TIMEOUT, async {
        let collected = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("amiabot body collect failed: {e}"))?;
        Ok::<_, String>(collected.to_bytes())
    })
    .await
    .map_err(|_| "amiabot body read timed out")??;

    let json: serde_json::Value = serde_json::from_slice(&raw)?;

    let verdict = &json["verdict"];
    let reasons: Vec<String> = verdict["reasons"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r["id"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    // Cloudflare Bot Management score lives under `server` in amiabot's
    // response; `server.httpProtocol` is present when the server echoes the
    // negotiated protocol.
    let cf_score = json["server"]["cloudflareBotManagement"]["score"]
        .as_f64()
        .or_else(|| json["cloudflareBotManagement"]["score"].as_f64())
        .or_else(|| json["server"]["cf"]["cloudflareBotManagement"]["score"].as_f64());
    let http_protocol = json["server"]["httpProtocol"]
        .as_str()
        .or_else(|| json["server"]["headerNames"]["httpProtocol"].as_str())
        .unwrap_or_default()
        .to_string();
    let echo_has_ua = json["server"]["headers"].as_object().is_some_and(|m| {
        m.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("user-agent")
                && v.as_str().is_some_and(|s| s.contains(&hdrs.user_agent))
        })
    });

    let mut flags: Vec<&'static str> = Vec::new();
    if reasons.iter().any(|r| r == "library_user_agent") {
        flags.push("library_user_agent");
    }
    if cf_score.is_some_and(|s| s >= 99.0) {
        flags.push("cf>=99");
    }
    if !echo_has_ua {
        flags.push("echo");
    }

    Ok(Row {
        name: entry.name,
        protocol: if use_h2 { "h2" } else { "h1" },
        verdict_score: verdict["score"].as_f64(),
        classification: verdict["classification"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        cf_score,
        http_protocol,
        user_agent_echoed: echo_has_ua,
        raw: None,
        flags,
    })
}
