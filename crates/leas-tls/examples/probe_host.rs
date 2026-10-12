//! Live host probe — dial `host:port` with the engine's plain-TLS path and
//! report each attempt's outcome.
//!
//! Tier-2 diagnostic for the one question a hermetic test cannot answer: is a
//! recorded handshake failure the *server's* condition or the *engine's*
//! behaviour? The batch pipeline persists the engine's error text (for example
//! `TLS error: handshake error: record too large: 20527 bytes`); this tool
//! dials the same `host:port` with the same SNI and says whether a handshake
//! succeeds, so a suspect row can be classified without a code change.
//!
//! Two results decided the 2026-09-15 investigation: the batch-time
//! `record too large` / `Finished MAC mismatch` rows handshook 60/60 here
//! afterwards (transient path, not an engine defect — no fix invented), while
//! a TLS-1.2-only host failed 3/3 with `unsupported named curve 0x0017` and
//! was fixed (secp256r1 ECDHE in `handshake::tls12`).
//!
//! ```text
//! cargo run -p leas-tls --example probe_host -- <host> <port> <sni> [attempts] [alpn,list] [--verify]
//! ```
//!
//! Certificate verification is disabled by default (`insecure`): the probe
//! answers "does a handshake complete", not "is the chain trusted" — a proxy
//! server's chain is the operator's business, and a verification failure
//! would hide the handshake outcome this tool exists to observe. Pass
//! `--verify` to run the real `WebPKI` path instead — **required** to re-probe
//! the verify-class failures a batch records (`server presented no
//! certificate`, `chain verification failed`, `server name mismatch`,
//! `invalid leaf certificate`), which `insecure` short-circuits before the
//! chain is ever looked at.

use std::sync::Arc;
use std::time::{Duration, Instant};

use leas_tls::client::{TlsConfig, connect};
use leas_tls::fingerprints::{Browser, Fingerprint};
use leas_tls::verify::WebPkiVerifier;

/// Per-attempt dial + handshake budget.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let verify = args.iter().any(|a| a == "--verify");
    args.retain(|a| a != "--verify");
    if args.len() < 3 {
        eprintln!("usage: probe_host <host> <port> <sni> [attempts] [alpn,list] [--verify]");
        std::process::exit(2);
    }
    let host = args[0].clone();
    let port: u16 = args[1].parse()?;
    let sni = args[2].clone();
    let attempts: usize = args.get(3).map_or(1, |value| value.parse().unwrap_or(1));
    let alpn: Option<Vec<String>> = args
        .get(4)
        .map(|list| list.split(',').map(str::to_string).collect());

    println!("{host}:{port} sni={sni} attempts={attempts} alpn={alpn:?} verify={verify}");
    let mut tasks = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        let (host, sni, alpn) = (host.clone(), sni.clone(), alpn.clone());
        tasks.push(tokio::spawn(async move {
            let stream = match tokio::net::TcpStream::connect((host.as_str(), port)).await {
                Ok(stream) => stream,
                Err(e) => return format!("tcp dial failed: {e}"),
            };
            let verifier = Arc::new(WebPkiVerifier::webpki_roots().with_insecure(!verify));
            let mut config = TlsConfig::plain(
                Some(Fingerprint::default_for(Browser::Chrome)),
                verifier,
                sni,
            );
            config.alpn = alpn.map(|list| list.into_iter().map(String::into_bytes).collect());
            let started = Instant::now();
            match tokio::time::timeout(ATTEMPT_TIMEOUT, connect(stream, &config)).await {
                Ok(Ok(_tls)) => format!("OK in {:?}", started.elapsed()),
                Ok(Err(e)) => format!("FAIL: {e}"),
                Err(_) => format!("TIMEOUT ({ATTEMPT_TIMEOUT:?})"),
            }
        }));
    }

    let mut failures = 0usize;
    for task in tasks {
        match task.await {
            Ok(line) => {
                if !line.starts_with("OK") {
                    failures += 1;
                }
                println!("  {line}");
            }
            Err(e) => {
                failures += 1;
                println!("  task failed: {e}");
            }
        }
    }
    println!("{failures}/{attempts} attempts failed");
    Ok(())
}
