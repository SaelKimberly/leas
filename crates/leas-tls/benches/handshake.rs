//! TLS handshake bench: a full client handshake against a local rustls
//! server, plus an allocation count per connect.
//!
//! The server is a plain blocking `rustls::ServerConnection` loop; the client
//! is the production `leas_tls::client::connect` with the insecure verifier
//! (the handshake path is what is measured, not PKI). Every iteration creates
//! one TCP connection so the number includes resolution, hello build, key
//! schedule and certificate verification.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};
use leas_tls::client::{TlsConfig, connect};
use leas_tls::verify::WebPkiVerifier;

/// Counts allocations so the bench can print one `allocations/connect` row.
struct Counting;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to `System` and only adds an atomic counter.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[allow(
    clippy::needless_pass_by_value,
    reason = "the listener and config move into the accept-loop thread"
)]
fn server(listener: std::net::TcpListener, config: Arc<rustls::ServerConfig>) {
    for sock in listener.incoming() {
        let Ok(mut sock) = sock else { continue };
        let config = Arc::clone(&config);
        std::thread::spawn(move || {
            let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                return;
            };
            while conn.is_handshaking() {
                if conn.complete_io(&mut sock).is_err() {
                    return;
                }
            }
            // Drain whatever the client sends so the socket is not reset
            // mid-handshake, then close.
            let mut buf = [0u8; 512];
            let _ = std::io::Read::read(&mut sock, &mut buf);
        });
    }
}

fn spawn_server() -> std::net::SocketAddr {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(
                certified.cert.der().to_vec(),
            )],
            rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
                .unwrap(),
        )
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || server(listener, Arc::new(config)));
    addr
}

async fn one_connect(addr: std::net::SocketAddr) {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let verifier = Arc::new(WebPkiVerifier::webpki_roots().with_insecure(true));
    let config = TlsConfig::plain(None, verifier, "localhost");
    let tls = connect(tcp, &config).await.unwrap();
    drop(tls);
}

fn benches(c: &mut Criterion) {
    let addr = spawn_server();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    // Warm the path once so lazy statics and the server thread are ready.
    rt.block_on(one_connect(addr));

    ALLOCS.store(0, Ordering::Relaxed);
    rt.block_on(one_connect(addr));
    eprintln!(
        "tls_handshake allocations/connect (process-wide: client + rustls server thread + runtime): {}",
        ALLOCS.load(Ordering::Relaxed)
    );

    let mut group = c.benchmark_group("tls_handshake");
    group.bench_function("plain_chrome", |b| {
        b.iter(|| rt.block_on(one_connect(addr)));
    });
    group.finish();
}

criterion_group!(benches_group, benches);
criterion_main!(benches_group);
