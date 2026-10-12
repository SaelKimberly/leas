use futures_util::StreamExt;
use std::io;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Kinds of speed tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestType {
    TcpPing,
    RealPing,
    SpeedTest,
    UdpTest,
}

#[derive(Error, Debug)]
pub enum SpeedTestError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Timeout after {0:?}")]
    Timeout(Duration),
    #[error("Proxy error: {0}")]
    Proxy(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
}

/// TCP ping: measure time to complete TCP handshake with `addr:port`.
/// Connects directly (not through proxy). Timeout applied.
pub async fn tcp_ping(
    addr: &str,
    port: u16,
    test_timeout: Duration,
) -> Result<Duration, SpeedTestError> {
    let start = std::time::Instant::now();
    match timeout(test_timeout, TcpStream::connect((addr, port))).await {
        Ok(Ok(_)) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(SpeedTestError::Io(e)),
        Err(_) => Err(SpeedTestError::Timeout(test_timeout)),
    }
}

/// Direct UDP ping: send a probe to `addr:port`, measure time to any response.
/// Uses raw UDP (not through proxy). Timeout applied.
/// Good for WireGuard endpoints, ShadowsocksR, and other UDP-based protocols.
pub async fn udp_ping(
    addr: &str,
    port: u16,
    test_timeout: Duration,
) -> Result<Duration, SpeedTestError> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect((addr, port)).await?;

    let start = std::time::Instant::now();
    socket.send(&[0u8]).await?;

    let mut buf = [0u8; 64];
    match timeout(test_timeout, socket.recv(&mut buf)).await {
        Ok(Ok(_)) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(SpeedTestError::Io(e)),
        Err(_) => Err(SpeedTestError::Timeout(test_timeout)),
    }
}

use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;

type ClientCacheInner = HashMap<(String, u16, bool, bool), reqwest::Client>;

static CLIENT_CACHE: LazyLock<Mutex<ClientCacheInner>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Reset the client cache — exposed for testing.
#[doc(hidden)]
pub fn reset_client_cache() {
    if let Ok(mut cache) = CLIENT_CACHE.lock() {
        cache.clear();
    }
}

/// Create a `reqwest::Client` with SOCKS5 proxy configured, using a cache to
/// avoid per-call connection pool creation overhead. The cache key includes
/// the redirect policy: probe clients use `Policy::none()` (a redirecting
/// probe URL must not silently follow), fetch clients use the default policy.
async fn create_socks5_client(
    proxy: &str,
    port: u16,
    socks5h: bool,
    timeout: Duration,
) -> Result<reqwest::Client, SpeedTestError> {
    create_socks5_client_with_policy(proxy, port, socks5h, timeout, false).await
}

async fn create_socks5_client_with_policy(
    proxy: &str,
    port: u16,
    socks5h: bool,
    timeout: Duration,
    no_redirects: bool,
) -> Result<reqwest::Client, SpeedTestError> {
    crate::ensure_tls_provider();
    let key = (proxy.to_string(), port, socks5h, no_redirects);
    if let Some(client) = CLIENT_CACHE.lock().unwrap().get(&key) {
        return Ok(client.clone()); // Client::clone() is cheap (Arc)
    }
    let scheme = if socks5h { "socks5h" } else { "socks5" };
    let proxy_url = format!("{scheme}://{proxy}:{port}");
    let mut builder = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy_url).map_err(|e| SpeedTestError::Proxy(e.to_string()))?)
        .timeout(timeout);
    if no_redirects {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }
    let client = builder.build().map_err(SpeedTestError::Http)?;
    CLIENT_CACHE.lock().unwrap().insert(key, client.clone());
    Ok(client)
}

/// Speed test: download `url` through SOCKS5 proxy, measure throughput.
/// Streams for at least `min_duration` up to `max_duration`.
/// Returns bits per second.
pub async fn speed_test(
    proxy: &str,
    port: u16,
    url: &str,
    min_duration: Duration,
    max_duration: Duration,
) -> Result<u64, SpeedTestError> {
    let client =
        create_socks5_client(proxy, port, true, max_duration + Duration::from_secs(5)).await?;

    let start = std::time::Instant::now();
    let resp = client.get(url).send().await?;
    let resp = resp.error_for_status()?;

    let mut total_bytes: u64 = 0;
    let deadline = start + max_duration;

    // Use streaming to read chunks
    let stream = resp.bytes_stream();
    tokio::pin!(stream);

    while std::time::Instant::now() < deadline {
        match timeout(Duration::from_secs(10), stream.as_mut().next()).await {
            Ok(Some(Ok(chunk))) => {
                total_bytes += chunk.len() as u64;
                // If we've met min duration and have data, we can stop
                if start.elapsed() >= min_duration {
                    break;
                }
            }
            Ok(Some(Err(e))) => return Err(SpeedTestError::Http(e)),
            Ok(None) | Err(_) => break,
        }
    }

    let elapsed = start.elapsed();
    match throughput_bps(total_bytes, elapsed) {
        Some(bps) => Ok(bps),
        None => Err(SpeedTestError::Timeout(max_duration)),
    }
}

/// bits-per-second from bytes and elapsed. Never truncates to whole seconds;
/// a sub-second elapsed with bytes flowing is NOT a timeout.
fn throughput_bps(total_bytes: u64, elapsed: std::time::Duration) -> Option<u64> {
    if total_bytes == 0 {
        return None; // caller maps None -> Timeout
    }
    let secs = elapsed.as_secs_f64().max(0.001);
    Some((total_bytes as f64 * 8.0 / secs) as u64)
}

/// Wrap an I/O future in `timeout`; maps timeout to SpeedTestError::Timeout.
async fn io_timeout<T>(
    timeout: Duration,
    fut: impl Future<Output = std::io::Result<T>>,
) -> Result<T, SpeedTestError> {
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(SpeedTestError::Io(e)),
        Err(_) => Err(SpeedTestError::Timeout(timeout)),
    }
}

/// UDP test: verify UDP forwarding through SOCKS5 proxy via UDP ASSOCIATE.
/// Sends a small DNS-like packet to 1.1.1.1:53 and checks for response.
/// Returns round-trip duration.
pub async fn udp_test(
    proxy: &str,
    port: u16,
    test_timeout: Duration,
) -> Result<Duration, SpeedTestError> {
    // 1. Establish UDP ASSOCIATE via TCP to SOCKS5 proxy
    let proxy_addr = format!("{proxy}:{port}");
    let tcp = timeout(test_timeout, TcpStream::connect(&proxy_addr))
        .await
        .map_err(|_| SpeedTestError::Timeout(test_timeout))??;

    // SOCKS5 handshake: no auth
    let handshake = [5u8, 1, 0]; // VER=5, NMETHODS=1, METHOD=0(no auth)
    let (mut r, mut w) = tcp.into_split();

    io_timeout(test_timeout, w.write_all(&handshake)).await?;
    let mut response = [0u8; 2];
    io_timeout(test_timeout, r.read_exact(&mut response)).await?;
    if response != [5, 0] {
        return Err(SpeedTestError::Proxy("SOCKS5 handshake failed".into()));
    }

    // UDP ASSOCIATE request
    // VER=5, CMD=3(UDP ASSOCIATE), RSV=0, ATYP=1(IPv4), BND.ADDR=0, BND.PORT=0
    let mut req = Vec::with_capacity(10);
    req.extend_from_slice(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
    io_timeout(test_timeout, w.write_all(&req)).await?;

    let mut header = [0u8; 10];
    io_timeout(test_timeout, r.read_exact(&mut header)).await?;
    if header[1] != 0 {
        return Err(SpeedTestError::Proxy(
            "SOCKS5 UDP ASSOCIATE rejected".into(),
        ));
    }

    // Parse relay address from response
    // ATYP=1 => IPv4 (4 bytes addr + 2 bytes port = 6 bytes after header[3])
    // ATYP=4 => IPv6 (16 bytes addr + 2 bytes port = 18 bytes after header[3])
    let atyp = header[3];
    let (relay_addr, relay_port) = if atyp == 1 {
        let ip = std::net::Ipv4Addr::new(header[4], header[5], header[6], header[7]);
        let port = u16::from_be_bytes([header[8], header[9]]);
        (ip.to_string(), port)
    } else if atyp == 4 {
        // Read remaining bytes for full IPv6 response (header is only 10 bytes)
        let mut extra = [0u8; 10];
        io_timeout(test_timeout, r.read_exact(&mut extra)).await?;
        let mut full = [0u8; 20];
        full[..10].copy_from_slice(&header);
        full[10..].copy_from_slice(&extra);
        let ip = std::net::Ipv6Addr::new(
            u16::from_be_bytes([full[4], full[5]]),
            u16::from_be_bytes([full[6], full[7]]),
            u16::from_be_bytes([full[8], full[9]]),
            u16::from_be_bytes([full[10], full[11]]),
            u16::from_be_bytes([full[12], full[13]]),
            u16::from_be_bytes([full[14], full[15]]),
            u16::from_be_bytes([full[16], full[17]]),
            u16::from_be_bytes([full[18], full[19]]),
        );
        let mut port_buf = [0u8; 2];
        io_timeout(test_timeout, r.read_exact(&mut port_buf)).await?;
        let port = u16::from_be_bytes(port_buf);
        (ip.to_string(), port)
    } else {
        return Err(SpeedTestError::Proxy("UDP ASSOCIATE unknown ATYP".into()));
    };

    // 2. Send a DNS query packet through UDP relay
    // DNS query: A record for example.com
    let dns_query: Vec<u8> = vec![
        // DNS header: id=0x1234, flags=0x0100 (standard query), QDCOUNT=1
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Question: example.com (7 letters)
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
        0x01, // QTYPE=A
        0x00, 0x01, // QCLASS=IN
    ];

    // SOCKS5 UDP request header: RSV, FRAG, ATYP, DST.ADDR, DST.PORT
    let mut udp_packet = Vec::with_capacity(dns_query.len() + 16);
    udp_packet.extend_from_slice(&[0, 0, 0]); // RSV=0, FRAG=0
    udp_packet.push(1); // ATYP=1 (IPv4)
    udp_packet.extend_from_slice(&[1, 1, 1, 1]); // 1.1.1.1
    udp_packet.extend_from_slice(&[0, 53]); // port 53
    udp_packet.extend_from_slice(&dns_query);

    // Bind to a local UDP socket and send to the relay address
    let udp_sock = timeout(test_timeout, tokio::net::UdpSocket::bind("0.0.0.0:0"))
        .await
        .map_err(|_| SpeedTestError::Timeout(test_timeout))??;
    io_timeout(
        test_timeout,
        udp_sock.connect((relay_addr.as_str(), relay_port)),
    )
    .await?;

    let test_start = std::time::Instant::now();
    io_timeout(test_timeout, udp_sock.send(&udp_packet)).await?;

    // 3. Wait for response
    let mut buf = vec![0u8; 1500];
    let recv_fut = udp_sock.recv(&mut buf);
    match timeout(test_timeout, recv_fut).await {
        Ok(Ok(n)) if n > 10 => {
            // Got a response — UDP forwarding works
            Ok(test_start.elapsed())
        }
        Ok(Ok(_)) => Err(SpeedTestError::Proxy("UDP response too short".into())),
        Ok(Err(e)) => Err(SpeedTestError::Io(e)),
        Err(_) => Err(SpeedTestError::Timeout(test_timeout)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn io_timeout_maps_elapsed_to_timeout_error() {
        let fut = async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok::<_, std::io::Error>(())
        };
        let result = io_timeout(Duration::from_millis(50), fut).await;
        assert!(matches!(result, Err(SpeedTestError::Timeout(_))));
    }

    #[tokio::test]
    async fn io_timeout_returns_value_when_fast() {
        let fut = async { Ok::<_, std::io::Error>(42u32) };
        let result = io_timeout(Duration::from_millis(100), fut).await;
        assert!(matches!(result, Ok(42)));
    }

    #[tokio::test]
    async fn io_timeout_maps_io_error() {
        let fut = async { Err::<(), _>(std::io::Error::other("boom")) };
        let result = io_timeout(Duration::from_millis(100), fut).await;
        assert!(matches!(result, Err(SpeedTestError::Io(_))));
    }

    #[tokio::test]
    async fn client_cache_reset() {
        reset_client_cache();
        assert!(super::CLIENT_CACHE.lock().unwrap().is_empty());
    }

    #[test]
    fn throughput_uses_fractional_seconds() {
        // 1 MiB in 0.5s → ~16.7 Mbps, NOT a timeout, NOT 2x inflated.
        let bps = throughput_bps(1024 * 1024, Duration::from_millis(500)).unwrap();
        assert!((16_000_000..18_000_000).contains(&bps), "bps={bps}");
        assert!(throughput_bps(0, Duration::from_secs(5)).is_none());
    }
}
