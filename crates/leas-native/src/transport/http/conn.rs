//! Client-connection handshakes over our byte stream. Each spawns the hyper
//! driver task (detached; it ends when the stream/connection closes).

use hyper_util::rt::{TokioExecutor, TokioIo};

use super::body::ReqBody;
use crate::BoxStream;
use crate::error::{NativeError, timeouts};

/// Handshake an HTTP/1.1 client over `stream`.
pub async fn h1_client(
    stream: BoxStream,
) -> Result<hyper::client::conn::http1::SendRequest<ReqBody>, NativeError> {
    let limit = timeouts::TRANSPORT;
    let (sender, conn) = tokio::time::timeout(
        limit,
        hyper::client::conn::http1::handshake(TokioIo::new(stream)),
    )
    .await
    .map_err(|_| NativeError::Timeout {
        step: "http/1.1 handshake",
        limit,
    })?
    .map_err(|e| NativeError::Transport(format!("http/1.1 handshake: {e}")))?;
    // `.with_upgrades()`: the plain `Connection` future treats a 101
    // response as "upgrade handled manually" and never fulfills the
    // `OnUpgrade` extension (hyper: "upgrade expected but low level API in
    // use"). The upgradeable wrapper fulfills it with the raw IO — the
    // httpupgrade transport needs that. Non-upgrade responses behave
    // identically.
    tokio::spawn(conn.with_upgrades());
    Ok(sender)
}

/// Handshake an HTTP/2 client over `stream`.
///
/// `profile` seeds the connection's flow-control windows from the SAME table
/// the TLS identity resolved (`leas_tls::Http2Profile`): a Firefox-shaped
/// hello followed by Chromium window sizes is a cross-layer discontinuity an
/// h2 fingerprint sees.
pub async fn h2_client(
    stream: BoxStream,
) -> Result<hyper::client::conn::http2::SendRequest<ReqBody>, NativeError> {
    h2_client_with(stream, None).await
}

/// [`h2_client`] with an explicit browser profile.
pub async fn h2_client_with(
    stream: BoxStream,
    profile: Option<leas_tls::Http2Profile>,
) -> Result<hyper::client::conn::http2::SendRequest<ReqBody>, NativeError> {
    let limit = timeouts::TRANSPORT;
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    if let Some(p) = profile {
        let _ = builder
            .initial_stream_window_size(Some(p.initial_window_size))
            .initial_connection_window_size(p.connection_window_size);
    }
    let (sender, conn) = tokio::time::timeout(limit, builder.handshake(TokioIo::new(stream)))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "http/2 handshake",
            limit,
        })?
        .map_err(|e| NativeError::Transport(format!("http/2 handshake: {e}")))?;
    tokio::spawn(conn);
    Ok(sender)
}
