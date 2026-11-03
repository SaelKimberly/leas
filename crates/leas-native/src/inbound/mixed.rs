//! Mixed inbound: one listener speaking both SOCKS5 and HTTP CONNECT.
//!
//! The first byte selects the protocol, as in xray-core's `mixed` inbound and
//! sing-box's `TypeMixed`: a SOCKS5 greeting starts with `0x05`, while an HTTP
//! request starts with an ASCII method token, so every non-SOCKS5 byte goes to
//! the HTTP CONNECT parser. SOCKS4 (`0x04`) is not spoken by this client.
//!
//! The listener is bound at the SOCKS config's `listen` address; the HTTP
//! config's `listen` is overwritten with it. Each side keeps its own config, so
//! authentication and trace kind follow the protocol actually negotiated.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

use super::Socks5InboundConfig;
use super::http::{self, HttpInboundConfig};
use super::socks5;
use super::{absorb_accept_error, warn_if_open_relay};
use crate::error::{NativeError, timeouts};

/// A bound mixed (SOCKS5 + HTTP CONNECT) server.
pub struct MixedInbound {
    listener: TcpListener,
    socks: Arc<Socks5InboundConfig>,
    http: Arc<HttpInboundConfig>,
}

impl MixedInbound {
    /// Binds the listener; call [`Self::serve`] to accept connections.
    ///
    /// # Errors
    /// Returns [`NativeError::Io`] when the listen address cannot be bound.
    pub async fn bind(
        socks: Socks5InboundConfig,
        mut http: HttpInboundConfig,
    ) -> Result<Self, NativeError> {
        let listener = TcpListener::bind(socks.listen).await?;
        http.listen = socks.listen;
        // Warn unless BOTH faces demand credentials: either face without auth
        // makes the port an open relay.
        warn_if_open_relay(
            &listener,
            socks.auth.is_some() && http.auth.is_some(),
            "mixed inbound",
        );
        Ok(Self {
            listener,
            socks: Arc::new(socks),
            http: Arc::new(http),
        })
    }

    /// The bound local address (useful when listening on port 0).
    ///
    /// # Errors
    /// Returns [`NativeError::Io`] when the kernel reports no local address.
    pub fn local_addr(&self) -> Result<SocketAddr, NativeError> {
        self.listener.local_addr().map_err(NativeError::Io)
    }

    /// Runs the accept loop forever, spawning one task per connection.
    ///
    /// Returns when the SOCKS config's `shutdown` receiver fires (the native
    /// session wires the same receiver into both sides).
    ///
    /// # Errors
    /// Never fails today — every `accept` error is absorbed and retried, so the
    /// loop ends only on shutdown.
    pub async fn serve(self) -> Result<(), NativeError> {
        loop {
            let accept = self.listener.accept();
            let accepted = match &self.socks.shutdown {
                Some(rx) => {
                    let mut rx = rx.clone();
                    tokio::select! {
                        biased;
                        _ = rx.changed() => return Ok(()),
                        accepted = accept => accepted,
                    }
                }
                None => accept.await,
            };
            let (conn, peer) = match accepted {
                Ok(pair) => pair,
                Err(error) => {
                    absorb_accept_error(&error, "mixed inbound").await;
                    continue;
                }
            };
            if let Err(error) = conn.set_nodelay(true) {
                tracing::debug!(%peer, %error, "mixed inbound: set_nodelay failed");
            }
            let socks = Arc::clone(&self.socks);
            let http = Arc::clone(&self.http);
            let shutdown = socks.shutdown.clone();
            tokio::spawn(async move {
                let handle = handle_conn(socks, http, conn, peer);
                match shutdown {
                    Some(rx) => {
                        let mut rx = rx;
                        tokio::select! {
                            biased;
                            _ = rx.changed() => {}
                            result = handle => {
                                if let Err(error) = result {
                                    tracing::debug!(%peer, %error, "mixed inbound: connection closed");
                                }
                            }
                        }
                    }
                    None => {
                        if let Err(error) = handle.await {
                            tracing::debug!(%peer, %error, "mixed inbound: connection closed");
                        }
                    }
                }
            });
        }
    }
}

impl fmt::Debug for MixedInbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MixedInbound")
            .field("listen", &self.listener.local_addr().ok())
            .finish_non_exhaustive()
    }
}

/// Peek the first byte without consuming it, then hand the whole stream to the
/// matching protocol handler.
async fn handle_conn(
    socks: Arc<Socks5InboundConfig>,
    http: Arc<HttpInboundConfig>,
    conn: TcpStream,
    peer: SocketAddr,
) -> Result<(), NativeError> {
    let mut first = [0u8; 1];
    let read = tokio::time::timeout(timeouts::PROTOCOL, conn.peek(&mut first))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "mixed protocol sniff",
            limit: timeouts::PROTOCOL,
        })??;
    if read == 0 {
        // Peer closed before sending anything (health-check style probe).
        return Ok(());
    }
    if first[0] == socks5::VERSION {
        super::handle_conn(socks, conn, peer).await
    } else {
        http::handle_conn(http, conn, peer).await
    }
}
