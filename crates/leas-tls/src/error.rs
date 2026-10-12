//! Error types for the TLS engine.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("spec error: {0}")]
    Spec(String),
    #[error("handshake error: {0}")]
    Handshake(String),
    #[error("certificate verification failed: {0}")]
    Verify(String),
    /// The server's certificate does not cover the configured server name.
    ///
    /// Split out of [`Self::Verify`] so a purge decision reads the TYPED cause
    /// instead of parsing the message.
    #[error("certificate verification failed: server name mismatch: {0}")]
    CertNotValidForName(String),
    /// Chain verification failed because a certificate is expired (or not yet
    /// valid). Split out of [`Self::Verify`] for the same reason.
    #[error("certificate verification failed: chain verification failed: {0}")]
    CertExpired(String),
    /// The peer answered in cleartext instead of a TLS record.
    ///
    /// Split out of [`Self::Handshake`]: the diagnosis is a statement about the
    /// endpoint, not a generic handshake failure.
    #[error(
        "handshake error: peer does not speak TLS: it answered in cleartext \
         ({0}) — the endpoint's port or its `security` setting is wrong"
    )]
    CleartextPeer(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("not implemented: {feature}")]
    NotImplemented { feature: String },
    #[error("server sent HelloRetryRequest; retry is not supported")]
    HelloRetryRequest,
    /// REALITY was expected but the server flight was not REALITY-authenticated
    /// — a real certificate (transparent proxy / possible MITM or redirection).
    #[error("REALITY: received real certificate (potential MITM or redirection)")]
    RealityFallback,
}

pub type Result<T> = std::result::Result<T, TlsError>;
