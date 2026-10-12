mod adapters;

#[cfg(feature = "quic-ping")]
pub use adapters::QuicPingAdapter;
pub use adapters::{FastPingAdapter, FastPingManager, TcpPingAdapter, UdpPingAdapter};

use std::fmt;

/// The transport used for a fast ping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingCapability {
    Tcp,
    Udp,
    Quic,
    None,
}

impl PingCapability {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Quic => "QUIC",
            Self::None => "\u{2014}",
        }
    }
}

/// A transport failure, carrying the OS facts the classifier needs instead of
/// the sentence the OS happened to render.
///
/// `std::io::Error`'s `Display` is localized — on a Russian Windows it reads
/// `Попытка установить соединение была безуспешной… (os error 10060)`. Any
/// consumer that pattern-matches that text is correct in exactly one locale,
/// so [`kind`] and [`raw_code`] travel with the error and the text is kept
/// only for display.
#[derive(Debug, Clone)]
pub struct IoFailure {
    /// The portable classification, or `None` when no `io::Error` stands behind
    /// this failure (an adapter's own message). `std` already folds the Windows
    /// WSA codes onto it (`WSAETIMEDOUT` → `TimedOut`, `WSAECONNREFUSED` →
    /// `ConnectionRefused`, `WSAEHOSTUNREACH` → `HostUnreachable`,
    /// `WSAENETUNREACH` → `NetworkUnreachable`), so where it is present it is
    /// the primary signal and it means the same thing on every platform.
    pub kind: Option<std::io::ErrorKind>,
    /// The platform's numeric code (`raw_os_error`), when there was one.
    /// Needed for the few failures `std` leaves uncategorized that still have
    /// a decided meaning here — notably Windows' `11001`
    /// (`WSAHOST_NOT_FOUND`, a name that does not resolve). No Unix `errno`
    /// reaches that value, so the code is unambiguous across platforms.
    pub raw_code: Option<i32>,
    /// The rendered message, for logs and the user-facing error text.
    pub text: String,
}

impl IoFailure {
    /// A failure that never came from `std::io` (an adapter's own message).
    /// No `kind` and no code: everything a classifier can key on is absent,
    /// which is exactly when the text is worth reading.
    #[must_use]
    pub fn msg(text: impl Into<String>) -> Self {
        Self {
            kind: None,
            raw_code: None,
            text: text.into(),
        }
    }

    /// Keep the typed facts, label the text with the stage that produced them.
    /// A DNS failure and a socket failure are the same `io::Error` shape; the
    /// stage is only ever in the message, so it is prepended rather than
    /// stored.
    #[must_use]
    pub fn prefixed(mut self, stage: &str) -> Self {
        self.text = format!("{stage}: {}", self.text);
        self
    }
}

impl From<std::io::Error> for IoFailure {
    fn from(e: std::io::Error) -> Self {
        Self {
            kind: Some(e.kind()),
            raw_code: e.raw_os_error(),
            text: e.to_string(),
        }
    }
}

impl fmt::Display for IoFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Error for ping operations.
#[derive(Debug, Clone)]
pub enum PingError {
    /// A transport failure. Typed: see [`IoFailure`].
    Io(IoFailure),
    Timeout(std::time::Duration),
    NotSupported,
    Other(String),
}

impl From<crate::speed_test::SpeedTestError> for PingError {
    fn from(e: crate::speed_test::SpeedTestError) -> Self {
        match e {
            crate::speed_test::SpeedTestError::Timeout(d) => PingError::Timeout(d),
            // The `io::Error` is captured whole here, while it still knows its
            // kind and OS code — this is the one place they are available.
            crate::speed_test::SpeedTestError::Io(e) => PingError::Io(e.into()),
            other => PingError::Other(other.to_string()),
        }
    }
}

impl fmt::Display for PingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO: {e}"),
            Self::Timeout(d) => write!(f, "timeout after {d:?}"),
            Self::NotSupported => write!(f, "not supported by any adapter"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}
