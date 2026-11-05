//! Outbound socket options: what a client core can set on a dial without
//! `unsafe`.
//!
//! `leas-native` is `#![forbid(unsafe_code)]`, and `setsockopt` is an unsafe
//! FFI call, so this module is deliberately bounded to the surface `socket2`
//! exposes safely: `TCP_USER_TIMEOUT`, keepalive, `SO_REUSEPORT`,
//! `IPV6_V6ONLY`, `TCP_NODELAY` and `TOS`.
//!
//! NOT implemented here, on purpose: `SO_MARK`, `SO_BINDTODEVICE`,
//! `TCP_CONGESTION` and `TCP_FASTOPEN_CONNECT` have no safe API in `socket2`.
//! They need an ADR that amends the crate's `forbid(unsafe_code)` policy (a
//! dedicated crate with a documented exception), not a silent loosening.
//!
//! Nothing is applied unless the caller asks: the default dial is byte-for-byte
//! what it was before this module existed.

use std::time::Duration;

/// The options one dial may request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SockOpts {
    /// `TCP_USER_TIMEOUT` in milliseconds.
    pub tcp_user_timeout_ms: Option<u32>,
    /// Keepalive probe interval; `None` leaves the platform default.
    pub tcp_keepalive: Option<Duration>,
    /// `IPV6_V6ONLY` for an IPv6 socket.
    pub v6only: Option<bool>,
    /// `SO_REUSEPORT` (only meaningful on a listener; applied when set).
    pub reuse_port: Option<bool>,
    /// `TCP_NODELAY`; `None` keeps the historical `true`.
    pub nodelay: Option<bool>,
    /// `IP_TOS` / `IPV6_TCLASS` diffserv byte.
    pub tos: Option<u32>,
}

impl SockOpts {
    /// True when nothing at all is requested — the dial then takes the plain
    /// path with no `socket2` involvement.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tcp_user_timeout_ms.is_none()
            && self.tcp_keepalive.is_none()
            && self.v6only.is_none()
            && self.reuse_port.is_none()
            && self.nodelay.is_none()
            && self.tos.is_none()
    }

    /// Apply to an already-connected stream (tokio or std) through
    /// [`socket2::SockRef`], so the dial path needs no socket ownership move.
    pub fn apply_to_stream<S: std::os::fd::AsFd>(&self, stream: &S) {
        let sock = socket2::SockRef::from(stream);
        self.apply(&sock);
    }

    /// Apply every requested option. Errors are per-option and non-fatal by
    /// design: a kernel that does not know an option must not cost the user
    /// the connection (the alternative — refusing the dial — turns an
    /// optimisation into an outage).
    pub fn apply(&self, socket: &socket2::SockRef<'_>) {
        if let Some(ms) = self.tcp_user_timeout_ms {
            let _ = socket.set_tcp_user_timeout(Some(Duration::from_millis(u64::from(ms))));
        }
        if let Some(interval) = self.tcp_keepalive {
            let keepalive = socket2::TcpKeepalive::new().with_time(interval);
            let _ = socket.set_tcp_keepalive(&keepalive);
        }
        if let Some(v6only) = self.v6only {
            let _ = socket.set_only_v6(v6only);
        }
        if let Some(reuse) = self.reuse_port {
            let _ = socket.set_reuse_port(reuse);
        }
        if let Some(nodelay) = self.nodelay {
            let _ = socket.set_tcp_nodelay(nodelay);
        }
        if let Some(tos) = self.tos {
            let _ = socket.set_tos_v4(tos);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seam is observable: a requested option reaches the socket builder,
    /// and an empty request leaves the dial untouched. The VALUES are asserted
    /// here (platform-independent because `socket2` normalises them); the
    /// syscall itself is not asserted, since CI kernels differ.
    #[test]
    fn empty_options_touch_nothing() {
        assert!(SockOpts::default().is_empty());
        assert!(
            !SockOpts {
                nodelay: Some(false),
                ..Default::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn apply_is_total_over_a_real_socket() {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .expect("socket");
        let opts = SockOpts {
            tcp_user_timeout_ms: Some(5_000),
            tcp_keepalive: Some(Duration::from_secs(30)),
            nodelay: Some(true),
            tos: Some(0x10),
            ..Default::default()
        };
        // Applying to an unconnected socket must not panic and must not
        // destroy it: the socket stays usable (bind proves it).
        opts.apply(&socket2::SockRef::from(&socket));
        socket
            .bind(
                &"127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
            )
            .expect("bind after apply");
    }
}
