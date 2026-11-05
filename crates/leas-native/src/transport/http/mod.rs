//! Shared hyper HTTP layer for the httpupgrade / xhttp / v2rayhttp transports.
//!
//! We own the byte stream, the dial, and timeouts; hyper owns HTTP/1.1 +
//! HTTP/2 framing, chunked encoding, Content-Length, and the RFC 7230 (101)
//! upgrade handshake.

pub mod body;
pub mod conn;

pub use body::{IncomingReader, ReqBody};
pub use conn::{h1_client, h2_client, h2_client_with};

/// The `Http2Profile` for a link's resolved TLS identity, when one exists.
///
/// `None` (no fingerprint, `REALITY`, or an unresolvable id) keeps hyper's
/// defaults — the same resolution the engine uses for the hello, so the h2
/// windows can never describe a different browser than the `ClientHello` did.
#[must_use]
pub fn profile_for(ctx: &crate::context::LinkContext) -> Option<leas_tls::Http2Profile> {
    let tls = ctx.security()?.tls.as_ref()?;
    let fp = match tls {
        leas_proto::proto_spec::common::TlsConfig::Tls(opts) => opts.fp.as_deref()?,
        // REALITY's h2 shape belongs to the spider, which owns its own table.
        leas_proto::proto_spec::common::TlsConfig::Reality(_) => return None,
    };
    let (id, _approximated) = crate::security::fingerprint::resolve_fingerprint(Some(fp));
    let profile = crate::security::fingerprint::profile_for(id?).ok()?;
    Some(leas_tls::Http2Profile::for_browser(profile.browser))
}
