//! Shared hyper HTTP layer for the httpupgrade / xhttp / v2rayhttp transports.
//!
//! We own the byte stream, the dial, and timeouts; hyper owns HTTP/1.1 +
//! HTTP/2 framing, chunked encoding, Content-Length, and the RFC 7230 (101)
//! upgrade handshake.

pub mod body;
pub mod conn;

pub use body::{IncomingReader, ReqBody};
pub use conn::{h1_client, h2_client};
