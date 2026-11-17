//! A pooled sbox carrier: one session protocol over one carrier stream.

use std::sync::Arc;

use crate::BoxStream;
use crate::addr::TargetAddr;
use crate::error::NativeError;
use crate::protocol::first_flight::HeaderFirst;

use super::h2mux::H2Mux;
use super::protocol::StreamRequest;
use super::smux::SmuxSession;
use super::stream::ResponsePeel;
use super::yamux::YamuxSession;

/// The session protocol a carrier speaks.
pub enum SboxSession {
    /// HTTP/2 streams.
    H2(H2Mux),
    /// `SagerNet` smux v1.
    Smux(SmuxSession),
    /// yamux.
    Yamux(YamuxSession),
}

/// One sbox carrier.
pub struct SboxTunnel {
    session: SboxSession,
}

impl SboxTunnel {
    /// Wrap a negotiated session.
    #[must_use]
    pub const fn new(session: SboxSession) -> Self {
        Self { session }
    }

    /// Open one TCP-equivalent stream to `target`.
    ///
    /// # Errors
    ///
    /// A closed session or a framing failure on the stream request.
    pub fn open(&self, target: &TargetAddr) -> Result<BoxStream, NativeError> {
        match &self.session {
            SboxSession::H2(h2) => h2.open(target),
            SboxSession::Smux(smux) => {
                let stream = smux
                    .open()
                    .map_err(|e| NativeError::Transport(format!("sbox smux session: {e}")))?;
                request_wrapped(stream, target, false)
            }
            SboxSession::Yamux(yamux) => {
                let stream = yamux
                    .open()
                    .map_err(|e| NativeError::Transport(format!("sbox yamux session: {e}")))?;
                request_wrapped(stream, target, false)
            }
        }
    }

    /// Open one UDP association stream to `target`.
    ///
    /// # Errors
    ///
    /// A closed session or a framing failure on the stream request.
    pub fn open_udp(&self, target: &TargetAddr) -> Result<BoxStream, NativeError> {
        match &self.session {
            SboxSession::H2(h2) => h2.open_with(target, true),
            SboxSession::Smux(smux) => {
                let stream = smux
                    .open()
                    .map_err(|e| NativeError::Transport(format!("sbox smux session: {e}")))?;
                request_wrapped(stream, target, true)
            }
            SboxSession::Yamux(yamux) => {
                let stream = yamux
                    .open()
                    .map_err(|e| NativeError::Transport(format!("sbox yamux session: {e}")))?;
                request_wrapped(stream, target, true)
            }
        }
    }

    /// Whether the carrier's reader task has exited.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        match &self.session {
            // An h2 sender reports death on the next send; there is no flag.
            SboxSession::H2(_) => false,
            SboxSession::Smux(smux) => smux.is_dead(),
            SboxSession::Yamux(yamux) => yamux.is_dead(),
        }
    }
}

/// Prepend the stream request to the first write and peel the response.
fn request_wrapped<S>(stream: S, target: &TargetAddr, udp: bool) -> Result<BoxStream, NativeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut prefix = Vec::with_capacity(16);
    StreamRequest {
        udp,
        packet_addr: false,
        target: target.clone(),
    }
    .encode(&mut prefix)?;
    Ok(Box::new(ResponsePeel::new(HeaderFirst::new(
        stream, prefix,
    ))))
}

/// A boxed sbox carrier, shared by the pool.
pub type SharedSboxTunnel = Arc<SboxTunnel>;
