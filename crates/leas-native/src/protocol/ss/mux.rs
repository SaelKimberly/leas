//! The Shadowsocks arm of the v2ray-plugin mux: a [`MuxClient`] whose
//! sessions each carry their **own** Shadowsocks codec.
//!
//! The layering is the reason this is not `MuxClient<BoxStream>` like the
//! VLESS arm. VLESS's codec sits *under* the multiplexer, so its sessions are
//! framed by the time they leave the mux. Here the plugin framing is the
//! stream and the SS codec sits **above** each session — and it must, because
//! one salt/subkey/counter stream is exactly one SS connection
//! (`ss/stream.rs`: *"a salt/counter is never carried across"*). A single
//! codec wrapped around the whole tunnel would push two connections' bytes
//! through one counter stream, which the server's per-connection subkey
//! rejects, and it would also break the chunk framing.
//!
//! So: [`SsMux::open_session`] opens a mux session and runs that session's own
//! handshake against the **session's** destination — which is not
//! `ctx.target`, because a v2ray-plugin New frame carries a dummy address
//! (spec §7), so the codec entry takes the target explicitly
//! ([`stream::connect_to`] / [`stream2022::connect_to`]).
//!
//! Tunnel granularity: one tunnel per dial carrying one session (spec §5.2).
//! The server builds a `ServerWorker` per inbound stream
//! (`common/mux/server.go`), so a fresh tunnel per dial is correct and
//! stateless; a *pooled* tunnel is the change that would make multiplexing
//! pay off, and it is not this one.

use leas_proto::proto_spec::SsConfig;

use crate::BoxStream;
use crate::addr::{Host, TargetAddr};
use crate::error::NativeError;
use crate::transport::mux::{self, MuxClient, MuxTarget};

use super::method::{SsFamily, SsMethod};
use super::{resolve_method, stream, stream2022};

/// A v2ray-plugin mux tunnel whose sessions are Shadowsocks streams.
pub struct SsMux {
    inner: MuxClient<BoxStream>,
    cfg: SsConfig,
    method: SsMethod,
}

impl SsMux {
    /// Wrap an already-framed stream (post dial + security + plugin framing) in
    /// the mux multiplexer.
    ///
    /// There is no mux handshake of our own to write: the v2ray mux protocol
    /// has no request header — the client simply starts emitting frames — so
    /// this is the same shape as the VLESS arm minus its `command = 0x03`
    /// header.
    pub fn new(stream: BoxStream, cfg: SsConfig) -> Result<Self, NativeError> {
        let method = resolve_method(&cfg)?;
        Ok(Self {
            inner: MuxClient::new(stream),
            cfg,
            method,
        })
    }

    /// The New frame's destination: the fixed dummy the reference client
    /// writes (`common/mux/client.go`'s `muxCoolAddress`). A v2ray-plugin
    /// server overrides every dispatched destination with its
    /// `freedom.DestinationOverride`, so the value is inert — but it must be
    /// the one both references write, not a guess (spec §7).
    fn header_target() -> MuxTarget {
        MuxTarget::TcpDomain(mux::MUX_DEST.to_string(), mux::MUX_PORT)
    }

    /// Open one mux session and run **its own** SS handshake for `target`, using
    /// the pinned `v1.mux.cool:9527` frame destination.
    pub async fn open_session(&self, target: &TargetAddr) -> Result<BoxStream, NativeError> {
        self.open_session_with_frame(Self::header_target(), target)
            .await
    }

    /// The same, with the New frame's destination given explicitly.
    ///
    /// The seam acceptance row 4b needs. The field is inert against a
    /// v2ray-plugin server — it overrides every dispatched destination with its
    /// `freedom.DestinationOverride` — and the only honest proof is to send the
    /// **other** value the ecosystem uses (mihomo's `127.0.0.1:0`) and see the row
    /// still pass. On the default path a "row 4b" would emit the same bytes as row 4
    /// and prove nothing.
    pub async fn open_session_with_frame(
        &self,
        frame: MuxTarget,
        target: &TargetAddr,
    ) -> Result<BoxStream, NativeError> {
        let session = self
            .inner
            .open_session(frame)
            .await
            .map_err(|e| NativeError::Transport(format!("v2ray-plugin mux session: {e}")))?;
        let stream: BoxStream = Box::new(session);
        match self.method.family {
            SsFamily::Classic => stream::connect_to(target, stream, &self.cfg, self.method).await,
            SsFamily::Blake3_2022 => {
                stream2022::connect_to(target, stream, &self.cfg, self.method).await
            }
        }
    }

    /// The target a dial opens, as the mux layer sees it: the plugin's own
    /// dummy, never the application's destination.
    #[must_use]
    pub fn wire_target() -> TargetAddr {
        TargetAddr::new(Host::Domain(mux::MUX_DEST.to_string()), mux::MUX_PORT)
    }
}

#[cfg(test)]
mod tests {
    use leas_proto::proto_spec::common::SecurityConfig;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    fn cfg() -> SsConfig {
        SsConfig {
            method: "aes-128-gcm".into(),
            password: "pw".into(),
            security: SecurityConfig::default(),
            remarks: None,
            plugin: None,
        }
    }

    /// The New frame carries the reference's dummy, never the app's
    /// destination — the plugin server overrides the dispatched target.
    #[test]
    fn the_new_frame_target_is_the_reference_dummy() {
        assert_eq!(
            SsMux::wire_target().host.as_str(),
            mux::MUX_DEST,
            "v1.mux.cool, the value both references write"
        );
        assert_eq!(SsMux::wire_target().port, mux::MUX_PORT);
        assert_eq!(mux::MUX_DEST, "v1.mux.cool");
        assert_eq!(mux::MUX_PORT, 9527);
    }

    /// The codec is per **session**, never once around the tunnel — the property
    /// row 27 exists for, and the previous version of this test could not fail
    /// for it (it opened no session at all).
    ///
    /// The evidence is on the wire: an SS session's first bytes are its 16-byte
    /// salt, and `stream::connect_to` draws a **fresh random** one per session
    /// (`protocol/ss/stream.rs`, `fill_nonsecret`). Two sessions over one tunnel
    /// must therefore open with different leading 16 bytes; a shared codec would
    /// reuse the salt, subkey and counter stream, which the server's
    /// per-connection subkey rejects.
    #[tokio::test]
    async fn each_session_owns_its_codec() {
        // A mux peer that answers the tunnel: the two New frames must reach it
        // before the test reads them, so the server side is a real reader.
        let (client, mut peer) = tokio::io::duplex(256 * 1024);
        let tunnel = SsMux::new(Box::new(client), cfg()).expect("tunnel");
        let target = TargetAddr::new(Host::Ip("127.0.0.1".parse().expect("ip")), 80);

        // Two sessions over ONE tunnel, each writing a byte so its handshake
        // reaches the peer. The peer is drained in this task after a short beat:
        // the writer task needs a moment to make the frames visible, and a
        // spawned drain task only added a join to reason about.
        let mut sessions = Vec::new();
        for _ in 0..2 {
            let mut session = tunnel.open_session(&target).await.expect("open a session");
            session.write_all(b"x").await.expect("write");
            let _ = session.flush().await;
            sessions.push(session);
        }
        drop(sessions);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let mut captured = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(Ok(n)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), peer.read(&mut chunk)).await
        {
            if n == 0 {
                break;
            }
            captured.extend_from_slice(&chunk[..n]);
        }

        assert!(
            captured.len() >= 2 * (5 + 16),
            "expected two New frames carrying two salt prefixes, got {} bytes",
            captured.len()
        );
        // Each session's payload begins with its own 16-byte salt; find both
        // frame payloads by their `[2B meta][meta][2B data_len]` shape.
        let salts = frame_payloads(&captured);
        let leading: Vec<&[u8]> = salts
            .iter()
            .filter(|p| p.len() >= 16)
            .map(|p| &p[..16])
            .collect();
        assert!(
            leading.len() >= 2,
            "two sessions must each emit a salt; saw {} payloads",
            leading.len()
        );
        assert_ne!(
            leading[0], leading[1],
            "two sessions over one tunnel must not share a salt/subkey/counter stream"
        );
    }

    /// Split a recorded mux byte stream into its frames' payloads.
    fn frame_payloads(bytes: &[u8]) -> Vec<&[u8]> {
        let mut payloads = Vec::new();
        let mut at = 0;
        while at + 2 <= bytes.len() {
            let meta_len = usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
            let Some(meta) = bytes.get(at + 2..at + 2 + meta_len) else {
                break;
            };
            let mut next = at + 2 + meta_len;
            // meta = sid(2) status(1) option(1) …
            if meta.len() >= 4 && meta[3] & 0x01 != 0 {
                if next + 2 > bytes.len() {
                    break;
                }
                let data_len = usize::from(u16::from_be_bytes([bytes[next], bytes[next + 1]]));
                next += 2;
                let Some(data) = bytes.get(next..next + data_len) else {
                    break;
                };
                payloads.push(data);
                at = next + data_len;
            } else {
                at = next;
            }
        }
        payloads
    }
}
