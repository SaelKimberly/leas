//! Async adapter for the sans-I/O [`Handshake`](super::state::Handshake).
//!
//! Only byte movement lives here. TLS 1.3 completes in the state machine;
//! TLS 1.2 hands the consumed bytes to the existing 1.2 driver, which still
//! owns that version's flight.

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::error::{Result, TlsError};
use crate::record::stream::TlsStream;

use super::state::Handshake;
use super::{HandshakeParams, RetrySupport, ServerAuth, connect_inner_hello, drive12_handoff};

/// Drive a plain TLS handshake through the sans-I/O state machine.
pub async fn connect_state<S>(
    mut stream: S,
    params: HandshakeParams<'_>,
    permute_extensions: bool,
) -> Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let prepared = connect_inner_hello(&params, permute_extensions)?;
    let retry = RetrySupport {
        permute_extensions,
        spec: params.spec,
        server_name: params.server_name,
        alpn: params.alpn,
        x25519_pub: &prepared.x25519_pub,
        draws: &prepared.recording,
        rng: params.rng,
    };
    let ech = prepared
        .ech
        .as_ref()
        .map(|(outer, state)| (outer.handshake_bytes.as_slice(), state));
    let mut state = Handshake::new(
        &prepared.hello.handshake_bytes,
        prepared.hello.session_id(),
        prepared.keypair,
        prepared.mlkem_sk,
        params.server_name,
        ServerAuth::Verifier(params.verifier),
        Some(&retry),
        ech,
    );
    state.feed(&[])?;
    let mut out = Vec::new();
    loop {
        out.clear();
        if state.poll_transmit(&mut out) {
            stream.write_all(&out).await?;
            continue;
        }
        if let Some(est) = state.take_established() {
            let mut tls = TlsStream::new(stream, est.keys);
            if let Some(secrets) = est.secrets {
                tls.set_app_secrets(secrets);
            }
            tls.set_negotiated_alpn(est.alpn);
            tls.set_negotiated_hybrid(est.hybrid);
            return Ok(tls);
        }
        if let Some(handoff) = state.take_handoff() {
            return drive12_handoff(stream, params, handoff).await;
        }
        let record = read_one_record(&mut stream).await?;
        state.feed(&record)?;
    }
}

/// Read exactly one TLS record (header + payload), never a byte more.
pub(crate) async fn read_one_record<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut hdr = [0u8; 5];
    tokio::io::AsyncReadExt::read_exact(stream, &mut hdr).await?;
    let len = usize::from(u16::from_be_bytes([hdr[3], hdr[4]]));
    if len > crate::record::MAX_RECORD_PAYLOAD {
        return Err(TlsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("TLS record too large: {len} bytes"),
        )));
    }
    let mut record = vec![0u8; 5 + len];
    record[..5].copy_from_slice(&hdr);
    tokio::io::AsyncReadExt::read_exact(stream, &mut record[5..]).await?;
    Ok(record)
}
