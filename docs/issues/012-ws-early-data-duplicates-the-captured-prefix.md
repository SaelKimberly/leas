# 012 — WS early data writes the captured prefix into two frames on top of the header, corrupting the first bytes of the tunnel

- **Location:** `crates/leas-native/src/transport/ws.rs:183-193` (the capture
  branch of `poll_write`), `:213-229` (replay of `early`, then the caller's
  `data`), `:147-151` (`poll_read`'s unwoken `Pending`)
- **Severity:** high
- **Status:** theory (reproducer run, output below)
- **Domain:** native-transport

## Hypothesis

`EarlyDataDial` implements Xray's `?ed=N` trick: the first `N` bytes the caller
writes ride in the `Sec-WebSocket-Protocol` header instead of a frame. It does
this by capturing bytes on the first `poll_write` and returning `Poll::Pending`:

```rust
if this.upgrading.is_none() {
    let take = data.len().min(this.max_early.max(1));
    this.early.extend_from_slice(&data[..take]);   // the caller's bytes, kept
    ...start the upgrade...
    return Poll::Pending;                          // "nothing consumed"
}
```

`Pending` means **no bytes were consumed**, so the caller retries with the same
buffer. When the upgrade lands, the completion path sends `this.early` as the
first frame and then writes the caller's `data` in full:

```rust
while this.early_pos < this.early.len() { /* send the captured prefix */ }
let ws = this.ws.as_mut().expect("checked above");
match Pin::new(ws).poll_write(cx, data) {       // and the same bytes again
    Poll::Ready(Ok(n)) => Poll::Ready(Ok(n.max(early_len.min(data.len())))),
```

The captured prefix therefore leaves the client **three** times: once in
`Sec-WebSocket-Protocol` (correct, xray's convention), then twice as frame
payload — the `early` replay loop and the full `data` write. The reproducer
below shows the frame half: 26 bytes off the socket for a 13-byte write. The
`.max()` in the returned count is an attempt to account for the prefix after it
has already been sent again; it cannot undo the write.

Early data removes those bytes from the socket *by design* — both references
do it (`dialer.go:203-205` returns `len(ed), nil`, quoted in
`docs/aegis/specs/2026-09-23-ws-path-canonicalization-design.md` §"Residual") —
so any frame copy is a duplicate, never a fallback.

Consequence is not a failed handshake but **silent corruption**: the server
feeds the header bytes into the tunnel, then reads the same bytes again from
the frames as the first tunnel payload. For VLESS the duplicated request header
becomes the first bytes the destination receives; VMess's AEAD chunk would
fail validation instead, which breaks the tunnel just as hard.

## Reproducer (run, then reverted)

Appended to `crates/leas-native/src/transport/ws.rs`'s `early_data_tests`
(reverted afterwards — `git status --porcelain` shows no `crates/leas-native`
path). The listing carries both assertions a permanent test needs — the header
half decodes the echoed subprotocol, the frame half must be empty — because
checking only one of them cannot tell "sent once, in the header" from "sent only
as a frame":

```rust
#[tokio::test]
async fn challenge_early_data_bytes_reach_the_carrier_once() {
    use crate::protocol::first_flight::HeaderFirst;
    use futures_core::Stream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client, server) = tokio::io::duplex(64 * 1024);
    let seen_header = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let capture = seen_header.clone();
    let srv = tokio::spawn(async move {
        let mut ws = tokio_tungstenite::accept_hdr_async(server, move |req, resp| {
            if let Some(v) = req.headers().get("sec-websocket-protocol") {
                *capture.lock().expect("capture") = v.to_str().ok().map(str::to_owned);
            }
            echo_subprotocol(req, resp)
        })
        .await
        .unwrap();
        let mut got = Vec::new();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(300);
        loop {
            let next = std::future::poll_fn(|cx| Pin::new(&mut ws).poll_next(cx));
            match tokio::time::timeout_at(deadline, next).await {
                Ok(Some(Ok(Message::Binary(b)))) => got.extend_from_slice(&b),
                _ => break,
            }
        }
        got
    });
    let dial = EarlyDataDial::new(cfg(Some(64)), "example.com".into(), Box::new(client), 64);
    let mut stream = HeaderFirst::new(Box::new(dial), b"HEADER".to_vec());
    stream.write_all(b"PAYLOAD").await.unwrap();
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(800),
        stream.read(&mut [0u8; 1]),
    )
    .await;
    use base64::Engine as _;
    let header = seen_header.lock().expect("capture").clone().expect("header sent");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header)
        .expect("base64url");
    assert_eq!(&decoded, b"HEADERPAYLOAD", "header must carry the whole buffer");
    let got = srv.await.unwrap();
    assert!(got.is_empty(), "frames must carry nothing, saw {}", String::from_utf8_lossy(&got));
}
```

```
thread 'transport::ws::early_data_tests::challenge_early_data_bytes_reach_the_carrier_once'
  panicked at crates/leas-native/src/transport/ws.rs:543:9:
assertion `left == right` failed: carrier saw "HEADERPAYLOADHEADERPAYLOAD"
  left:  [72, 69, 65, 68, 69, 82, 80, 65, 89, 76, 79, 65, 68, 72, 69, 65, 68, 69, 82, 80, 65, 89, 76, 79, 65, 68]
  right: [72, 69, 65, 68, 69, 82, 80, 65, 89, 76, 79, 65, 68]
```

The run recorded above used the frame assertion in the form
`assert_eq!(got, b"HEADERPAYLOAD")`, so that failure is the frame half; 26 bytes
left the socket for a 13-byte write. The same shape reproduces with
`max_early_data` any value ≥ 1 and any first-write length ≥ 1. The header
capture is the part the run did not execute: it is what a fixed client must
satisfy along with the empty frame set — all 13 bytes fit in the 64-byte window,
so none of them may ride a frame.

## Why no existing test caught it

The two tests in `early_data_tests` are error-path tests: one asserts a 400
upgrade surfaces as an error, the other asserts a rejected upgrade keeps the
typed `NativeError`. `early_data_upgrade_completes_on_the_read_path` sends a
`REPLY` frame and never reads what the client wrote, so the duplicated prefix
is invisible to all three. The plugin path cannot mask it either — it disables
early data by construction (`transport/v2ray/ws.rs:13-16`), which is why
nothing exercised the direct WS early-data path end to end.

## Fix sketch

The capture already did the work: the bytes are in `Sec-WebSocket-Protocol`, so
the capture branch must report them **consumed** and the stream must never touch
them again. Delete the replay, not just the second copy:

```rust
if this.upgrading.is_none() {
    let take = data.len().min(this.max_early.max(1));
    this.early.extend_from_slice(&data[..take]);
    ...start the upgrade...
    return Poll::Ready(Ok(take));   // consumed INTO THE HEADER, not Pending
}
```

- Later `poll_write`s pass their buffer straight to the upgraded stream — no
  `early_pos`, no `skip`, no `.max()` arithmetic, because nothing is left to
  account for.
- The bytes are only *reported* consumed once they are in the header, which is
  when they left the caller's hands; a failed upgrade still fails the tunnel.
- A read-before-write keeps returning `Pending` until a write starts the
  upgrade, so `poll_read`'s shape is unchanged.

This is the reference's own shape — both cores return `len(ed), nil`
(`dialer.go:203-205`, quoted in the canonicalization spec's "Residual") — and it
is why the assertion in the reproducer is `frames.is_empty()`: the bytes travel
in the header only.

Two related defects in the same region, worth fixing in the same change:

- `poll_read` returns `Poll::Pending` when `upgrading` is `None`
  (`:147-151`) without registering a waker — a lost wakeup. It is unreachable
  from the protocol layer today (the transport is always wrapped in
  `HeaderFirst`, whose read flushes a non-empty header first), so this is a
  latent trap rather than a live hang.

## Related

- **007:** the same "a `Bytes` we already own is copied again" cost class, on
  the send side of a transport instead of the receive side of a protocol.
- **008:** shares the wrapper but not the cause — 008 is about `HeaderFirst`'s
  `pending` keeping a credential, not about the retry. The retry that feeds the
  duplicate is plain `AsyncWrite`: `flush_pending` advances `pos` only on an
  accepted write (`first_flight.rs:85-105`), so a `Pending` replay is the same
  bytes the capture kept — and any `write_all` caller does exactly that.
