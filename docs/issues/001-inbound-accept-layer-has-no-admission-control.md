# 001 — The accept layer has no admission control, and it is written three times

- **Location:** `crates/leas-native/src/inbound/mod.rs:200` (`Socks5Inbound::serve`),
  `crates/leas-native/src/inbound/http.rs:169` (`HttpInbound::serve`),
  `crates/leas-native/src/inbound/mixed.rs:72` (`MixedInbound::serve`);
  auth compare at `crates/leas-native/src/inbound/socks5.rs:177` and
  `crates/leas-native/src/inbound/http.rs:586`
- **Severity:** medium
- **Status:** theory
- **Domain:** native-inbound

## Hypothesis

Every listener accepts and spawns without any admission boundary: there is no
concurrency cap, no per-connection budget, and no throttle on authentication
attempts. The three inbound flavours also each own a copy of that accept loop,
so any fix has to be written three times (and the copies have already drifted).

## Evidence

The SOCKS5 loop is the reference shape (`inbound/mod.rs:200-247`):

```rust
loop {
    let accept = self.listener.accept();
    ...
    let (conn, peer) = match accepted { Ok(pair) => pair, Err(e) => { absorb_accept_error(&e, "socks5 inbound").await; continue; } };
    if let Err(error) = conn.set_nodelay(true) { ... }
    let config = Arc::clone(&self.config);
    let shutdown = config.shutdown.clone();
    tokio::spawn(async move { ... });          // mod.rs:229 — no cap, no permit
}
```

1. **No cap.** `tokio::spawn` runs per accepted socket, before authentication
   and before any outbound dial. `crates/leas-native/src` contains no admission
   primitive at all (no `Semaphore` under `inbound/`, `transport/` or `server/`);
   the semaphores that do exist elsewhere gate other work — `ops/enrich.rs:334`
   (DNS), `ops/ping.rs:47`, `ops/speed_test.rs:179`, plus example binaries —
   and no `max_connections` setting reaches an inbound
   (`crates/leas/src/ops/settings.rs:148` is the mux knob, consumed at
   `crates/leas/src/ops/native_connect.rs:194`).
   What one unauthenticated peer can therefore create, per connection it opens:
   one task, two 16 KiB relay buffers (`inbound/outbound.rs:258-291`,
   `POOL_CAP` 64 then fresh allocations), and — once negotiating — one
   outbound dial that crosses the same mux pool the rest of the app uses
   (`inbound/outbound.rs:95`).
2. **No attempt throttle.** `negotiate` compares credentials with `==`
   (`socks5.rs:177`: `let ok = expected_user == &user && expected_pass == &pass;`)
   and the HTTP path compares the decoded `user:pass` with `==` too
   (`http.rs:586`). Both short-circuit: wrong length or a wrong first byte
   answers sooner, and there is no attempt counter, delay, or lockout — an
   attacker who can reach the port gets an unlimited online guessing oracle at
   loopback latency.
3. **Open relay is only a log line.** `warn_if_open_relay`
   (`inbound/mod.rs:291`) prints one warning when a non-loopback listener has no
   auth; nothing refuses or bounds it.
4. **Three owners, already drifted.** `http.rs:169-228` and `mixed.rs:72-126`
   repeat the loop byte-for-byte except for the handler and the log prefix. The
   drift is visible: `mixed.rs:102` boxes the handler future ("keeps the
   spawned task's frame bounded"), `mod.rs:230` and `http.rs:199` do not. A cap
   added to one copy would silently not exist in the other two.

## Why it matters for this client

The listener is normally loopback, but the config surface allows `0.0.0.0`
(`Socks5InboundConfig::listen`) — and it is the one place in the process where
untrusted input defines how much work the process does. A local app storm (a
browser opening hundreds of sockets on a dead tunnel) is the benign version:
each accepted socket is admitted, dialed, and held until `RELAY_IDLE`
(`error.rs:253`, 60 s) while the proxy carrier is the shared bottleneck.

## Fix sketch

One helper owning the accept loop for all three flavours:

```rust
async fn accept_loop<F, Fut>(listener: TcpListener, shutdown: Option<watch::Receiver<bool>>, admit: Arc<Semaphore>, handler: F)
where F: Fn(TcpStream, SocketAddr) -> Fut + Send + 'static, Fut: Future<Output = Result<(), NativeError>> + Send + 'static;
```

- `admit` = `Arc<Semaphore>` with a small default (64); `try_acquire_owned`
  before `spawn`, on refusal answer the protocol-level refusal (SOCKS5
  `0x01` / HTTP 503) and close, which is observable to the client instead of a
  hanging connect.
- Move the `set_nodelay`, `absorb_accept_error` and shutdown `select!` into
  that one place (the `Box::pin` from `mixed.rs` included).
- Auth: compare with a constant-time helper and keep one failure counter per
  peer address; the counter is the same admission object, not new state.

Not in scope: refusing an unauthenticated non-loopback bind (policy change, not
a bug).

## Related

- [003](003-udp-association-eager-buffers.md) — a UDP association outlives its
  connection task and costs 192 KiB; unbounded admission multiplies it.
- [002](002-relay-write-has-no-deadline.md) — a stalled connection is held by a
  write that no timeout bounds; admission is the only thing that would cap how
  many of those exist.
