# ADR 0019 — `WireGuard` is an L3 outbound with a userspace stack; the DNS owner gains a caller-supplied transport

Date: 2026-11-26.
Status: **accepted** (user decision, 2026-11-26, after the grilling recorded in the spec).
Spec: `docs/aegis/specs/2026-11-26-wireguard-native-design.md`; plan
`docs/aegis/plans/2026-11-26-wireguard-native.md`.

## Context

`leas-native` is a stream engine: every protocol it serves is
`connect(&LinkContext, BoxStream) -> BoxStream`. WireGuard carries IP packets, not
streams, and every reference implementation that serves a proxy through it
(`Xray-core/proxy/wireguard`, `sing-box/protocol/wireguard`, `mihomo/adapter/outbound`)
does so by pairing the WireGuard device with a **userspace TCP/IP stack** — gVisor in
all three. Two Rust cores in `thirdparty/` confirm the shape: `ferrox` writes the
protocol itself (`ferrox-core/src/wireguard/{kdf,handshake,transport,device}.rs`, sans-I/O,
caller-supplied `now`) and drives `smoltcp`; `ZeroNet` wraps `boringtun` and a *patched*
`netstack-smoltcp` whose `PATCHES.md` lists six real socket-lifecycle bugs a naive
integration inherits. `shoes` pins a `smoltcp` fork for a TCP loss-recovery series,
which is the standing warning that vanilla `smoltcp` TCP recovery is a behaviour to
prove, not assume.

Three decisions had to be durable: the dependency, the dispatch shape, and where target
resolution inside a tunnel lives.

## Decision

1. **`smoltcp 0.14` is `leas-native`'s IP stack owner for L3 outbounds.** It is
   `#![deny(unsafe_code)]` (`src/lib.rs:2`); its `unsafe` is confined to `phy/sys/*`
   behind `phy-sys` features that stay off, so `leas-native`'s
   `#![forbid(unsafe_code)]` survives. A version bump, or the `cfal` fork, requires the
   loss-recovery acceptance row first (`leas-oracles`).
2. **An L3 outbound owns one device and one driver task per profile identity.**
   `WireGuard` keeps `ConnectShape::DeviceTunnel`; `inbound::outbound::dial` routes it to
   `protocol::wireguard::pool`, which returns a flow from the shared device rather than
   running `protocol::connect`. A peer keeps one session per key, so two devices with the
   same key would keep replacing each other's handshake; the pool keys on the
   wire-visible identity (server, peer key, private-key hash, PSK hash, addresses, MTU,
   reserved) and drops an entry once no flow holds it and it has been idle for 5 minutes.
   A `WireGuard` link can only be the whole chain: it cannot ride a base tunnel and it
   cannot carry a later link.
3. **Target resolution inside a tunnel is the tunnel's job.** A `WireGuard` profile
   resolves names through its own `dns` servers over the stack's UDP flow; the local
   resolver is used only when no configured resolver answered inside
   `RESOLVER_ALIVE_WINDOW` (600 s). `leas-dns` keeps the policy, the liveness window and
   the fallback, and the caller supplies the transport through one trait
   (`PlainResolver`); `DnsResolver` stays concrete (its pool stays
   `Resolver<DnsCryptProvider>`), because a generic resolver would leak the provider type
   through every app call site and a hickory provider arm would need a full
   `DnsRequestSender` for a wire the tunnel already owns.
4. **The codec is ours, sans-I/O.** `protocol/wireguard/core/{kdf,handshake,transport,device}`
   takes `now: u64` and emits events; nothing in it opens a socket or reads a clock.
   `boringtun`/`gotatun` are not production dependencies: their tree pulls pre-release
   `aead`/`chacha20poly1305` versions against our 0.11 line, and `Tunn` reads
   `Instant::now()` itself.

## Consequences

- A `WireGuard` row becomes dialable natively (SOCKS TCP, UDP ASSOCIATE, Real Test) once
  `capability::SUPPORT_REVISION` moves (3 → 4), which re-opens the persisted `[n-a]`
  verdicts exactly once.
- Memory is ~192 KB per live connection at 64 KiB rings; the live-socket cap is the
  listener's own ceiling and past it a SYN is answered with RST.
- The DNS fallback is a deliberate, bounded leak: one WARN per session, only while no
  configured resolver has answered in 10 minutes.
- `reserved` (WARP) is carried in the type word's bytes 1..4, stamped after the MACs and
  zeroed before verification; it is unit-proven, not WARP-live.
- The loss-recovery row (`leas-oracles`) is the gate for trusting stock `smoltcp`; if it
  fails, the escalation is a `[patch.crates-io]` to the fork and its own ADR.
