# ADR 0017 — Encryption is validated at ingestion; Trojan-Go's SS layer is a bare AEAD stream

Date: 2026-11-18.
Status: **accepted — SHIPPED** (gate `just quality-gate code`: fmt + clippy +
2 814 tests; Trojan oracle suite 17/17, including the three `trojan-go v0.10.6`
rows).
Spec: `docs/aegis/specs/2026-11-18-encryption-validity-and-trojan-go-ss-design.md`.
Plan: `docs/aegis/plans/2026-11-18-encryption-validity-and-trojan-go-ss.md`.
Relates to: `specs/2026-09-22-native-testability-improvement-design.md` (mlkem
classification), `specs/2026-11-06-shadowsocks-coverage-design.md` (classic AEAD
stream), ADR 0007 (crypto dependency posture).

## Context

Two defects shared one shape: a field that changed the wire was parsed but never
validated.

1. A live feed served `vmess://<uuid>@host:1234?…&encryption=aes-128-gcm…` — a
   URI-form VMess body. `VmessConfig` rejected it structurally, the fallback
   chain reached `VlessConfig`, and VLESS stored the body with `encryption`
   verbatim. The row could never be dialed; it was marked
   `not testable by the native engine: vless account encryption is not
   implemented`, which named the wrong cause.
2. The Clash conversion copied `encryption` verbatim, including `none`, while
   the URL parser dropped it. A Clash row with `none` passed capability and died
   at dial in the mlkem path.
3. Trojan's `encryption` — Trojan-Go's `ss;<method>:<password>` layer — was read
   by neither parser nor dial path. A `trojan-go://` link did not parse at all
   (no scheme), and a `trojan://…encryption=ss;…` link dialed plain Trojan.

The reference for the layer is Trojan-Go v0.10.6, the only implementation.
Its stack is `transport → tls → websocket → shadowsocks → trojan`, and the layer
is `core.Cipher.StreamConn`: salt plus sealed chunks with **no SS
target-address header**. xray-core, sing-box and Clash cannot express it.

## Decisions

1. **D-A — parse permissively, validate strictly, do not import invalid rows.**
   A config that fails the encryption rule is a `ParseError::InvalidConf`; an
   import drops it and counts the reason. Stored rows written by an older build
   are not deleted: `capability` re-runs the same rule, names the value, and
   refuses the dial.
2. **D-B — one normaliser per owner, in `leas-proto`.** VLESS restores `none`,
   `auto` (ASCII case-insensitive) and `none`+a junk suffix (`none=/@Telegram…`)
   to absent, keeps a valid `mlkem768x25519plus` value, and rejects everything
   else. Full mlkem validity — grammar, decoded keys, padding bounds — is
   owned by `parse_mlkem_encryption`; `leas-native` consumes the validated value
   and keeps no second parser. The same function is called by the URL parser,
   the Clash conversion, stored-config `validate()`, and the dial dispatch.
3. **D-C — the fallback chain stops on `InvalidConf`.** A structural failure
   means "not my body, try the next parser"; a config-invalid result means "my
   body, broken", so reinterpreting it as another protocol is wrong. Without
   this, the VMess body above would heal into Trojan or Hysteria (both accept
   any userinfo as a credential).
4. **D-D — every non-owner parser rejects any `encryption` presence**,
   including `none` and an empty value.
5. **D-E — Trojan-Go's layer is modelled and typed.** `TrojanEncryption::Ss
   { method, password }` with exactly `aes-128-gcm`, `aes-256-gcm`,
   `chacha20-ietf-poly1305`; the method is a signature field and the password a
   credential. `trojan-go://` is a scheme; `type=original` restores to TCP;
   `plugin=…` is invalid (unimplemented and wire-changing); reconstruction emits
   `trojan-go://…encryption=ss%3B<method>%3A<password>` when the layer is
   present and `trojan://` otherwise.
6. **D-F — the native layer is a bare AEAD stream.**
   `protocol/ss/stream.rs::wrap_bare` builds `SsStream::new(..., first: None)`
   (no target-address chunk) and the Trojan connect wraps its stream before
   `HeaderFirst`; `connect_udp` wraps its command-3 header the same way. No new
   crypto: the three ciphers and the classic AEAD codec already exist.
7. **D-G — builders that cannot carry the layer refuse it.** xray/sing-box
   injection and Clash serialisation return a named error instead of emitting a
   config that would dial plain Trojan.
8. **D-H — stored-row identity is normalised once.** A marker-gated DATA step
   (`app_meta.vless_encryption_normalized`, no DDL, no cursor bump) rewrites
   stored `auto`/`none`-junk VLESS configs to absent, re-keys through the
   existing rebuild/merge machinery, and merges collisions. Invalid rows are
   left in place for the capability backstop.
9. **D-I — Trojan-Go v0.10.6 is a pinned oracle core.** SHA-256 pinned from the
   computed assets (the release API publishes no digest), spawned as the server;
   our client is under test. Rows: `aes-128-gcm/tcp`, `aes-256-gcm/ws`,
   `chacha20-ietf-poly1305/tcp`.

## Alternatives considered

- **Store invalid configs and mark them n-a** (the old behaviour): rejected —
  the row is not a config of the protocol it claims, and the marker text
  conflated "invalid" with "unimplemented".
- **Per-parser strictness without the chain-terminal rule:** rejected — after
  VLESS rejects the VMess body, Trojan accepts any userinfo as a password, so
  the row would become a silently wrong protocol instead of a drop.
- **Reject Trojan `encryption` presence:** rejected — three live `trojan://`
  links carry `encryption=none`, and Trojan-Go itself accepts `none`.
- **Treat `aes-128-gcm` as `none`:** rejected — `auto` requests no concrete
  cipher (restore), a concrete VMess cipher does not.
- **Hermetic tests without the Trojan-Go binary:** rejected — byte KATs cannot
  prove layer order or header placement, and Trojan-Go is the only reference.

## Consequences

- Invalid links are dropped at import with a counted reason; existing invalid
  rows stay visible with a named capability reason until manually removed.
- On first open after upgrade, the DATA step rewrites the ~11 stored
  `auto`/`none`-junk VLESS rows and re-keys them; the marker makes it once-only
  and the transaction makes it atomic.
- The oracle crate now requires a fourth binary (all four claimed platforms
  have assets). A missing binary fails oracle resolution, not the default test
  suite.
- Trojan-Go is unmaintained since 2023; if it stops running in CI the layer's
  e2e evidence becomes a harness problem, not a client verdict.

## References

- Trojan-Go v0.10.6: `proxy/client/client.go:24-42`,
  `tunnel/shadowsocks/client.go`, `url/share_link.go:143-185`,
  `url/option.go:82-90`.
- Local: `crates/leas-proto/src/proto_spec/{vless,trojan,mod,common,utils}.rs`,
  `crates/leas-native/src/{capability.rs,protocol/ss/stream.rs,protocol/trojan/mod.rs}`,
  `crates/leas-db/src/schema/rekey.rs`, `crates/leas-oracles/src/pins.rs`.
