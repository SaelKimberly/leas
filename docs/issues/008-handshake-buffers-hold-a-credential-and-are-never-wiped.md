# 008 — The handshake buffers carry a replayable credential and are never wiped

- **Location:** `crates/leas-native/src/protocol/trojan/mod.rs:78-99` and `:114`,
  `crates/leas-native/src/protocol/first_flight.rs:39-46` / `:102-106` /
  `:165-172`, `crates/leas-native/src/protocol/vless/mod.rs:113`
- **Severity:** low
- **Status:** theory
- **Domain:** native-protocol

## Hypothesis

The protocol modules go to real trouble to keep key material out of stale heap
memory — `trojan::auth_key` returns `Zeroizing<[u8; 56]>` with the comment
"Wipes on drop: it travels on the wire but is a replayable bearer
credential", and `ss`/`socks` wrap their key and auth buffers in `Zeroizing`
— and then every one of those bytes is copied into an ordinary `Vec<u8>` that
is never wiped:

- trojan: `encode_request(&auth_key(&cfg.password), &ctx.target)?` returns
  `Vec<u8>` whose first 56 bytes are the hex `sha224(password)` (`:92-99`);
  the `Zeroizing` copy dies at the end of the expression, the `Vec` lives on.
- VLESS: `Vec::with_capacity(header::HEADER_RESERVE)` gets the 16-byte UUID
  appended (`vless/mod.rs:113`, `header.rs:92-100`).
- Both buffers are then owned by `HeaderFirst`, whose `pending: Vec<u8>`
  outlives the handshake for the whole connection (the first payload is
  appended to the same buffer) and is `clear()`ed, not wiped, once flushed
  (`first_flight.rs:102-106`). There is no `Drop` on `HeaderFirst`.

A UUID or a trojan password hash is the whole authentication: anyone who reads
it from a core dump, a reused mimalloc page, or a `minidump` of a crashed
session can use the server without the password.

## Evidence

- `crates/leas-native/src/protocol/trojan/mod.rs:80-91` — `auth_key` is
  `Zeroizing<[u8; 56]>` and its doc says why:

  ```rust
  /// Wipes on drop: it travels on the wire but is a replayable bearer
  /// credential, so a stale stack copy is as good as the password.
  ```

- `crates/leas-native/src/protocol/trojan/mod.rs:92-99` — `encode_request`
  allocates a plain `Vec<u8>` and copies the hash into it;
  `trojan/mod.rs:114` passes that `Vec` straight to `HeaderFirst::new`.
- `crates/leas-native/src/protocol/first_flight.rs:39-46` — `pending: Vec<u8>`
  is the struct's only buffer; `first_flight.rs:104-105` does
  `self.pending.clear(); self.pos = 0;` after the flush, so the header bytes
  stay in the allocation until it is reused or returned.
- `crates/leas-native/src/protocol/vless/mod.rs:111-118` — the VLESS request
  (version, UUID, addons, command, destination) is built into a plain `Vec`
  that becomes the same `HeaderFirst::pending`. The Vision path does it twice
  (`vless/mod.rs:188`, `:466` for the mux carrier).
- The convention the rest of the crate follows: `socks/mod.rs:132`
  (`Zeroizing::new(Vec::with_capacity(...))` for the auth frame),
  `ss/method.rs:226-290` (`Zeroizing` for every derived subkey and PSK),
  `ss/stream.rs:92`/`:171` (`subkey: Zeroizing<Vec<u8>>`).
- `zeroize` is already a `leas-native` dependency (`Cargo.toml:72`), so this
  costs no new dependency.

## Impact

Every established tunnel keeps a heap copy of the credential for its lifetime
(`HeaderFirst::pending`, up to 16 KiB once a first payload joined it and the
allocation is retained by `clear()`), and the raw `Vec`s are dropped unwiped.
This is the one class of secret the repo explicitly wipes elsewhere; the
handshake buffers are the hole in that policy.

## Fix sketch

Small and local:

1. `HeaderFirst` records the header extent — `header_len: usize` set in `new`
   — and wipes only that prefix, never the joined payload:
   `self.pending[..self.header_len].zeroize()` (with `zeroize::Zeroize` in
   scope) **inside `flush_pending`, immediately before the `clear()` at
   `first_flight.rs:104`** — wiping after the flush returns would index an
   empty `Vec`.
2. The never-flushed case needs a `Drop` impl, which collides with the existing
   `#[cfg(test)] into_inner(self) -> S` (`first_flight.rs:80-82`): `Drop` makes
   a by-value field move out of `self` an E0509. Keep `into_inner` by taking the
   field with `unsafe`-free `ManuallyDrop` + `ptr::read`, or (simpler) drop
   `into_inner` and have its four test call sites (`:248`, `:261`, `:287`,
   `:324`) go through the existing `inner_mut`.
3. Build the request in `Zeroizing<Vec<u8>>` where the caller does not hand it
   straight to `HeaderFirst` (the Vision preambles at `vless/mod.rs:188`/`:466`
   keep the header and then append the camouflage frame — the wipe has to
   cover the header prefix there too).
4. Leave vmess alone: its header already AEAD-seals the body, and the `auth_id`
   it exposes is an AES-128-ECB block over `timestamp ‖ rand4 ‖ crc32`
   (`vmess/keys.rs:162-173`, the key from a `kdf16` of `cmd_key` with the
   "AES Auth ID Encryption" path) — a timestamp-bound value, not a static
   secret the peer can replay later.

Cost: a 60–96 byte wipe per connect, nothing per datagram. Test that pins it:
assert the wipe on the `Zeroizing<Vec<u8>>` that `encode_request` builds (and,
for `HeaderFirst`, that `pending[..header_len]` is all zero immediately after
`poll_write` completes the flush — the buffer is still alive there; a check
after the drop is a use-after-free).

## Related

- [005](005-mux-key-rebuilt-twice-per-dial.md) — the same convention gap one
  layer up: the pool's `MuxKey` keeps the credential in a `String` map key that
  is never zeroized.
- [007](007-datagram-recv-copies-what-bytes-already-owns.md) — same
  `HeaderFirst`/carrier buffers, different concern (copy vs. wipe).
