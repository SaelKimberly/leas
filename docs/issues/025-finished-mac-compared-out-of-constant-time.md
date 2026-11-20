# 025 — The handshake `Finished` MACs are compared with `!=`, not in constant time, while every other secret-keyed tag comparison in the crate is constant-time

- **Location**: `crates/leas-tls/src/handshake/mod.rs:602` (TLS 1.3 server
  `Finished`), `crates/leas-tls/src/handshake/tls12.rs:531` (TLS 1.2 server
  `Finished`), `crates/leas-tls/src/verify/mod.rs:147` (SPKI pin digest)
- **Severity**: low
- **Status**: theory (code-proven; hardening — no reachable oracle)

## Hypothesis

The server's `Finished` is the message that authenticates the handshake, and
its expected value is a `HMAC(finished_key, Transcript-Hash)` — a keyed tag the
client computes and the server must match. Both handshake drivers compare it
with Rust's short-circuiting slice `!=`:

```rust
// handshake/mod.rs:601-606 — TLS 1.3
let server_finished_key = ks.finished_key(&server_hs_ts[..hash_len])?;
if ks.finished_mac(&server_finished_key[..hash_len]) != flight.sf_verify_data {
    return Err(TlsError::Handshake(
        "server Finished MAC mismatch — possible MITM or wrong key".into(),
    ));
}
```

```rust
// handshake/tls12.rs:531-535 — TLS 1.2
if sf_body != expected_sf.as_slice() {
    return Err(TlsError::Handshake(
        "TLS 1.2 server Finished MAC mismatch — possible MITM or wrong key".into(),
    ));
}
```

`!=` on byte slices stops at the first differing byte, so the time to reject
grows with the length of the common prefix. Every audited TLS implementation
compares MACs and tags through a constant-time primitive for that reason — and
this crate says the same, in code and in its manifest (below). These three
comparisons are the exceptions.

The same `!=` shape appears once more, non-fatally: the pin digest
(`verify/mod.rs:147`) is compared with `digest.as_ref() != pin` — a SPKI hash is
public information and the pinned key still has to sign, so no prefix leak buys
authentication power; it is the same comparison and belongs on the same
helper.

Threat model, stated up front so nothing below is read as an exploit claim: both
`Finished` comparisons run on a record that has already been AEAD-opened under
the handshake traffic key, and the expected tag is derived from that same secret
(§"Why it matters" below).

The crate is otherwise explicit that this must not happen. `reality/verify.rs`
compares the REALITY certificate HMAC with `subtle`'s `ct_eq` and carries the
reason inline:

```rust
// reality/verify.rs:76-78
// Constant-time: `subtle`'s slice comparison (both sides are fixed-size
// HMAC-SHA512 tags). ring's `verify_slices_are_equal` is deprecated.
if expected.as_ref().ct_eq(signature).unwrap_u8() != 1 { … }
```

`subtle` is a **direct dependency** of `leas-tls` with that same justification
in its manifest (`crates/leas-tls/Cargo.toml:22-24`), `leas-dns`'s dnscrypt
half uses `ct_eq` for its tag (`crates/leas-dns/src/dnscrypt.rs:230`), and the
ECH acceptance check is hand-written branchless (`handshake/mod.rs:434-443`: `diff |= a ^ b` over the 8 confirmation bytes). So the codebase has one convention applied
in three places and missed in three.

## Why it matters

**No oracle is reachable today, and this issue does not claim one.** The record
carrying the server `Finished` is AEAD-opened under the handshake traffic key
before the comparison runs, and `finished_key` is HKDF-Expanded from that same
secret (`ks.finished_key(&server_hs_ts[..hash_len])`, `handshake/mod.rs:601`).
Any party that can put a candidate tag in front of these two comparisons
therefore already holds the key that derives the real tag — the timing leak
exposes a value its own submitter can compute. The Lucky13 parallel that
motivated the `ct_eq` sites in this crate (a record-layer padding/MAC oracle)
does not transfer to an authenticated handshake flight.

What remains is a consistency defect with a real cost when it is violated
later: the crate states a rule ("keyed tags are compared in constant time"),
enforces it at three sites, and the last two authentication comparisons in the
handshake are the exceptions. A non-constant-time compare of a secret tag is
the shape that becomes an oracle the moment it moves ahead of authentication —
an early-reject path, an alert MAC, a resumed/PSK variant that compares before
the record is opened — and the fix is mechanical now and risky later.

The issue is therefore **hardening**, deliberately filed at `low`: it is not a
claim that a practical attack exists, only that the last two tags the code
compares do not meet the rule the crate documents for exactly this comparison.

## Fix options

1. **One helper, three call sites.** The three call sites live in two modules,
   so the helper needs a shared home and `pub(crate)` visibility — a private
   `fn` in `handshake` is not reachable from `verify`. Put it in
   `crates/leas-tls/src/crypto/mod.rs` (the AEAD/KDF home both modules already
   read) and import it as `crate::crypto::tags_equal`:

   ```rust
   /// Constant-time equality for a keyed tag (see `reality::verify`).
   pub(crate) fn tags_equal(a: &[u8], b: &[u8]) -> bool {
       a.len() == b.len() && a.ct_eq(b).unwrap_u8() == 1
   }
   ```

   and use it at `handshake/mod.rs:602`, `handshake/tls12.rs:531`,
   `verify/mod.rs:147`. `subtle::ConstantTimeEq` is a direct dependency
   (`reality/verify.rs:11` uses it today); `crypto/mod.rs` adds one `use`.

2. **`ring::constant_time::verify_slices_are_equal`.** Rejected by the crate
   already (deprecated) — `reality/verify.rs:77-78` says so. Keep `subtle`.

Option 1 is the smallest complete change and removes the third convention.

## Verification

No test can prove constant-time behaviour, so this issue carries no reproducer:
the evidence is the comparison operators at the three cited lines versus the
`ct_eq` at the two cited lines. A test would be a source-text assertion, which
this review does not accept. If a mechanical guard is wanted, the honest one is
a grep-shaped CI check (`!= .*verify_data`) rather than a Rust test.

## Related

- **008** (`native-protocol`) — the same "a credential sits in a buffer that
  the rest of the crate treats as secret" shape, one layer down: 008 is the
  storage, this is the comparison.
