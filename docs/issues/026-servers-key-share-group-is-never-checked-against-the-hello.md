# 026 — The client accepts a ServerHello key-share group it never offered, and never checks it against the HelloRetryRequest's `selected_group`

- **Location**: `crates/leas-tls/src/handshake/mod.rs:1079-1112`
  (`EXT_KEY_SHARE` accepts 0x001D or 0x11EC unconditionally), `:247-262`
  (`hrr.selected_group` is consumed only to rebuild `ClientHello2`), `:390-395`
  (the only offered-check on a `ServerHello` is the cipher suite), `:557`
  (`signature_algorithms` is checked), `:810-837` (`offered_group` /
  `offered_share`, used only by the retry rebuild at `:269`, `:275`)
- **Severity**: low
- **Status**: theory

## Hypothesis

RFC 8446 §4.2.8 defines several obligations for the ServerHello `key_share`.
Two of them — the group the server may select, and the client's duty after a
retry — are the ones this engine does not enforce:

> `server_share`: A single `KeyShareEntry` value that is in the same group as
> one of the client's shares.
> … This value MUST be in the same group as the `KeyShareEntry` value offered
> by the client that the server has selected for the negotiated key exchange.

> If using (EC)DHE key establishment and a HelloRetryRequest containing a
> "key_share" extension was received by the client, the client MUST verify that
> the selected `NamedGroup` in the ServerHello is the same as that in the
> HelloRetryRequest. If this check fails, the client MUST abort the handshake
> with an "illegal_parameter" alert.

Two of the three offered-checks are implemented on the ServerHello path — the
cipher suite (`ensure_offered_suite`, `:801`, called `:394`) and the signature
algorithm (`ensure_offered_sigalg`, `:936`, called `:557`), both re-derived
from the hello that was actually sent. The group is not:

```rust
// handshake/mod.rs:1079-1112 — every branch decides on (group, key_len) alone
match (group, key_len, ext_data.len()) {
    (0x001D, 32, n) if n == 4 + key_len => {
        peer_key = Some(ext_data[4..36].try_into().expect("32 bytes"));
    }
    (0x11EC, 1120, n) if n == 4 + key_len => {
        mlkem_ciphertext = Some(Ciphertext::from_bytes(&ext_data[4..4 + 1088])?);
        peer_key = Some(ext_data[4 + 1088..].try_into().expect("32 bytes"));
    }
    …
}
```

Nothing reads the hello's `key_share` entry list, and `hrr.selected_group` —
kept in the parsed `HelloRetryRequest` (`:1141-1148`) — is used only to rebuild
`ClientHello2` (`:247-262`). The `ServerHello` that follows is never compared to
it, so the RFC's mandatory client check does not exist.

## Why it matters

The retried case is a working downgrade, not a theoretical one. When the server
answers the first hello with `HelloRetryRequest(selected_group = X25519MLKEM768)`,
`retry.rebuild` produces a `ClientHello2` whose `key_share` holds only the
hybrid entry (`retry_extensions`, `:843-892`), and that entry is
`ML-KEM-768 encapsulation key (1184) || X25519 pub (32)`
(`crates/leas-tls/src/spec/mod.rs:165-168`) — the client's classical public half
is **on the wire inside the hybrid entry**.

A hostile server can therefore ignore the ML-KEM half, answer `key_share: x25519
(0x001D)` with its own share, derive the classical secret from the X25519 public
key it already received, and complete the handshake. The client takes the
`(0x001D, 32, …)` arm, leaves `mlkem_ciphertext` as `None`, and the key schedule
is fed `classical_shared` alone (`:494-508`) — a classical-only TLS 1.3 tunnel
for a profile that promised post-quantum hybrid. RFC 8446 §4.2.8 says this must
be `illegal_parameter`; here it succeeds.

The non-retried case has the same missing "was it offered" check (a server MUST
the client does not enforce): a profile whose hello carries only the hybrid
share (`handshake/mod.rs:1558-1568` is the engine's own such test hello) accepts
a `0x001D` reply the same way.

The only observer is `negotiated_hybrid()` (`:643`), read by the e2e oracle
(`crates/leas-oracles/src/e2e/mod.rs:328`, `:429-444`) to fail a `pq_assert` row
that negotiated classically. No production path surfaces it, so against a hostile
server the downgrade completes without a visible signal.

The paragraph's other rules (a `KeyShareEntry` only for a group in
`supported_groups`, none under `psk_ke`, exactly one entry) are out of scope
here — only the group-identity checks are missing.

Scope limit, so the fix is not over-read: when the profile offered the classical
share as well, selecting it is **legal**, and this issue does not propose
rejecting it. The checks are "was this group in `key_share`" (§4.2.8 server MUST)
and "is it the group the retry asked for" (§4.2.8 client MUST).

## Evidence

The helper family is half-wired: `offered_group` (`:810`) and `offered_share`
(`:825-837`) exist and are only reachable from the retry rebuild. The doc comment
above `ensure_offered_suite` (`:795-800`) is even the one written for
`offered_group` ("Whether `spec` listed `wire` in `supported_groups`"), left
attached to the neighbouring function — the group check was added for the retry
path and never carried over to the `ServerHello` path.

## Fix options

1. **Record the selected group and check both rules in the same block that
   checks the suite.** `ParsedServerHello` currently keeps only the parsed key
   and the ML-KEM ciphertext; add the wire group id as `Option<u16>` (`None`
   for TLS 1.2, where the extension does not exist). Then, where `drive`
   validates the suite (`:390-395`):

   ```rust
   // `selected_wire` is `Option<u16>`: a TLS 1.2 ServerHello has no key_share,
   // and this block is version-generic (`sh.suite12` is read two lines up).
   if let Some(selected_wire) = selected_wire {
       if let Some(group) = hrr_group {             // the retry's selected_group
           if group != selected_wire {              // RFC 8446 §4.2.8, client MUST
               return Err(TlsError::Handshake(format!(
                   "ServerHello key_share 0x{selected_wire:04X} differs from the \
                    retry's selected_group 0x{group:04X} (illegal_parameter)"
               )));
           }
       }
       ensure_offered_share(&current_hello, selected_wire)?;
   }
   ```

   `ensure_offered_share` parses the sent hello's `key_share` body
   (`.extension(0x0033)`, `hello/parse.rs:23-30`) and requires the group among
   the entries — the same read-back shape as `ensure_offered_suite`. GREASE is
   excluded: a GREASE entry's wire value is the runtime-drawn `grease_a`, never a
   real group id, and `keyshare_group_for` already rejects it (`:787-793`), so a
   GREASE slot can never be "selected" by a server and must not be in the
   offered set.
2. **Thread the `ClientHelloSpec` into the retried path's helpers**
   (`offered_share` already takes a spec). Equivalent, but the driver only has
   the wire hello, so this adds plumbing for the same answer.

Option 1 is smaller and matches the existing suite/sigalg pattern. The retry
case needs the `selected_group` kept in `drive`'s loop state (it is already
available at `:412-413`).

## Verification

Hermetic, no server needed:

- `hrr_message(&sid, Some(0x11EC), None)` (the existing helper, `:1606-1626`) then
  a `ServerHello` body whose `key_share` is `0x001D`: today the parse succeeds and
  the schedule goes classical; after the fix the comparison must error.
- `ensure_offered_share(&hello.handshake_bytes, 0x001D)` on a hello built with
  `KeyShare(vec![KeyShareGroup::X25519Mlkem768])` (the shape at `:1558-1568`)
  must be `Err`, and `0x11EC` `Ok`.

## Related

- **010** (`native-transport`) — the same shape one layer down: an input the
  code computed for the dial (there the ALPN-derived HTTP version, here the
  offered share list) is not consulted at the point that decides.
- **025** — same file, same defensive family: 025 is a comparison the code
  makes the wrong way, this is a check it never makes.
