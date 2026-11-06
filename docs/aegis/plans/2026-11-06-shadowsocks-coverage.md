# Shadowsocks coverage — implementation plan

**Status: EXECUTED 2026-11-06 (T1–T12).** Gate: `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean; `cargo nextest run --workspace` **2747 passed, 11 skipped**; `cargo hakari generate` re-run after the `chacha20` promotion. e2e rows (legacy ciphers + UDP, sing-box-only) added to `tests/shadowsocks.rs`, opt-in via `$LEAS_CORE_BIN_DIR`.

Spec: `docs/aegis/specs/2026-11-06-shadowsocks-coverage-design.md` (D1–D8).
Each task lands with its tests; no task defers its own verification.

## Slice A — native cipher surface (D1, D8)

- **T1 — method model.** `protocol/ss/method.rs`: `SsCipher { Aead, Stream }`,
  `StreamCipher` (10 variants), `SsFamily::Stream`, `key_len`/`iv_len`/`kind`,
  `from_method` table + aliases, `password_key` stream arm (EVP_BytesToKey with
  each key length; `none` → empty). Tests: table coverage per name, key lengths,
  `none` empty key, unknown still `None`.
- **T2 — primitives.** Extract `vmess/legacy.rs::Cfb` to `crypto/cfb128.rs`
  generic over AES key size; VMess keeps its NIST + chunking tests against the
  new home. Add `crypto/rc4.rs` (RFC 6229 KATs). Promote `chacha20` (zeroize)
  in `leas-native/Cargo.toml`; run hakari. Add `crypto-dependencies.md` rows.
- **T3 — TCP codec.** `protocol/ss/stream_legacy.rs`: IV prefix per direction,
  continuing keystream, `rc4-md5` via `MD5(key‖iv)`, `none` passthrough;
  `ss::connect` gains the `Stream` arm. Tests: golden IV→ciphertext for
  `[addr][payload]`, write-split continuity, `none` identity, round trip.
- **T4 — UDP.** `ss/udp.rs` `Stream` arm: per-datagram IV, fresh cipher state,
  `none` with no IV; keep the existing chain/security guards. Tests: two
  datagrams carry different IVs, `none` has no prefix, round trip.
- **T5 — capability.** `ss_reason` no longer refuses the ten legacy names;
  rewrite `ss_kinds_are_native_and_legacy_methods_defer` to the new partition.

## Slice B — plugin semantics + import policy (D2, D4, D5)

- **T6 — `tls` presence-only.** `ss_plugin.rs`: `TlsSetting { Unset, On }`
  (`Off`/`Invalid` deleted), parse = presence; delete the `capability` refusal
  arm and its test row; identity keeps `tls=1`.
- **T7 — escape-aware options.** `PluginSpec::from_query` unescapes `\\`, `\;`,
  `\=` per `v2ray-plugin/args.go:70-108`. Tests: `certRaw=a\=b` decodes,
  escape-free strings unchanged.
- **T8 — import gate.** Rename `validate_ss2022_key` → `validate_ss_config` with
  three rules (2022 key, `none` on a cleartext wire, `mode=quic`), wired into
  `parse_share_url` and `fields_to_parsed`. Tests: the §4 matrix, both funnels.

## Slice C — certificate pin (D6, D7) and routing (D8)

- **T9 — pin.** `security/`: PEM→DER→`webpki` SPKI→SHA-256; plugin `cert` (file
  read, 64 KiB cap) and `certRaw`; merge into the existing pin field; conflict
  with `security.tls.pin_sha256` when the digests differ → named refusal.
  `TlsError::PinMismatch` → `NativeError::CertPinMismatch` → evidence
  `CertNotValidForName` → `[cert]`. Tests: match, different key, same-key
  re-issue, row isolation, missing file, conflict.
- **T10 — routing.** `ops/connect.rs::resolve_runtime_core` asks for native when
  the config is supported, keeping proxy-all/unloaded precedence and the
  `link.core_type` fallback. Tests: legacy `SingBox`-stamped row → `Native`;
  refused config → stamp.

## Slice D — closure

- **T11 — docs.** `native-core.md`, `native-core-integration.md`,
  `crypto-dependencies.md`, spec status + `INDEX.md` status.
- **T12 — gate.** `cargo fmt`, workspace clippy `-D warnings`,
  `cargo nextest run --workspace`, hakari; the opt-in `native-e2e` rows.

## Acceptance

Spec §11 items 1–6, each covered by a named test in its task.
