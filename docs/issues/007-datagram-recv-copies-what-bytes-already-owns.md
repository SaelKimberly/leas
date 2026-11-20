# 007 — The datagram receive path copies every payload that already lives in a `Bytes`

- **Location:** `crates/leas-native/src/protocol/hysteria2/udp.rs:124-125`
  (`addr.to_string()`, `rest[addr_len..].to_vec()`),
  `crates/leas-native/src/protocol/vless/packet.rs:156`
  (`Bytes::copy_from_slice(payload)`), and — for hysteria2 only — the seam that
  forces its copy: `crates/leas-native/src/protocol/mod.rs:422-426`
  (`to_bytes`) applied at `mod.rs:311-314` / `:412-415`
- **Severity:** low
- **Status:** theory
- **Domain:** native-protocol

## Hypothesis

`PacketTunnel::recv` / `PacketReader::recv` already return
`io::Result<Option<(Option<SocketAddr>, bytes::Bytes)>>` — but four of the
seven carriers (`trojan`, `hysteria2`, `ss`, `anytls`) produce a `Vec<u8>`
internally and `mod.rs` converts with `Bytes::from(Vec)` (a move, no copy).
Two copies of a `Bytes` therefore survive the seam for two different reasons:

- hysteria2 — a carrier-contract consequence. Its reader returns `Vec`, so the
  seam's `to_bytes` is the only way out, and `UdpMessage::parse` cannot hand
  the payload through: quinn's `Connection::read_datagram()` already returns
  `Bytes` (`quinn 0.11.12`, `Cargo.toml:73`), but the parse takes `&[u8]` and
  does `rest[addr_len..].to_vec()` — one allocation and one full copy per
  received datagram, plus `addr.to_string()` for the address.
- VLESS packetaddr — local to the frame decoder, not the seam. `ReadState`
  already returns `Bytes` (`packet.rs:145`) and never reaches `to_bytes`;
  `FrameReader` hands the frame up as a `Bytes` (`packet.rs:149`,
  `let Some(frame)`), and the packetaddr arm throws it away with
  `Bytes::copy_from_slice(payload)` — second allocation and copy of the same
  datagram, entirely inside this arm.

The steady state of the *send* direction in both carriers is allocation-free
(reused scratch: `trojan/mod.rs:363-368`, `hysteria2/udp.rs:287-296`), so the
asymmetry is on the receive side only.

## Evidence

- `crates/leas-native/src/protocol/mod.rs:422-426`:

  ```rust
  fn to_bytes(
      r: std::io::Result<Option<(Option<std::net::SocketAddr>, Vec<u8>)>>,
  ) -> std::io::Result<Option<(Option<std::net::SocketAddr>, bytes::Bytes)>> {
      r.map(|o| o.map(|(dest, payload)| (dest, bytes::Bytes::from(payload))))
  }
  ```

  `Bytes::from(Vec<u8>)` reuses the allocation, so the conversion itself is
  free — the cost was already paid when the carrier built the `Vec`.

- The zero-copy form is already the house pattern in the same module:
  `vmess/udp.rs:83` returns `self.scratch.split_to(n).freeze()` and
  `vless/udp.rs:102` returns `self.payload.split_to(n).freeze()`. Both hand
  back a slice of a refcounted buffer, no copy.
- hysteria2's read: `hysteria2/udp.rs:263` binds `bytes` from
  `conn.read_datagram().await` (a `Bytes`) and passes `&bytes` to
  `accept_datagram` → `UdpMessage::parse` (`:107`), which owns everything even
  though the single-fragment case (`frag_count <= 1`, `:159`) never keeps the
  message.
- VLESS packetaddr read: `packet.rs:150-157` — `Raw` mode returns `frame`
  untouched; `PacketAddr` mode copies. Only the address header has to be
  parsed (`packetaddr::decode_dest` returns `&[u8]` for the rest, `:60-79`).
- `bytes 1.12.1` provides `Bytes::slice_ref(&self, subset: &[u8]) -> Bytes`
  for exactly this: the payload slice comes out of the same allocation.
- Callers are a single seam: the relay consumes `PacketReader::recv` at
  `crates/leas-native/src/inbound/mod.rs:1467`; nothing else pattern-matches
  the carriers' inner return type.

## Impact

One `malloc` + one full `memcpy` per received datagram on the two carriers
whose servers are UDP-heavy by construction (hysteria2 is a QUIC proxy sold on
UDP performance; packetaddr is VLESS's per-packet-address UDP mode). A DNS or
game flow at a few thousand datagrams per second turns that into megabytes of
allocator traffic per second, and it is exactly the traffic the receive-side
scratch reuse was built to avoid.

## Fix sketch

Move `Bytes` down into the carrier contract so no carrier is forced to stage a
`Vec`:

1. `PacketTunnel::{Vless,Vmess,Trojan,Hysteria2,Ss,AnyTls,Sbox}::recv` and the
   matching `PacketReader` halves all return
   `Option<(Option<SocketAddr>, Bytes)>` (`PacketWriter::send` is unaffected — it
   takes `&[u8]`); `to_bytes` and its eight call sites in `mod.rs` are deleted.
2. hysteria2: keep the wire parse over `&Bytes`, and in the `frag_count <= 1`
   fast path return `bytes.slice_ref(data)` (and parse the address straight
   into `Option<SocketAddr>`, no `String`). The owned `UdpMessage` stays for
   the fragmenting path — the defragger genuinely keeps fragments.
3. vless packetaddr: `frame.slice_ref(payload)`.
4. trojan / ss / anytls: build their `Vec` as today, `freeze()` it — behaviour
   unchanged, the contract now just permits the zero-copy carriers.

Test that pins it: a `#[rstest]` row per carrier asserting the returned
`Bytes` shares the source allocation (e.g. hysteria2: send one unfragmented
`UDPMessage` through a duplex and assert the received `Bytes` pointer range
falls inside the read buffer's range — or, cheaper and less brittle, assert
`recv` allocates zero times on the steady path with the crate's counting
allocator, the `leas-hotpath` pattern).

## Related

- [003](003-udp-association-eager-buffers.md) — the other per-association UDP
  cost: 3 × 64 KiB held eagerly for sockets that never see a datagram.
- [009](009-hysteria2-defragger-sizes-slots-from-untrusted-frag-count.md) — the
  same receive function; that issue covers what the defragger allocates from a
  peer-controlled field, this one what the fast path copies.
