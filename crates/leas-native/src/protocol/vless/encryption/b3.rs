//! Minimal portable BLAKE3 (derive-key only).
//!
//! xray's `encryption` package derives AEAD/CTR keys with
//! `blake3.DeriveKey(k, string(ctx), key)` where `ctx` is BINARY (the 16-byte
//! client IV, the 1216-byte PFS public key, a record header+payload). The
//! `blake3` crate only accepts `&str` contexts (`derive_key`,
//! `Hasher::new_derive_key`) and exposes no byte-context derive-key API
//! (`hazmat::hash_derive_key_context` is `&str` too, `guts` has no flag
//! support), so the derive-key construction is implemented here on the
//! reference algorithm. Test-only cross-validation against the `blake3`
//! crate (dev-dependency) proves byte-equality for string contexts; the
//! binary-context vectors were generated with Go's `lukechampine.com/blake3`
//! (the exact library xray uses).
//!
//! Only what the wire needs: 32-byte root output over arbitrary-length
//! input with the `DERIVE_KEY_CONTEXT` / `DERIVE_KEY_MATERIAL` flag pair.

const OUT_LEN: usize = 32;
const KEY_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

/// `BLOCK_LEN` as `u32` (the compress API takes the block length wide).
const BLOCK_LEN_U32: u32 = 64;

const CHUNK_START: u8 = 1 << 0;
const CHUNK_END: u8 = 1 << 1;
const PARENT: u8 = 1 << 2;
const ROOT: u8 = 1 << 3;
const DERIVE_KEY_CONTEXT: u8 = 1 << 5;
const DERIVE_KEY_MATERIAL: u8 = 1 << 6;

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

const fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    // Mix the columns.
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    // Mix the diagonals.
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0; 16];
    for (i, &pi) in MSG_PERMUTATION.iter().enumerate() {
        permuted[i] = m[pi];
    }
    *m = permuted;
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "BLAKE3 counter enters the state words as two u32 halves by spec"
)]
fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut block = *block_words;
    round(&mut state, &block); // round 1
    permute(&mut block);
    round(&mut state, &block); // round 2
    permute(&mut block);
    round(&mut state, &block); // round 3
    permute(&mut block);
    round(&mut state, &block); // round 4
    permute(&mut block);
    round(&mut state, &block); // round 5
    permute(&mut block);
    round(&mut state, &block); // round 6
    permute(&mut block);
    round(&mut state, &block); // round 7
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

fn first_8_words(compression_output: [u32; 16]) -> [u32; 8] {
    let mut out = [0; 8];
    out.copy_from_slice(&compression_output[..8]);
    out
}

fn words_from_le_bytes(bytes: &[u8; 32]) -> [u32; 8] {
    let mut out = [0; 8];
    for (i, word) in out.iter_mut().enumerate() {
        *word = u32::from_le_bytes([
            bytes[4 * i],
            bytes[4 * i + 1],
            bytes[4 * i + 2],
            bytes[4 * i + 3],
        ]);
    }
    out
}

/// Incremental BLAKE3 hash over arbitrary-length input with a custom key and
/// flag set (the derive-key construction is the only user).
struct Hasher {
    chunk_state: ChunkState,
    key_words: [u32; 8],
    flags: u32,
    // Stack of complete subtree chaining values, `cv_stack[i]` = a subtree of
    // `2^(i+1)` chunks (total length 2^64 chunks is unreachable in practice).
    cv_stack: [[u32; 8]; 54],
    cv_stack_len: u8,
}

impl Hasher {
    const fn new(key_words: [u32; 8], flags: u32) -> Self {
        Self {
            chunk_state: ChunkState::new(key_words, 0, flags),
            key_words,
            flags,
            cv_stack: [[0; 8]; 54],
            cv_stack_len: 0,
        }
    }

    const fn push_stack(&mut self, cv: [u32; 8]) {
        self.cv_stack[self.cv_stack_len as usize] = cv;
        self.cv_stack_len += 1;
    }

    const fn pop_stack(&mut self) -> [u32; 8] {
        self.cv_stack_len -= 1;
        self.cv_stack[self.cv_stack_len as usize]
    }

    /// The BLAKE3 subtree-addition rule: a chunk is added by merging the
    /// right-most pair of equal-size subtrees repeatedly (the resulting CV
    /// stack encodes the tree shape).
    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], total_chunks: u64) {
        let mut new_total = total_chunks;
        while new_total & 1 == 0 {
            new_cv = parent_cv(self.pop_stack(), new_cv, self.key_words, self.flags);
            new_total >>= 1;
        }
        self.push_stack(new_cv);
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(self.key_words, total_chunks, self.flags);
            }
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    fn finalize_xof(&self) -> Output {
        let mut output = self.chunk_state.output();
        for i in (0..self.cv_stack_len).rev() {
            let parent_input: [[u32; 8]; 2] = [self.cv_stack[i as usize], output.chaining_value()];
            output = Output::new(
                self.key_words,
                &parent_input_as_words(&parent_input),
                0,
                BLOCK_LEN_U32,
                u32::from(PARENT) | self.flags,
            );
        }
        output
    }
}

fn parent_input_as_words(pair: &[[u32; 8]; 2]) -> [u32; 16] {
    let mut out = [0; 16];
    out[..8].copy_from_slice(&pair[0]);
    out[8..].copy_from_slice(&pair[1]);
    out
}

struct ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    const fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            cv: key_words,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    const fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    const fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START as u32
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len as usize == BLOCK_LEN {
                let block_words = self.block_words();
                self.cv = first_8_words(compress(
                    &self.cv,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN_U32,
                    self.flags | self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let want = BLOCK_LEN - self.block_len as usize;
            let take = want.min(input.len());
            let dst_start = self.block_len as usize;
            self.block[dst_start..dst_start + take].copy_from_slice(&input[..take]);
            self.block_len += u8::try_from(take).expect("take < BLOCK_LEN");
            input = &input[take..];
        }
    }

    fn block_words(&self) -> [u32; 16] {
        let mut words = [0u32; 16];
        for (word, chunk) in words.iter_mut().zip(self.block.as_chunks::<4>().0.iter()) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        words
    }

    fn output(&self) -> Output {
        Output::new(
            self.cv,
            &self.block_words(),
            self.chunk_counter,
            u32::from(self.block_len),
            self.flags | self.start_flag() | u32::from(CHUNK_END),
        )
    }
}

/// A finalized BLAKE3 state: either a chunk output or a parent output, ready
/// to emit the root output stream (XOF).
struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    const fn new(
        input_chaining_value: [u32; 8],
        block_words: &[u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
    ) -> Self {
        Self {
            input_chaining_value,
            block_words: *block_words,
            counter,
            block_len,
            flags,
        }
    }

    fn chaining_value(&self) -> [u32; 8] {
        first_8_words(compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    fn root_output_bytes(&self, out: &mut [u8]) {
        for (out_block, out_slice) in out.chunks_mut(2 * OUT_LEN).enumerate() {
            let words = compress(
                &self.input_chaining_value,
                &self.block_words,
                self.counter + out_block as u64,
                self.block_len,
                self.flags | u32::from(ROOT),
            );
            for (word, dst) in words.iter().zip(out_slice.chunks_mut(4)) {
                let bytes = word.to_le_bytes();
                dst.copy_from_slice(&bytes[..dst.len()]);
            }
        }
    }
}

fn parent_cv(
    left_child: [u32; 8],
    right_child: [u32; 8],
    key_words: [u32; 8],
    flags: u32,
) -> [u32; 8] {
    let mut block_words = [0; 16];
    block_words[..8].copy_from_slice(&left_child);
    block_words[8..].copy_from_slice(&right_child);
    first_8_words(compress(
        &key_words,
        &block_words,
        0,
        BLOCK_LEN_U32,
        u32::from(PARENT) | flags,
    ))
}

/// BLAKE3 `derive_key(context, key_material)` with a BINARY context —
/// byte-compatible with Go's `blake3.DeriveKey(dst, ctx, srcKey)`, which
/// xray feeds non-UTF-8 contexts (random IVs, ciphertext material).
pub fn derive_key_bytes(context: &[u8], key_material: &[u8]) -> [u8; KEY_LEN] {
    // Step 1: hash the context with the DERIVE_KEY_CONTEXT flag.
    let mut context_hasher = Hasher::new(IV, u32::from(DERIVE_KEY_CONTEXT));
    context_hasher.update(context);
    let context_key: [u8; KEY_LEN] = {
        let mut out = [0; KEY_LEN];
        context_hasher.finalize_xof().root_output_bytes(&mut out);
        out
    };
    // Step 2: keyed hash of the key material with the DERIVE_KEY_MATERIAL
    // flag, keyed by the context hash.
    let mut material_hasher = Hasher::new(
        words_from_le_bytes(&context_key),
        u32::from(DERIVE_KEY_MATERIAL),
    );
    material_hasher.update(key_material);
    let mut out = [0; KEY_LEN];
    material_hasher.finalize_xof().root_output_bytes(&mut out);
    out
}

/// Plain 32-byte BLAKE3 hash (xray's `blake3.Sum256` — the relay hash32
/// chain).
pub(super) fn hash32(input: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Hasher::new(IV, 0);
    hasher.update(input);
    let mut out = [0; OUT_LEN];
    hasher.finalize_xof().root_output_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// String contexts must match the reference `blake3` crate exactly —
    /// this is what proves the hand-rolled algorithm.
    #[test]
    fn derive_key_matches_reference_crate() {
        assert_eq!(
            derive_key_bytes(b"VLESS", b"abc"),
            blake3::derive_key("VLESS", b"abc")
        );
        assert_eq!(derive_key_bytes(b"", b""), blake3::derive_key("", b""));
        let long_ctx = vec![b'x'; 5000]; // multi-chunk context
        let long_key = vec![7u8; 3000]; // multi-chunk key material
        assert_eq!(
            derive_key_bytes(&long_ctx, &long_key),
            blake3::derive_key(std::str::from_utf8(&long_ctx).unwrap(), &long_key)
        );
    }

    /// Binary contexts (impossible via the crate's API) against vectors
    /// generated with Go's `lukechampine.com/blake3` v1.3.0 — xray's exact
    /// dependency.
    #[test]
    fn derive_key_binary_context_go_vectors() {
        let bin_ctx = [0x00, 0xff, 0x10, 0x83, 0x7e, 0x01];
        assert_eq!(
            derive_key_bytes(&bin_ctx, b"src-key-bytes"),
            [
                0x21, 0x2d, 0x24, 0x63, 0x82, 0x46, 0x2e, 0x01, 0x6a, 0x90, 0x55, 0x4e, 0x03, 0x4c,
                0xc9, 0x31, 0x67, 0xf1, 0x0e, 0x22, 0x94, 0x0d, 0x79, 0x5f, 0x84, 0x3b, 0x0f, 0x36,
                0x0b, 0x6c, 0x7c, 0x68
            ]
        );
        let long_ctx: Vec<u8> = (0..1500)
            .map(|i| u8::try_from(i % 251).expect("in range"))
            .collect();
        assert_eq!(
            derive_key_bytes(&long_ctx, b"material-1234"),
            [
                0xbc, 0x07, 0x41, 0x94, 0x2a, 0xc7, 0xa0, 0xaf, 0x17, 0xc8, 0x8b, 0xd3, 0x56, 0xd0,
                0x7a, 0x1b, 0xc8, 0x07, 0x9a, 0xda, 0x9a, 0x2c, 0x24, 0xd2, 0x65, 0xda, 0x3f, 0x25,
                0x58, 0x11, 0xea, 0xa8
            ]
        );
    }

    #[test]
    fn hash32_matches_reference_crate() {
        assert_eq!(hash32(b"hello"), *blake3::hash(b"hello").as_bytes());
        let long = vec![9u8; 3000];
        assert_eq!(hash32(&long), *blake3::hash(&long).as_bytes());
    }

    /// The in-tree hand-rolled BLAKE3 (already pinned against the `blake3`
    /// crate by `derive_key_matches_reference_crate`) must agree with the
    /// helper on the 2022 context — an implementation the crate call cannot
    /// silently define into correctness.
    #[test]
    fn ss2022_subkey_matches_hand_rolled_derive_key() {
        let key = [0x22_u8; 32];
        let salt = [0x33_u8; 32];
        let material = [key.as_slice(), salt.as_slice()].concat();
        assert_eq!(
            crate::crypto::kdf::blake3_derive_key("shadowsocks 2022 session subkey", &material),
            derive_key_bytes(b"shadowsocks 2022 session subkey", &material)
        );
    }
}
