//! `ClientHello` parser: decodes a handshake message back into structured
//! fields for fingerprinting and introspection.

use crate::error::TlsError;

/// Parsed view of a `ClientHello` handshake message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedClientHello {
    /// TLS legacy record version, e.g. `0x0303`.
    pub legacy_version: u16,
    /// Client random (RFC 8446 §4.1.2).
    pub random: [u8; 32],
    /// Legacy session id; empty when absent.
    pub session_id: Vec<u8>,
    /// Cipher suites in wire order.
    pub cipher_suites: Vec<u16>,
    /// Compression methods in wire order.
    pub compression_methods: Vec<u8>,
    /// Extensions in wire order: `(type, body)`.
    pub extensions: Vec<(u16, Vec<u8>)>,
}

impl ParsedClientHello {
    /// Returns the body of the extension with the given type.
    #[must_use]
    pub fn extension(&self, ty: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(t, _)| *t == ty)
            .map(|(_, data)| data.as_slice())
    }
}

/// Decodes a `ClientHello` handshake message (type `0x01` + 3-byte length +
/// body) into structured fields.
///
/// Trailing bytes after the declared handshake body are tolerated (the
/// message may share a record or flight with other handshake messages).
/// Truncated or malformed messages are rejected with
/// [`TlsError::Handshake`].
pub fn parse_hello(handshake_bytes: &[u8]) -> Result<ParsedClientHello, TlsError> {
    let mut msg = Reader::new(handshake_bytes);
    if msg.u8()? != 0x01 {
        return Err(TlsError::Handshake(
            "expected ClientHello handshake type 0x01".to_string(),
        ));
    }
    let body_len = msg.u24()?;
    let body = msg.take(body_len)?;
    // Tolerate trailing data: anything past the declared body length (e.g.
    // further handshake messages in the same flight) is not part of this
    // `ClientHello` and is ignored.
    let mut r = Reader::new(body);

    let legacy_version = r.u16()?;
    let random_bytes = r.take(32)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(random_bytes);

    let sid_len = usize::from(r.u8()?);
    let session_id = r.take(sid_len)?.to_vec();

    let cs_len = usize::from(r.u16()?);
    if cs_len % 2 != 0 {
        return Err(TlsError::Handshake(
            "cipher suite list length is odd".to_string(),
        ));
    }
    let cs_bytes = r.take(cs_len)?;
    let cipher_suites = cs_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();

    let comp_len = usize::from(r.u8()?);
    let compression_methods = r.take(comp_len)?.to_vec();

    let ext_total = usize::from(r.u16()?);
    let ext_bytes = r.take(ext_total)?;
    let mut exts = Reader::new(ext_bytes);
    let mut extensions = Vec::new();
    while !exts.is_empty() {
        let ty = exts.u16()?;
        let len = usize::from(exts.u16()?);
        let data = exts.take(len)?.to_vec();
        extensions.push((ty, data));
    }

    Ok(ParsedClientHello {
        legacy_version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        extensions,
    })
}

/// Byte cursor over a slice; every read is bounds-checked and surfaces
/// [`TlsError::Handshake`] on truncation or length overflow.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns `true` when the cursor has consumed the whole buffer.
    const fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }

    /// Takes the next `n` bytes, failing with [`TlsError::Handshake`] when
    /// fewer remain.
    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| TlsError::Handshake("message length overflows usize".to_string()))?;
        let out = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| TlsError::Handshake("truncated message".to_string()))?;
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, TlsError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TlsError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<usize, TlsError> {
        let b = self.take(3)?;
        Ok((usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TlsError;

    /// Builds a minimal valid `ClientHello` handshake message: version
    /// `0x0303`, 32 bytes of random, a 32-byte session id, two cipher
    /// suites, compression method `0x00` and no extensions.
    fn minimal_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x42; 32]);
        body.push(32);
        body.extend_from_slice(&[0x42; 32]);
        body.extend_from_slice(&(2 * 2u16).to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        body.push(1);
        body.push(0x00);
        body.extend_from_slice(&0x0000u16.to_be_bytes());

        let mut hs = Vec::with_capacity(4 + body.len());
        hs.push(0x01);
        let len = u32::try_from(body.len()).expect("tiny body");
        hs.extend_from_slice(&len.to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        hs
    }

    /// Appends a `signature_algorithms` extension with the given schemes to
    /// a handshake message built by [`minimal_hello`] (its extension block
    /// is currently empty, so this rewrites the length field).
    fn with_signature_algorithms(schemes: &[u16]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x42; 32]);
        body.push(32);
        body.extend_from_slice(&[0x42; 32]);
        body.extend_from_slice(&(2 * 2u16).to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        body.push(1);
        body.push(0x00);

        let mut ext = Vec::with_capacity(4 + 2 + schemes.len() * 2);
        ext.extend_from_slice(&0x000du16.to_be_bytes());
        let list_len = u16::try_from(schemes.len() * 2).expect("tiny list");
        ext.extend_from_slice(&(2 + list_len).to_be_bytes());
        ext.extend_from_slice(&list_len.to_be_bytes());
        for scheme in schemes {
            ext.extend_from_slice(&scheme.to_be_bytes());
        }
        body.extend_from_slice(&u16::try_from(ext.len()).expect("tiny ext").to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = Vec::with_capacity(4 + body.len());
        hs.push(0x01);
        let len = u32::try_from(body.len()).expect("tiny body");
        hs.extend_from_slice(&len.to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        hs
    }

    #[test]
    fn parses_minimal_hello() {
        let parsed = parse_hello(&minimal_hello()).unwrap();
        assert_eq!(parsed.legacy_version, 0x0303);
        assert_eq!(parsed.random, [0x42; 32]);
        assert_eq!(parsed.session_id, vec![0x42; 32]);
        assert_eq!(parsed.cipher_suites, vec![0x1301, 0x1302]);
        assert_eq!(parsed.compression_methods, vec![0x00]);
        assert!(parsed.extensions.is_empty());
        assert!(parsed.extension(0x000d).is_none());
    }

    #[test]
    fn parses_extensions_in_wire_order() {
        let parsed = parse_hello(&with_signature_algorithms(&[0x0403, 0x0804])).unwrap();
        let sig = parsed.extension(0x000d).expect("signature_algorithms");
        assert_eq!(sig, &[0x00, 0x04, 0x04, 0x03, 0x08, 0x04]);
        assert_eq!(parsed.extensions.len(), 1);
    }

    #[test]
    fn tolerates_trailing_data() {
        // A second handshake message or record payload after this one must
        // not fail the parse.
        let mut bytes = minimal_hello();
        bytes.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x02]);
        let parsed = parse_hello(&bytes).unwrap();
        assert_eq!(parsed.cipher_suites, vec![0x1301, 0x1302]);
    }

    #[test]
    fn rejects_truncated_body() {
        let bytes = minimal_hello();
        assert!(matches!(
            parse_hello(&bytes[..bytes.len() - 4]),
            Err(TlsError::Handshake(_))
        ));
        assert!(matches!(
            parse_hello(&bytes[..8]),
            Err(TlsError::Handshake(_))
        ));
    }

    #[test]
    fn rejects_wrong_handshake_type() {
        let mut bytes = minimal_hello();
        bytes[0] = 0x02; // ServerHello, not ClientHello
        assert!(matches!(parse_hello(&bytes), Err(TlsError::Handshake(_))));
    }

    #[test]
    fn rejects_empty_input() {
        assert!(matches!(parse_hello(&[]), Err(TlsError::Handshake(_))));
    }
}
