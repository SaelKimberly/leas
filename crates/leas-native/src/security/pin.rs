//! SPKI pin resolution for the SIP003 `cert` / `certRaw` options.
//!
//! The reference reads these as a **client CA**: v2ray-plugin marks the
//! certificate `AUTHORITY_VERIFY` (`main.go:186-190`) and v2ray-core appends it
//! to the root pool (`transport/internet/tls/config_other.go:43-52`). This
//! client instead pins the **key**: the leaf's SPKI SHA-256 must equal the
//! pinned certificate's own SPKI digest, so the row trusts exactly that server
//! and hands the certificate to nobody else (design spec D6/D7).
//!
//! Reuse, not a second verifier: the digest is the same value
//! [`WebPkiVerifier::with_pin`](leas_tls::verify::WebPkiVerifier) already
//! compares, and `security::fingerprint` already routes `pinSHA256` into it.

use base64::Engine as _;
use leas_proto::proto_spec::PluginSpec;

use super::fingerprint::decode_pin_sha256;
use crate::error::NativeError;

/// A pinned certificate file larger than this is refused rather than read: the
/// path comes from subscription data, so the read is bounded.
const MAX_PIN_FILE: u64 = 64 * 1024;

/// The row's SPKI pin: the explicit `tls.pinSHA256`, the plugin's
/// `cert`/`certRaw`, or a conflict between them.
///
/// A row that states both faces a single question — which anchor is the truth —
/// and two DIFFERENT answers are an undecidable trust statement, so that is a
/// config error rather than a silent preference.
pub(crate) async fn resolve(
    explicit: Option<&str>,
    spec: Option<&PluginSpec>,
) -> Result<Option<[u8; 32]>, NativeError> {
    let explicit = decode_pin_sha256(explicit)?;
    let plugin = plugin_pin(spec).await?;
    match (explicit, plugin) {
        (Some(a), Some(b)) if a != b => Err(NativeError::Config(
            "row states two different certificate pins (`security.tls.pinSHA256` and the \
             plugin's `cert`/`certRaw`); which one is the trust anchor is not decidable"
                .into(),
        )),
        (Some(pin), _) => Ok(Some(pin)),
        (None, pin) => Ok(pin),
    }
}

/// The pin a plugin certificate states, if any.
///
/// Only when the plugin actually runs TLS (`tls` present): a certificate on a
/// plaintext plugin row is inert in the reference too, because v2ray-plugin
/// reads it inside its `if *tlsEnabled` branch (`main.go:165-190`).
async fn plugin_pin(spec: Option<&PluginSpec>) -> Result<Option<[u8; 32]>, NativeError> {
    let Some(spec) = spec.filter(|spec| spec.needs_tls()) else {
        return Ok(None);
    };
    let text = if let Some(path) = spec.cert_path() {
        let path = std::path::Path::new(path);
        let meta = tokio::fs::metadata(path).await.map_err(|e| {
            NativeError::Config(format!(
                "shadowsocks plugin `cert` file {}: {e}",
                path.display()
            ))
        })?;
        if meta.len() > MAX_PIN_FILE {
            return Err(NativeError::Config(format!(
                "shadowsocks plugin `cert` file {} is larger than {MAX_PIN_FILE} bytes",
                path.display()
            )));
        }
        let bytes = tokio::fs::read(path).await.map_err(|e| {
            NativeError::Config(format!(
                "shadowsocks plugin `cert` file {}: {e}",
                path.display()
            ))
        })?;
        String::from_utf8_lossy(&bytes).into_owned()
    } else if let Some(raw) = spec.cert_raw() {
        raw.to_owned()
    } else {
        return Ok(None);
    };
    let der = certificate_der(&text).map_err(|e| {
        NativeError::Config(format!(
            "shadowsocks plugin certificate pin: {e} (a pin that cannot be read is never \
             replaced by system roots)"
        ))
    })?;
    leas_tls::verify::spki_sha256(&der)
        .map(Some)
        .map_err(|e| NativeError::Config(format!("shadowsocks plugin certificate pin: {e}")))
}

/// The first certificate in a PEM document, or a bare base64 body.
///
/// `cert` supplies PEM armour; `certRaw` supplies the body without it (the
/// reference wraps it back — `main.go:73-76`), and exporters escape its `=` as
/// `\=` (unescaped by the option parser), so only whitespace is stripped here.
fn certificate_der(text: &str) -> Result<Vec<u8>, String> {
    let body = if let Some(start) = text.find("-----BEGIN CERTIFICATE-----") {
        let rest = &text[start + "-----BEGIN CERTIFICATE-----".len()..];
        let end = rest
            .find("-----END CERTIFICATE-----")
            .ok_or_else(|| "PEM block has no END marker".to_owned())?;
        &rest[..end]
    } else {
        text
    };
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&compact)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&compact))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&compact))
        .map_err(|e| format!("certificate is not PEM/base64: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use leas_proto::proto_spec::ss_plugin::PluginSpec;

    fn spec(name: &str, opts: &str) -> PluginSpec {
        PluginSpec::from_parts(Some(name), opts)
    }

    #[test]
    fn certificate_der_reads_pem_and_bare_bodies() {
        // One real DER certificate, encoded both ways.
        let der = rcgen::generate_simple_self_signed(vec!["pin.example".into()])
            .unwrap()
            .cert
            .der()
            .to_vec();
        let body = base64::engine::general_purpose::STANDARD.encode(&der);
        assert_eq!(certificate_der(&body).unwrap(), der);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----");
        assert_eq!(certificate_der(&pem).unwrap(), der);
        assert!(certificate_der("not a certificate").is_err());
    }

    #[tokio::test]
    async fn cert_raw_without_tls_is_inert() {
        let plain = spec("v2ray-plugin", "host=h");
        assert!(plugin_pin(Some(&plain)).await.unwrap().is_none());
        let with_tls = spec("v2ray-plugin", "host=h;tls");
        assert!(
            plugin_pin(Some(&with_tls)).await.unwrap().is_none(),
            "no cert key at all"
        );
    }

    #[tokio::test]
    async fn a_conflicting_explicit_pin_is_a_config_error() {
        let certified = rcgen::generate_simple_self_signed(vec!["pin.example".into()]).unwrap();
        let body = base64::engine::general_purpose::STANDARD.encode(certified.cert.der());
        let row = spec("v2ray-plugin", &format!("host=h;tls;certRaw={body}"));
        let err = resolve(
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            Some(&row),
        )
        .await
        .expect_err("two different anchors cannot be reconciled");
        assert!(matches!(err, NativeError::Config(_)));
    }

    /// The `cert` option is a PATH: the file is read (bounded) and its first
    /// certificate becomes the pin; a missing file fails the row loudly.
    #[tokio::test]
    async fn the_cert_path_is_read_and_pinned() {
        let certified = rcgen::generate_simple_self_signed(vec!["pin.example".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.pem");
        std::fs::write(&path, certified.cert.pem()).unwrap();
        let row = spec(
            "v2ray-plugin",
            &format!("host=h;tls;cert={}", path.display()),
        );
        let pin = plugin_pin(Some(&row)).await.unwrap().expect("a pin");
        assert_eq!(
            pin,
            leas_tls::verify::spki_sha256(certified.cert.der()).unwrap()
        );

        let missing = spec("v2ray-plugin", "host=h;tls;cert=/nonexistent/pin.pem");
        assert!(matches!(
            plugin_pin(Some(&missing)).await,
            Err(NativeError::Config(_))
        ));
    }

    #[tokio::test]
    async fn the_plugin_pin_matches_the_certificate_spki() {
        let certified = rcgen::generate_simple_self_signed(vec!["pin.example".into()]).unwrap();
        let body = base64::engine::general_purpose::STANDARD.encode(certified.cert.der());
        let row = spec("v2ray-plugin", &format!("host=h;tls;certRaw={body}"));
        let pin = plugin_pin(Some(&row)).await.unwrap().expect("a pin");
        assert_eq!(
            pin,
            leas_tls::verify::spki_sha256(certified.cert.der()).unwrap()
        );
    }
}
