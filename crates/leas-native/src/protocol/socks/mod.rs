//! SOCKS5 client handshake (no-auth / username-password) over the tunnel.
//!
//! The client mirror of the server codec in [`crate::inbound::socks5`]:
//! after the dial → transport → security chain has produced the byte
//! stream, this module writes the RFC 1928 greeting, negotiates the method
//! (RFC 1929 sub-negotiation when credentials are configured), sends the
//! CONNECT request for [`LinkContext::target`], and returns the stream once
//! the server replies success. The tunnel itself is transparent — the
//! returned [`BoxStream`] is the handshake stream.
//!
//! Reference: fast-socks5 `client.rs` (`use_stream` path), RFC 1928/1929,
//! v2ray-core `proxy/socks`.
//!
//! TCP CONNECT only: SOCKS5 UDP datagrams (ASSOCIATE) ride a raw UDP socket
//! to the proxy, not the possibly-TLS-wrapped byte stream this layer sits
//! on, so there is no `PacketTunnel` here — a UDP client needs its own
//! socket-shape design.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::BoxStream;
use crate::addr::{TargetAddr, encode_addr_port_last};
use crate::context::LinkContext;
use crate::error::{NativeError, timeouts};
use crate::inbound::socks5::{Command, Method, Socks5Error, VERSION};
use leas_proto::proto_spec::{ProtocolKind, Socks5Config};

/// Perform the SOCKS5 client handshake over an already-established stream.
///
/// # Errors
/// Returns [`NativeError::Protocol`] on a handshake failure (bad version,
/// refused method, refused request, RFC 1929 rejection), [`NativeError::Io`]
/// on transport errors, and [`NativeError::Timeout`] if any step exceeds
/// [`timeouts::PROTOCOL`].
pub async fn connect(
    ctx: &LinkContext,
    mut stream: BoxStream,
    cfg: &Socks5Config,
) -> Result<BoxStream, NativeError> {
    let limit = timeouts::PROTOCOL;

    // Offer username/password first when credentials are configured, else
    // no-auth only. An empty username counts as absent, matching every other
    // consumer of this config (`add_user_if_present` in the xray/sing-box
    // injectors, `opt_string` in the config forms) — an RFC 1929 frame with
    // `ULEN = 0` is outside the spec's 1-255 range and servers reject it.
    // (fast-socks5 offers both methods; xray offers exactly one.)
    let username = cfg.username.as_deref().filter(|user| !user.is_empty());
    let methods = if username.is_some() {
        vec![Method::UsernamePassword, Method::None]
    } else {
        vec![Method::None]
    };

    let selected = tokio::time::timeout(limit, client_greeting(&mut stream, &methods))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "socks5 client greeting",
            limit,
        })?
        .map_err(err_to_native)?;

    if selected == Method::UsernamePassword {
        let Some(user) = username else {
            return Err(NativeError::Protocol {
                kind: ProtocolKind::Socks,
                detail: "server selected password auth but no username is configured".into(),
            });
        };
        let pass = cfg.password.as_deref().unwrap_or("");
        tokio::time::timeout(limit, client_auth(&mut stream, user, pass))
            .await
            .map_err(|_| NativeError::Timeout {
                step: "socks5 client auth",
                limit,
            })?
            .map_err(err_to_native)?;
    }

    tokio::time::timeout(
        limit,
        client_request(&mut stream, Command::Connect, &ctx.target),
    )
    .await
    .map_err(|_| NativeError::Timeout {
        step: "socks5 client request",
        limit,
    })?
    .map_err(err_to_native)?;

    Ok(stream)
}

/// Write the greeting (`VER, NMETHODS, METHODS[]`) and read the server's
/// method selection (`VER, METHOD`).
async fn client_greeting<S>(stream: &mut S, methods: &[Method]) -> Result<Method, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut packet = Vec::with_capacity(2 + methods.len());
    packet.push(VERSION);
    packet.push(u8::try_from(methods.len()).expect("methods fit in a u8"));
    packet.extend(methods.iter().map(|m| *m as u8));
    stream.write_all(&packet).await?;
    stream.flush().await?;

    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await?;
    let [ver, method] = selection;
    if ver != VERSION {
        return Err(Socks5Error::InvalidVersion(ver));
    }
    match method {
        0x00 => Ok(Method::None),
        0x02 => Ok(Method::UsernamePassword),
        0xFF => Err(Socks5Error::NoAcceptableMethod),
        other => Err(Socks5Error::InvalidMethod(other)),
    }
}

/// Run the RFC 1929 username/password sub-negotiation as the client.
async fn client_auth<S>(stream: &mut S, username: &str, password: &str) -> Result<(), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let user = username.as_bytes();
    let pass = password.as_bytes();
    // Credentials come from an unvalidated share URL, so an over-long one is
    // an error, never a panic.
    // The frame carries the cleartext password; wipe the heap copy.
    let mut packet = Zeroizing::new(Vec::with_capacity(3 + user.len() + pass.len()));
    packet.push(0x01);
    packet.push(u8::try_from(user.len()).map_err(|_| Socks5Error::CredentialTooLong)?);
    packet.extend_from_slice(user);
    packet.push(u8::try_from(pass.len()).map_err(|_| Socks5Error::CredentialTooLong)?);
    packet.extend_from_slice(pass);
    stream.write_all(&packet).await?;
    stream.flush().await?;

    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await?;
    if status[0] != 0x01 {
        return Err(Socks5Error::InvalidAuthVersion(status[0]));
    }
    if status[1] != 0 {
        return Err(Socks5Error::AuthFailed);
    }
    Ok(())
}

/// Send a request (`VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT`) and read the
/// reply, consuming (and discarding) the BND.ADDR.
async fn client_request<S>(
    stream: &mut S,
    cmd: Command,
    target: &TargetAddr,
) -> Result<(), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut packet = vec![VERSION, cmd as u8, 0x00];
    packet.extend(encode_addr_port_last(target).map_err(|e| {
        Socks5Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            e.to_string(),
        ))
    })?);
    stream.write_all(&packet).await?;
    stream.flush().await?;

    // Reply: `VER, REP, RSV` then the full `BND.ADDR` (ATYP + addr + port) —
    // read_target consumes the whole address, so only the 3-byte prefix is
    // read here.
    let mut header = [0u8; 3];
    stream.read_exact(&mut header).await?;
    let [ver, rep, rsv] = header;
    if ver != VERSION {
        return Err(Socks5Error::InvalidVersion(ver));
    }
    if rep != 0x00 {
        return Err(Socks5Error::reply(rep));
    }
    if rsv != 0 {
        // RFC 1928 §6 mandates X'00', but neither fast-socks5 nor xray
        // validates the reply's RSV — don't kill a tunnel the server accepted.
        tracing::debug!(rsv, "socks5 client: non-zero RSV in reply");
    }
    // Consume and discard the BND.ADDR that follows a successful reply.
    let _ = crate::inbound::socks5::read_target(stream).await?;
    Ok(())
}

/// Map a codec error into the native error type for a client handshake.
fn err_to_native(error: Socks5Error) -> NativeError {
    match error {
        Socks5Error::Io(io) => NativeError::Io(io),
        other => NativeError::Protocol {
            kind: ProtocolKind::Socks,
            detail: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::addr::Host;
    use crate::context::NativeConnectParams;
    use leas_proto::proto_spec::endpoint::EndpointEssentials;

    /// A `Socks5Config` built from JSON (schema-tagged, like other test
    /// configs).
    fn config(auth: Option<(&str, &str)>) -> Socks5Config {
        let value = match auth {
            Some((user, pass)) => serde_json::json!({
                "schema": "Socks",
                "username": user,
                "password": pass,
            }),
            None => serde_json::json!({ "schema": "Socks" }),
        };
        serde_json::from_value(value).expect("socks config parses")
    }

    /// A `LinkContext` whose target the handshake dials through the proxy.
    fn ctx_to(host: &str, port: u16) -> LinkContext {
        let params = NativeConnectParams::new(
            serde_json::from_value(serde_json::json!({ "schema": "Socks" }))
                .expect("protocol parses"),
            EndpointEssentials::new("proxy.invalid".to_string(), 1080),
            TargetAddr::new(Host::new(host), port),
        );
        LinkContext::new(params, TargetAddr::new(Host::new(host), port))
    }

    /// What the fake server expects to read and how it answers. Expectations
    /// are exact byte strings: a regression that swapped the address codec
    /// (port-first, VLESS family bytes) or sent the proxy endpoint instead of
    /// the target must fail here.
    struct ServerScript {
        /// Exact greeting bytes, `VER | NMETHODS | METHODS[]`.
        greeting: Vec<u8>,
        /// Method byte the server selects.
        select: u8,
        /// Exact RFC 1929 frame, when the server selects `0x02`.
        auth_frame: Option<Vec<u8>>,
        /// RFC 1929 status to answer with (0 = accepted).
        auth_status: u8,
        /// Exact CONNECT request bytes, `VER | CMD | RSV | ATYP | addr | port`.
        request: Vec<u8>,
        /// Reply code to answer the request with.
        reply_rep: u8,
    }

    impl ServerScript {
        /// A no-auth script expecting `request` verbatim.
        fn no_auth(request: Vec<u8>) -> Self {
            Self {
                greeting: vec![0x05, 0x01, 0x00],
                select: 0x00,
                auth_frame: None,
                auth_status: 0,
                request,
                reply_rep: 0x00,
            }
        }
    }

    /// The CONNECT request bytes for a domain target (port-last).
    fn domain_request(domain: &str, port: u16) -> Vec<u8> {
        let mut request = vec![0x05, 0x01, 0x00, 0x03];
        request.push(u8::try_from(domain.len()).expect("test domain ≤ 255"));
        request.extend_from_slice(domain.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());
        request
    }

    /// Run the far end of the duplex. Returns the first assertion failure
    /// instead of panicking in a detached task, so a mismatch is reported as
    /// itself rather than as the client's `UnexpectedEof`.
    async fn far_side_run(
        mut far: tokio::io::DuplexStream,
        script: ServerScript,
    ) -> Result<(), String> {
        let mut greeting = vec![0u8; script.greeting.len()];
        far.read_exact(&mut greeting)
            .await
            .map_err(|e| format!("greeting read: {e}"))?;
        if greeting != script.greeting {
            return Err(format!(
                "greeting mismatch: got {greeting:02x?}, want {:02x?}",
                script.greeting
            ));
        }
        far.write_all(&[0x05, script.select])
            .await
            .map_err(|e| format!("selection write: {e}"))?;

        if let Some(expected) = &script.auth_frame {
            let mut frame = vec![0u8; expected.len()];
            far.read_exact(&mut frame)
                .await
                .map_err(|e| format!("auth read: {e}"))?;
            if &frame != expected {
                return Err(format!(
                    "auth frame mismatch: got {frame:02x?}, want {expected:02x?}"
                ));
            }
            far.write_all(&[0x01, script.auth_status])
                .await
                .map_err(|e| format!("auth status write: {e}"))?;
            if script.auth_status != 0 {
                return Ok(());
            }
        }

        if script.request.is_empty() {
            // The client is expected to refuse before sending a request.
            return Ok(());
        }

        let mut request = vec![0u8; script.request.len()];
        far.read_exact(&mut request)
            .await
            .map_err(|e| format!("request read: {e}"))?;
        if request != script.request {
            return Err(format!(
                "CONNECT mismatch: got {request:02x?}, want {:02x?}",
                script.request
            ));
        }

        far.write_all(&[0x05, script.reply_rep, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .map_err(|e| format!("reply write: {e}"))?;
        if script.reply_rep != 0x00 {
            return Ok(());
        }
        // Echo until the client drops its half.
        let mut buf = [0u8; 64];
        loop {
            let n = far.read(&mut buf).await.map_err(|e| format!("echo: {e}"))?;
            if n == 0 {
                return Ok(());
            }
            far.write_all(&buf[..n])
                .await
                .map_err(|e| format!("echo write: {e}"))?;
        }
    }

    /// The `Protocol` detail of a socks handshake error.
    fn protocol_detail(error: &NativeError) -> &str {
        match error {
            NativeError::Protocol {
                kind: ProtocolKind::Socks,
                detail,
            } => detail,
            other => panic!("expected a socks protocol error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handshake_connects_and_echoes_no_auth() {
        let (client, server_half) = duplex(1024);
        let server = tokio::spawn(far_side_run(
            server_half,
            ServerScript::no_auth(domain_request("example.com", 443)),
        ));
        let cfg = config(None);
        let ctx = ctx_to("example.com", 443);
        let mut stream = connect(&ctx, Box::new(client), &cfg)
            .await
            .expect("handshake");
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        drop(stream);
        server.await.expect("server task").expect("server wire");
    }

    /// An IPv6 target must use ATYP `0x04` with the 16 octets and the port
    /// LAST — the SOCKS5 encoding, not the VLESS/VMess port-first one.
    #[tokio::test]
    async fn ipv6_target_uses_socks5_port_last_encoding() {
        let mut request = vec![0x05, 0x01, 0x00, 0x04];
        request.extend_from_slice(
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .expect("test address")
                .octets(),
        );
        request.extend_from_slice(&443u16.to_be_bytes());
        let (client, server_half) = duplex(1024);
        let server = tokio::spawn(far_side_run(server_half, ServerScript::no_auth(request)));
        let cfg = config(None);
        let ctx = ctx_to("2001:db8::1", 443);
        let stream = connect(&ctx, Box::new(client), &cfg)
            .await
            .expect("handshake");
        drop(stream);
        server.await.expect("server task").expect("server wire");
    }

    #[tokio::test]
    async fn handshake_uses_password_when_configured() {
        let (client, server_half) = duplex(1024);
        let server = tokio::spawn(far_side_run(
            server_half,
            ServerScript {
                // Password offered FIRST, then no-auth.
                greeting: vec![0x05, 0x02, 0x02, 0x00],
                select: 0x02,
                auth_frame: Some(vec![
                    0x01, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's',
                ]),
                auth_status: 0,
                request: domain_request("example.com", 443),
                reply_rep: 0x00,
            },
        ));
        let cfg = config(Some(("user", "pass")));
        let ctx = ctx_to("example.com", 443);
        let mut stream = connect(&ctx, Box::new(client), &cfg)
            .await
            .expect("handshake");
        stream.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
        drop(stream);
        server.await.expect("server task").expect("server wire");
    }

    /// An empty username is absent: only no-auth is offered, so no RFC 1929
    /// frame with `ULEN = 0` ever reaches the wire.
    #[tokio::test]
    async fn empty_username_is_treated_as_absent() {
        let (client, server_half) = duplex(1024);
        let server = tokio::spawn(far_side_run(
            server_half,
            ServerScript::no_auth(domain_request("example.com", 443)),
        ));
        let cfg = config(Some(("", "pass")));
        let ctx = ctx_to("example.com", 443);
        let stream = connect(&ctx, Box::new(client), &cfg)
            .await
            .expect("handshake");
        drop(stream);
        server.await.expect("server task").expect("server wire");
    }

    #[tokio::test]
    async fn bad_password_is_rejected() {
        let (client, server_half) = duplex(1024);
        let server = tokio::spawn(far_side_run(
            server_half,
            ServerScript {
                greeting: vec![0x05, 0x02, 0x02, 0x00],
                select: 0x02,
                auth_frame: Some(vec![
                    0x01, 4, b'u', b's', b'e', b'r', 5, b'w', b'r', b'o', b'n', b'g',
                ]),
                auth_status: 0x01,
                request: Vec::new(),
                reply_rep: 0x00,
            },
        ));
        let cfg = config(Some(("user", "wrong")));
        let ctx = ctx_to("example.com", 443);
        let Err(err) = connect(&ctx, Box::new(client), &cfg).await else {
            panic!("expected bad password to fail the handshake");
        };
        let detail = protocol_detail(&err);
        assert!(
            detail.contains("authentication failed"),
            "error names the auth step: {detail}"
        );
        server.await.expect("server task").expect("server wire");
    }

    #[tokio::test]
    async fn non_zero_reply_is_an_error_naming_the_code() {
        let (client, server_half) = duplex(1024);
        let server = tokio::spawn(far_side_run(
            server_half,
            ServerScript {
                reply_rep: 0x05,
                ..ServerScript::no_auth(domain_request("example.com", 443))
            },
        ));
        let cfg = config(None);
        let ctx = ctx_to("example.com", 443);
        let Err(err) = connect(&ctx, Box::new(client), &cfg).await else {
            panic!("expected a non-zero reply to fail the handshake");
        };
        let detail = protocol_detail(&err);
        assert!(detail.contains("0x05"), "detail names the code: {detail}");
        assert!(
            detail.contains("connection refused"),
            "detail names the RFC meaning: {detail}"
        );
        server.await.expect("server task").expect("server wire");
    }

    #[tokio::test]
    async fn no_acceptable_method_is_refused() {
        let (client, server_half) = duplex(1024);
        let server = tokio::spawn(far_side_run(
            server_half,
            ServerScript {
                select: 0xFF,
                ..ServerScript::no_auth(Vec::new())
            },
        ));
        let cfg = config(None);
        let ctx = ctx_to("example.com", 443);
        let Err(err) = connect(&ctx, Box::new(client), &cfg).await else {
            panic!("expected 0xFF to fail the handshake");
        };
        let detail = protocol_detail(&err);
        assert!(
            detail.contains("no acceptable authentication method"),
            "{detail}"
        );
        server.await.expect("server task").expect("server wire");
    }

    /// A GSSAPI selection (0x01) is a METHOD problem — it must not be
    /// reported as an invalid command.
    #[tokio::test]
    async fn unexpected_method_is_a_method_error() {
        let (client, server_half) = duplex(1024);
        let server = tokio::spawn(far_side_run(
            server_half,
            ServerScript {
                select: 0x01,
                ..ServerScript::no_auth(Vec::new())
            },
        ));
        let cfg = config(None);
        let ctx = ctx_to("example.com", 443);
        let Err(err) = connect(&ctx, Box::new(client), &cfg).await else {
            panic!("expected an unsupported method to fail the handshake");
        };
        let detail = protocol_detail(&err);
        assert!(
            detail.contains("unsupported authentication method"),
            "method error, not a command error: {detail}"
        );
        server.await.expect("server task").expect("server wire");
    }

    /// Credentials come from an unvalidated share URL: an over-long one is an
    /// error, never a panic.
    #[tokio::test]
    async fn over_long_credentials_error_instead_of_panicking() {
        let (client, server_half) = duplex(1024);
        let long = "u".repeat(256);
        let server = tokio::spawn(far_side_run(
            server_half,
            ServerScript {
                greeting: vec![0x05, 0x02, 0x02, 0x00],
                select: 0x02,
                // The client must fail before writing any RFC 1929 frame.
                auth_frame: None,
                auth_status: 0,
                request: Vec::new(),
                reply_rep: 0x00,
            },
        ));
        let cfg = config(Some((&long, "pass")));
        let ctx = ctx_to("example.com", 443);
        let Err(err) = connect(&ctx, Box::new(client), &cfg).await else {
            panic!("expected an over-long credential to fail the handshake");
        };
        let detail = protocol_detail(&err);
        assert!(detail.contains("longer than 255 bytes"), "{detail}");
        server.abort();
    }
}
