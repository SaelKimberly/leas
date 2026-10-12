//! **3b oracle rows: a real SIP003 plugin on BOTH ends.** Rows 1–2 (`obfs=http`,
//! `obfs=tls`), rows 3–4 (`mode=websocket`, mux off and on), and rows 5/15 (`wss`).
//!
//! The two cores cannot host a plugin — xray-core has no SIP003 support at all and
//! sing-box's SS *inbound* has no plugin field — so the server side is a plugin-capable SS
//! server: a vendored `ssserver` driving `obfs-server` / `v2ray-plugin` as real child
//! processes. That makes this a **different shape of test** from `tests/shadowsocks.rs`,
//! which spawns a core from a JSON config; teaching that machinery a flag-based server would
//! make every case carry a half-fit branch, so these rows stand alone.
//!
//! Opt-in, like the core binaries: `#[ignore]`d, and run with
//! ```text
//! just plugin-bins                                  # installs the pinned binaries
//! cargo test -p leas-native --features native-e2e --test plugin_sip003 -- --ignored
//! ```
//!
//! Two environment inputs, both printed by `just plugin-bins`:
//!
//! - `LEAS_PLUGIN_BIN_DIR` — where the pinned plugin binaries live (the recipe also
//!   writes `plugin-env.sh` there, which supplies `PATH` and the libev loader path);
//! - `LEAS_SSSERVER_BIN` — the `ssserver` binary (it lives under the gitignored
//!   `thirdparty/` tree, so a test cannot assume it exists).
//!
//! `clippy::future_not_send` is allowed file-wide (rstest, see `shadowsocks.rs`).
#![allow(clippy::future_not_send)]
#![cfg(feature = "native-e2e")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use leas_native::BoxStream;
use leas_native::NativeConnectParams;
use leas_native::addr::{Host, TargetAddr};
use leas_native::connect;
use leas_native::e2e::config::BODY;
use leas_native::e2e::harness::spawn_echo;
use leas_proto::proto_spec::PluginSpec;
use leas_proto::proto_spec::TlsConfig;
use leas_proto::proto_spec::TlsOpts;
use leas_proto::proto_spec::common::SecurityConfig;
use leas_proto::proto_spec::endpoint::EndpointEssentials;
use leas_proto::proto_spec::{ProtocolConfig, SsConfig};

/// The cipher the row speaks; anything AEAD the plugin server accepts is fine — this is a
/// plugin-row proof, not a cipher matrix.
const METHOD: &str = "aes-256-gcm";
const PASSWORD: &str = "hunter2";

/// A free TCP port: bind to :0, read the assignment, drop the listener.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// The pinned plugin directory, or a loud failure — an `#[ignore]`d row that skips
/// silently would be a vacuous pass.
fn plugin_dir() -> PathBuf {
    let dir = std::env::var("LEAS_PLUGIN_BIN_DIR").unwrap_or_else(|_| {
        panic!(
            "LEAS_PLUGIN_BIN_DIR is not set — run `just plugin-bins` first, then \
             re-run with --ignored"
        )
    });
    let dir = PathBuf::from(dir);
    for binary in ["obfs-server", "v2ray-plugin"] {
        assert!(
            dir.join(binary).exists(),
            "{} is missing from {} — re-run `just plugin-bins`",
            binary,
            dir.display()
        );
    }
    dir
}

fn ssserver_bin() -> PathBuf {
    if let Ok(bin) = std::env::var("LEAS_SSSERVER_BIN") {
        return PathBuf::from(bin);
    }
    // The vendored build, which is where the plan's oracle lives. Gitignored, so this is
    // a fallback rather than a promise.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../thirdparty/shadowsocks-rust/target/release/ssserver")
}

/// The child environment the plugin needs.
///
/// `ssserver` spawns the plugin itself, so the plugin's own environment is what matters:
/// its directory must be on `PATH`, and libev must be loadable (the recipe builds a **shared**
/// libev, and `$ORIGIN` does not survive shell → make → ld, so the loader path is the
/// recipe's to report). `plugin-env.sh`, written by `just plugin-bins`, carries both.
fn child_env(plugin_dir: &Path) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();
    let path = std::env::var("PATH").map_or_else(
        |_| plugin_dir.display().to_string(),
        |existing| format!("{}:{existing}", plugin_dir.display()),
    );
    env.push(("PATH".to_string(), path));
    if let Ok(dir) = std::env::var("LEAS_PLUGIN_LIB_DIR") {
        let existing = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
        env.push((
            "LD_LIBRARY_PATH".to_string(),
            if existing.is_empty() {
                dir
            } else {
                format!("{dir}:{existing}")
            },
        ));
    } else {
        let script = plugin_dir.join("plugin-env.sh");
        if let Ok(text) = std::fs::read_to_string(&script) {
            for line in text.lines() {
                if let Some(rest) = line.trim().strip_prefix("export LD_LIBRARY_PATH=") {
                    env.push((
                        "LD_LIBRARY_PATH".to_string(),
                        rest.trim_matches('"').to_string(),
                    ));
                }
            }
        }
    }
    env
}

/// A running `ssserver` with a plugin, killed on drop.
struct PluginServer {
    child: Child,
    /// The child's stderr, accumulated as it arrives.
    ///
    /// Accumulated rather than read to EOF: the plugin is a **grandchild** that
    /// inherits the pipe and outlives `ssserver`, so waiting for EOF would block
    /// forever and every failure message would read empty.
    stderr: std::sync::Arc<std::sync::Mutex<String>>,
}

impl PluginServer {
    /// `plugin` is the binary name (the server half, e.g. `obfs-server`); `opts` goes
    /// through `SS_PLUGIN_OPTIONS`, which is the only channel a SIP003 plugin has.
    fn start(plugin: &str, opts: &str, port: u16, plugin_dir: &Path) -> Self {
        let bin = ssserver_bin();
        assert!(
            bin.exists(),
            "{} does not exist — build it (`cargo build --release --features server --bin \
             ssserver` in thirdparty/shadowsocks-rust) or set LEAS_SSSERVER_BIN",
            bin.display()
        );
        let mut cmd = Command::new(&bin);
        cmd.arg("-s")
            .arg(format!("127.0.0.1:{port}"))
            .arg("-m")
            .arg(METHOD)
            .arg("-k")
            .arg(PASSWORD)
            .arg("--plugin")
            .arg(plugin)
            .arg("--plugin-opts")
            .arg(opts)
            // BOTH streams are piped, not nulled: the plugin's and the
            // server's own lines are the fastest diagnosis when a row fails, and
            // a silent server is exactly the failure mode this row catches.
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in child_env(plugin_dir) {
            cmd.env(key, value);
        }
        let mut child = cmd.spawn().expect("spawn ssserver");
        let stderr = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        // Both streams feed one sink: interleaved, which is how the server
        // prints them.
        let stdout = child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>);
        let stderr_pipe = child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>);
        for source in [stdout, stderr_pipe].into_iter().flatten() {
            let mut pipe = source;
            let sink = std::sync::Arc::clone(&stderr);
            // Drain on a thread: a full pipe would block the server mid-row.
            std::thread::spawn(move || {
                use std::io::Read as _;
                let mut chunk = [0u8; 1024];
                while let Ok(n) = pipe.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    if let Ok(mut slot) = sink.lock() {
                        slot.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    }
                }
            });
        }
        Self { child, stderr }
    }

    /// Stop the server and wait for it, so its stderr is fully drained.
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// The server's own log, for a failure message.
    ///
    /// Called after [`Self::stop`]: the reader thread only sees EOF once the
    /// child has exited, so a short wait avoids reading an empty slot.
    fn log(&self) -> String {
        self.stderr.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

impl Drop for PluginServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Wait for the plugin server's public port to answer (it binds after spawning the plugin).
async fn wait_for(port: u16) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("ssserver never listened on 127.0.0.1:{port}");
}

/// The client's row: the same plugin, the other side of the pipe.
fn client_params(
    port: u16,
    target: &TargetAddr,
    plugin_opts: &str,
    security: SecurityConfig,
) -> NativeConnectParams {
    NativeConnectParams::new(
        ProtocolConfig::Ss(SsConfig {
            method: METHOD.into(),
            password: PASSWORD.to_string(),
            security,
            remarks: None,
            plugin: Some(PluginSpec::from_parts(Some("obfs-local"), plugin_opts)),
        }),
        EndpointEssentials::new("127.0.0.1", port),
        target.clone(),
    )
}

/// Dial and fetch, following the SAME dispatch the inbound uses
/// (`inbound/outbound.rs::dial`): a mux-resolved link goes through the mux protocol phase and
/// opens one session, everything else takes the plain chain.
///
/// Going straight to `connect()` bypasses that predicate, and row 4 then fails in a way that
/// reads like a framing bug: the server mandates mux, receives a raw SS stream, and reports
/// `common/mux: invalid metalen <n>` from bytes that were never frames.
async fn dial_and_fetch(
    params: NativeConnectParams,
    target: &TargetAddr,
) -> Result<String, String> {
    let tunnel = if params.mux {
        let mux = leas_native::connect_mux(&params)
            .await
            .map_err(|e| format!("connect_mux: {e:?}"))?;
        leas_native::mux_session::open_session(mux, &params.target)
            .await
            .map_err(|e| format!("mux session: {e:?}"))?
    } else {
        Box::new(
            connect(params)
                .await
                .map_err(|e| format!("connect: {e:?}"))?,
        )
    };
    fetch_over(tunnel, target).await
}

/// Fetch the echo target over an already-open session.
///
/// Split out so a row can supply its own session — row 4b opens one through
/// `SsMux::open_session_with_frame`, which the default dispatch cannot do.
async fn fetch_over(mut tunnel: BoxStream, target: &TargetAddr) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        target.host.as_str(),
        target.port
    );
    tunnel
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    tunnel.flush().await.map_err(|e| format!("flush: {e}"))?;
    let mut response = String::new();
    // The echo answers a fixed body then closes; a short bound keeps a broken row from
    // hanging the suite.
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tunnel.read_to_string(&mut response),
    )
    .await
    .map_err(|_| "read timed out".to_string())?;
    read.map_err(|e| format!("read: {e}"))?;
    Ok(response)
}

/// Rows 1 and 2: `obfs=http` and `obfs=tls` against the real `obfs-server`.
#[tokio::test]
#[ignore = "needs the pinned plugin binaries and a plugin-capable ssserver (just plugin-bins)"]
async fn obfs_rows_dial_the_real_plugin_server() {
    let dir = plugin_dir();
    let echo = spawn_echo();
    let target = TargetAddr::new(Host::Ip(echo.addr.ip()), echo.addr.port());

    for (row, mode) in [("1", "http"), ("2", "tls")] {
        let port = free_port();
        let opts = format!("obfs={mode};obfs-host=cdn.example");
        let server = PluginServer::start("obfs-server", &opts, port, &dir);
        wait_for(port).await;

        let params = client_params(port, &target, &opts, SecurityConfig::default());
        // The row is a plugin row, so the SS codec must be gated in only for a plugin spec
        // that survives `capability` — asserted here as part of the row's meaning.
        let ProtocolConfig::Ss(cfg) = &params.protocol else {
            panic!("the row is a Shadowsocks row");
        };
        assert!(
            leas_native::capability::supported(
                leas_proto::proto_spec::ProtocolKind::Shadowsocks,
                &params.protocol,
            ),
            "row {row}: a plain obfs row must be servable natively"
        );
        assert!(
            cfg.plugin.is_some(),
            "row {row}: the plugin spec survives the parse"
        );

        let response = dial_and_fetch(params, &target).await;
        // Stop first: the stderr is drained by a reader thread, so the log is
        // only complete once the child has exited.
        let mut server = server;
        server.stop();
        let log = server.log();
        let response = response
            .unwrap_or_else(|e| panic!("row {row} (obfs={mode}) failed: {e}\nserver log:\n{log}"));
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "row {row}: unexpected response: {response}\nserver log:\n{log}"
        );
        assert!(
            response.contains(BODY),
            "row {row}: the echo body is missing from {response}\nserver log:\n{log}"
        );
        drop(server);
    }
}

/// Rows 3 and 4: `mode=websocket`, mux off and mux on, against the real
/// `v2ray-plugin` server.
///
/// Two things about the **server** are not ours to choose, and getting either wrong makes the
/// row fail for the server's reason while the matrix blames the client:
///
/// - the role travels in the **options**, not argv: `ssserver` passes `--plugin-opts` as
///   `SS_PLUGIN_OPTIONS` and v2ray-plugin reads `server` from it, so the server row is
///   `--plugin-opts "server;mode=websocket;…"`;
/// - **`-mux` defaults to 1**, and a server with mux on sets its dokodemo destination to
///   `v1.mux.cool`, which `mux.Server.Dispatch` then parses as frames *unconditionally*. So a
///   client with `mux=0` (row 3) must be paired with a server started `mux=0`, and only row 4
///   uses the default. There is no negotiation: a mismatch is a silent failure.
#[tokio::test]
#[ignore = "needs the pinned plugin binaries and a plugin-capable ssserver (just plugin-bins)"]
async fn ws_rows_dial_the_real_v2ray_plugin() {
    let dir = plugin_dir();
    let echo = spawn_echo();
    let target = TargetAddr::new(Host::Ip(echo.addr.ip()), echo.addr.port());

    // (row, client plugin opts, server plugin opts)
    let cases: &[(&str, &str, &str)] = &[
        (
            "3",
            "mode=websocket;mux=0;host=cdn.example",
            "server;mode=websocket;mux=0",
        ),
        (
            "4",
            "mode=websocket;host=cdn.example",
            "server;mode=websocket",
        ),
    ];
    for (row, client_opts, server_opts) in cases {
        let port = free_port();
        let mut server = PluginServer::start("v2ray-plugin", server_opts, port, &dir);
        wait_for(port).await;

        let params = client_params(port, &target, client_opts, SecurityConfig::default());
        // The dispatch predicate is what decides mux, so assert the row actually
        // exercises the path it claims to: row 3 must NOT be mux-routed, row 4 must.
        let want_mux = *row == "4";
        assert_eq!(
            params.mux, want_mux,
            "row {row}: `mux_active` must decide the path, and the server must agree"
        );

        let response = dial_and_fetch(params, &target).await;
        server.stop();
        let log = server.log();
        let response = response.unwrap_or_else(|e| {
            panic!("row {row} ({client_opts}) failed: {e}\nserver log:\n{log}")
        });
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "row {row}: unexpected response: {response}\nserver log:\n{log}"
        );
        assert!(
            response.contains(BODY),
            "row {row}: the echo body is missing from {response}\nserver log:\n{log}"
        );
        drop(server);
    }
}

/// Rows 5 and 15: `wss` against the real plugin server, and the negative that
/// keeps row 5 honest.
///
/// Both halves run against **one** server on **one** port, so row 5's success
/// is what proves the environment — the plugin came up, TLS ran, the tunnel
/// carried the echo — and row 15's failure can only be the missing `insecure`.
/// Two servers would leave room for row 15 to fail on its own half-started one.
///
/// The negative is asserted **typed**, never by message text (the repo's standing
/// rule): an untrusted chain is `TlsError::Verify` → `NativeError::Tls`, while a
/// *name* mismatch is `TlsError::CertNotValidForName` → its own
/// `NativeError::CertNotValidForName`. Matching the wrong one would leave the
/// row green while proving a name mismatch instead of the untrusted chain, which
/// is the property it exists to pin.
///
/// No test CA is installed. `set_test_ca` is a **thread-local**, so it would
/// apply to both halves: row 15's chain is signed by that very CA and its SAN
/// covers `localhost`, so the negative would *verify* and the row would turn red.
/// Row 5 passes because its row states `insecure = true`, which the
/// `Some(Tls)` arm of `security::wrap` honours.
#[tokio::test]
#[ignore = "needs the pinned plugin binaries and a plugin-capable ssserver (just plugin-bins)"]
async fn wss_row_connects_and_its_negative_fails_verification() {
    use leas_native::NativeError;

    let dir = plugin_dir();
    let echo = spawn_echo();
    let target = TargetAddr::new(Host::Ip(echo.addr.ip()), echo.addr.port());
    let certs = leas_native::e2e::harness::generate_certs();

    // v2ray-plugin in server mode with `tls` needs material: with no `cert`/`key`
    // it looks for `~/.acme.sh/<host>/fullchain.cer` and exits 23.
    let tmp = tempfile::tempdir().expect("tempdir");
    let cert_path = tmp.path().join("server.crt");
    let key_path = tmp.path().join("server.key");
    std::fs::write(&cert_path, &certs.cert_pem).expect("write cert");
    std::fs::write(&key_path, &certs.key_pem).expect("write key");

    let port = free_port();
    let mut server = PluginServer::start(
        "v2ray-plugin",
        &format!(
            "server;mode=websocket;tls;cert={};key={}",
            cert_path.display(),
            key_path.display()
        ),
        port,
        &dir,
    );
    wait_for(port).await;

    // `host=localhost` is in the generated cert's SAN, so the name matches and
    // trust is the only difference between the halves.
    let client_opts = "mode=websocket;tls;host=localhost";
    let security = |insecure: bool| SecurityConfig {
        tls: Some(TlsConfig::Tls(TlsOpts {
            sni: Some("localhost".into()),
            insecure: Some(insecure),
            ..TlsOpts::default()
        })),
        enc: None,
    };

    // Row 5: the row says `insecure`, so the self-signed chain is accepted.
    let response = dial_and_fetch(
        client_params(port, &target, client_opts, security(true)),
        &target,
    )
    .await;
    assert!(
        response.is_ok(),
        "row 5 (wss) must connect: {:?}\nserver log:\n{}",
        response.err(),
        server.log()
    );
    let response = response.expect("row 5 answered");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "row 5: unexpected response: {response}\nserver log:\n{}",
        server.log()
    );
    assert!(
        response.contains(BODY),
        "row 5: the echo body is missing from {response}"
    );

    // Row 15: the same row, same server, without `insecure`. The handshake runs
    // inside the chain, so `connect_mux` itself returns the typed error.
    let params = client_params(port, &target, client_opts, security(false));
    let outcome = leas_native::connect_mux(&params).await;
    match outcome {
        Ok(_) => panic!(
            "row 15 must FAIL on the untrusted chain, but it connected\nserver log:\n{}",
            server.log()
        ),
        Err(NativeError::CertNotValidForName(detail)) => panic!(
            "row 15 failed as a NAME mismatch ({detail}), not as the untrusted chain it \
             exists to prove — the client's SNI and the cert's SAN have drifted apart"
        ),
        Err(NativeError::Tls(detail)) => assert!(
            detail.contains("certificate verification failed"),
            "row 15 must fail on chain verification, not: {detail}"
        ),
        Err(other) => panic!(
            "row 15 must fail as a TLS verification error, got {other:?}\nserver log:\n{}",
            server.log()
        ),
    }

    server.stop();
    drop(server);
}

/// Row 4b: the mux `New`-frame target is **inert**.
///
/// Row 4 proved our value (`v1.mux.cool:9527`) works. This proves the field
/// carries no meaning against a v2ray-plugin server — the server overrides every
/// dispatched destination with its `freedom.DestinationOverride`, so the other
/// value the ecosystem sends must work identically.
///
/// It has to go through `SsMux::open_session_with_frame`, because the default
/// dispatch can only ever emit the pinned value: a "row 4b" on that path would
/// put **the same bytes on the wire as row 4** and pass while proving nothing.
#[tokio::test]
#[ignore = "needs the pinned plugin binaries and a plugin-capable ssserver (just plugin-bins)"]
async fn the_mux_frame_target_is_inert() {
    use leas_native::MuxTunnel;
    use leas_native::transport::mux::MuxTarget;

    let dir = plugin_dir();
    let echo = spawn_echo();
    let target = TargetAddr::new(Host::Ip(echo.addr.ip()), echo.addr.port());

    let port = free_port();
    let mut server = PluginServer::start("v2ray-plugin", "server;mode=websocket", port, &dir);
    wait_for(port).await;

    // mihomo's value, not ours — that is the whole point of the row.
    let params = client_params(
        port,
        &target,
        "mode=websocket;host=cdn.example",
        SecurityConfig::default(),
    );
    assert!(
        params.mux,
        "this row is only meaningful for a mux-routed link"
    );

    let outcome = async {
        let mux = leas_native::connect_mux(&params)
            .await
            .map_err(|e| format!("connect_mux: {e:?}"))?;
        let MuxTunnel::Ss(ss) = &mux else {
            return Err("expected a Shadowsocks mux tunnel".to_string());
        };
        let session = ss
            // mihomo's form, byte for byte: `NewMux` runs
            // `net.ParseIP(option.Host)` and, for an IPv4 literal, writes
            // `atyp 0x01` + the four octets (`mihomo/transport/v2ray-plugin/mux.go:158-164`).
            // A `TcpDomain("127.0.0.1", 0)` would encode `atyp 0x02` + a
            // length-prefixed name — a third form neither reference writes.
            .open_session_with_frame(
                MuxTarget::Tcp(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
                &params.target,
            )
            .await
            .map_err(|e| format!("session: {e:?}"))?;
        fetch_over(session, &target).await
    }
    .await;

    server.stop();
    let log = server.log();
    let response = outcome.unwrap_or_else(|e| {
        panic!("row 4b: mihomo's frame target must work too: {e}\nserver log:\n{log}")
    });
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "row 4b: unexpected response: {response}\nserver log:\n{log}"
    );
    assert!(
        response.contains(BODY),
        "row 4b: the echo body is missing from {response}"
    );
    drop(server);
}
