//! SSH configuration (JSON config only — no standard share URL format).
//!
//! # Format
//! SSH does not have a standard share URL format. Configuration is only
//! available via JSON config file or UI form.
//!
//! # Fields (sing-box `SSHOutboundOptions`)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `user` | `Option<String>` | SSH username |
//! | `password` | `Option<String>` | SSH password |
//! | `private_key` | `Option<String>` | SSH private key |
//! | `private_key_path` | `Option<String>` | SSH private key path |
//! | `private_key_passphrase` | `Option<String>` | SSH private key passphrase |
//! | `host_key` | `Option<Vec<String>>` | Accepted host keys |
//! | `host_key_algorithms` | `Option<Vec<String>>` | Host key algorithms |
//! | `client_version` | `Option<String>` | SSH client version string |
//!
//! # References
//! - sing-box: `option/ssh.go` — `SSHOutboundOptions`

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::identity::IdentityWriter;
use crate::clash::{ClashProxy, ClashSsh};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::SecurityConfig;
use crate::proto_spec::common::clash_to_endpoint;
use crate::proto_spec::core_mapping;
use crate::proto_spec::{
    CoreType, EndpointEssentials, InjectOptions, InjectToCoreConf, ParseError, ParsedProto,
    ProtoIdentity, ProtoSpec, ProtocolConfig, ProtocolEssentials, ProtocolKind, SupportError,
};
use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText};

/// SSH protocol configuration — the identity payload (sans host/port).
///
/// SSH has no share URL format, so parsing only ever arrives through the Clash
/// path: `server`/`port` become the [`EndpointEssentials`] and this struct
/// carries only endpoint-free protocol parameters.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct SshConfig {
    pub user: Option<String>,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub private_key_path: Option<String>,
    pub private_key_passphrase: Option<String>,
    pub host_key: Option<Vec<String>>,
    pub host_key_algorithms: Option<Vec<String>>,
    pub client_version: Option<String>,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub remarks: Option<TinyText>,
}

impl SshConfig {
    /// SSH does not support URL format — always returns an error.
    pub fn try_parse_proto(_raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        Err(ParseError::Unknown(
            "SSH does not support URL format".into(),
        ))
    }

    /// SSH does not support URL format — always returns an error.
    pub fn reconstruct_proto(&self, _endpoint: &EndpointEssentials) -> Result<String, ParseError> {
        Err(ParseError::Unknown(
            "SSH does not support URL format".into(),
        ))
    }

    /// Serialize this endpoint-free config plus the endpoint to a Clash proxy
    /// entry. Endpoint host/port are taken from `endpoint`.
    pub fn to_clash_proto(
        &self,
        endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        let name = self.remarks.as_deref().unwrap_or("").to_string();
        Ok(ClashProxy::Ssh(ClashSsh {
            name,
            server: endpoint.host.clone(),
            port: endpoint.port,
            user: self.user.clone().unwrap_or_default(),
            password: self.password.clone(),
            private_key: self.private_key.clone(),
            private_key_path: self.private_key_path.clone(),
            host_key: self.host_key.clone(),
            host_key_algorithms: self.host_key_algorithms.clone(),
            client_version: self.client_version.clone(),
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials (the only parse source for SSH); the
    /// config payload is endpoint-free.
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Ssh(c) => {
                let config = Self {
                    user: Some(c.user.clone()),
                    password: c.password.clone(),
                    private_key: c.private_key.clone(),
                    private_key_path: c.private_key_path.clone(),
                    private_key_passphrase: None,
                    host_key: c.host_key.clone(),
                    host_key_algorithms: c.host_key_algorithms.clone(),
                    client_version: c.client_version.clone(),
                    security: SecurityConfig::default(),
                    remarks: match c.name.as_str() {
                        "" => None,
                        s => Some(TinyText::from(s)),
                    },
                };
                Ok(ParsedProto {
                    endpoints: vec![clash_to_endpoint(&c.server, c.port)],
                    protocol: ProtocolEssentials {
                        proto_kind: ProtocolKind::Ssh,
                        core_type: core_mapping::resolve_core(ProtocolKind::Ssh, None, None),
                        config: ProtocolConfig::Ssh(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown("expected ssh clash proxy".into())),
        }
    }
}

/// Legacy [`ProtoSpec`] bridge — kept so `ProtocolConfig` dispatch (and the
/// `Proto` consumer in leas-core) compile unchanged.
///
/// DEGRADED PATH (documented): `try_from_clash` still works by delegating to
/// the `*_proto` variant and discarding the parsed endpoints; `to_clash`/
/// `reconstruct` return errors because the config no longer stores host/port.
/// Import/export rewires to the `*_proto` variants in T11 (phase D builders
/// take the endpoint separately).
impl ProtoSpec for SshConfig {
    /// SSH does not support URL format — always returns an error.
    fn try_parse(_raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        Err(ParseError::Unknown(
            "SSH does not support URL format".into(),
        ))
    }

    /// SSH does not support URL format — always returns an error.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::Unknown(
            "SSH does not support URL format".into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Ssh
    }

    /// `None` — the endpoint host moved to [`EndpointEssentials`] (T5).
    fn host(&self) -> Option<&HostSpec> {
        None
    }

    /// `None` — the endpoint port moved to [`EndpointEssentials`] (T5).
    fn port(&self) -> Option<u16> {
        None
    }

    fn remarks(&self) -> Option<&str> {
        self.remarks.as_deref()
    }

    fn transport_type(&self) -> Option<&str> {
        None
    }

    /// # Errors
    ///
    /// If the Clash proxy doesn't match this protocol type.
    fn try_from_clash(proxy: &ClashProxy) -> Result<Self, ParseError> {
        let parsed = Self::try_from_clash_proto(proxy)?;
        match parsed.protocol.config {
            ProtocolConfig::Ssh(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "ssh clash proxy parsed to a non-ssh config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "ssh config no longer stores host/port; use SshConfig::to_clash_proto(endpoint)".into(),
        ))
    }
}

/// Per-kind identity tags (see [`super::identity`] for the reserved ranges).
const ID_USER: u8 = 0x50;
const ID_PRIVATE_KEY_PATH: u8 = 0x51;
const ID_HOST_KEY: u8 = 0x52;
const ID_HOST_KEY_ALGORITHMS: u8 = 0x53;
const ID_CLIENT_VERSION: u8 = 0x54;

impl ProtoIdentity for SshConfig {
    /// Identity fields: everything that reaches the sing-box builder.
    ///
    /// `user` is written through [`IdentityWriter::opt_str`]: the builder
    /// materializes the `"root"` default, so `None` and `Some("root")` build
    /// identically and MUST hash identically. Excluded on purpose: `remarks`
    /// (display). Credentials: `password`, `private_key`,
    /// `private_key_passphrase`.
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("ssh");
        super::common::write_security(w, &self.security);
        w.opt_str(ID_USER, self.user.as_deref(), "root");
        w.present_str(ID_PRIVATE_KEY_PATH, self.private_key_path.as_deref());
        if let Some(keys) = &self.host_key {
            w.list_str(ID_HOST_KEY, keys);
        }
        if let Some(algos) = &self.host_key_algorithms {
            w.list_str(ID_HOST_KEY_ALGORITHMS, algos);
        }
        w.present_str(ID_CLIENT_VERSION, self.client_version.as_deref());
        w.cred("password", self.password.as_deref().unwrap_or(""));
        w.cred("private_key", self.private_key.as_deref().unwrap_or(""));
        w.cred(
            "private_key_passphrase",
            self.private_key_passphrase.as_deref().unwrap_or(""),
        );
    }
}

impl InjectToCoreConf for SshConfig {
    fn inject_to(
        &self,
        core_conf: &mut Value,
        core_type: CoreType,
        endpoint: Option<&EndpointEssentials>,
        _opts: InjectOptions,
    ) -> Result<(), SupportError> {
        match core_type {
            CoreType::SingBox => self.inject_singbox(core_conf, endpoint),
            other @ CoreType::Xray => Err(SupportError::UnsupportedProtocol("ssh".into(), other)),
        }
    }
}

impl SshConfig {
    /// sing-box outbound for this config, ported field-by-field from the old
    /// builder's `Protocol::Ssh` arm (`server`/`server_port` from the
    /// endpoint — the typed config has no `host/ssh_port` fields — `user`
    /// defaulting to "root", `password`/`private_key` when non-empty, the
    /// private key as an array), plus the typed `private_key_path`/
    /// `private_key_passphrase`/`host_key`/`host_key_algorithms`/
    /// `client_version` fields (sing-box `SSHOutboundOptions` keys the old
    /// builder dropped).
    fn inject_singbox(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "ssh"));
        };
        let mut out = json!({
            "tag": "proxy",
            "type": "ssh",
            "server": ep.host,
            "server_port": ep.port,
            "user": self.user.as_deref().unwrap_or("root"),
        });
        if let Some(password) = self.password.as_deref().filter(|s| !s.is_empty()) {
            out["password"] = json!(password);
        }
        if let Some(key) = self.private_key.as_deref().filter(|s| !s.is_empty()) {
            out["private_key"] = json!([key]);
        }
        if let Some(path) = &self.private_key_path {
            out["private_key_path"] = json!(path);
        }
        if let Some(passphrase) = &self.private_key_passphrase {
            out["private_key_passphrase"] = json!(passphrase);
        }
        if let Some(keys) = &self.host_key {
            out["host_key"] = json!(keys);
        }
        if let Some(algos) = &self.host_key_algorithms {
            out["host_key_algorithms"] = json!(algos);
        }
        if let Some(version) = &self.client_version {
            out["client_version"] = json!(version);
        }
        *core_conf = out;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CoreType, HostKind, ProtoSpec, ProtocolConfig, ProtocolKind};
    use super::SshConfig;
    use crate::proto_spec::common::SecurityConfig;
    use crate::urlx::{RawUrlX, SchemeX};

    #[test]
    fn test_ssh_no_url() {
        let url = "ssh://user@host:22";
        let raw = RawUrlX::from(url);
        assert!(SshConfig::try_parse(&raw).is_err());
        assert!(SshConfig::try_parse_proto(&raw).is_err());
    }

    #[test]
    fn clash_import_builds_endpoint_and_config() {
        use crate::clash::{ClashProxy, ClashSsh};

        let proxy = ClashProxy::Ssh(ClashSsh {
            name: "ssh-box".into(),
            server: "example.com".into(),
            port: 22,
            user: "root".into(),
            password: Some("sekrit".into()),
            private_key: None,
            private_key_path: Some("/home/user/.ssh/id_ed25519".into()),
            host_key: Some(vec!["ssh-ed25519 AAA".into()]),
            host_key_algorithms: Some(vec!["ssh-ed25519".into()]),
            client_version: Some("SSH-2.0-myclient".into()),
        });
        let parsed = SshConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints.len(), 1);
        assert_eq!(parsed.endpoints[0].host, "example.com");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        assert_eq!(parsed.endpoints[0].port, 22);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Ssh);
        assert_eq!(parsed.protocol.core_type, CoreType::SingBox);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::Ssh(c) => c,
            other => panic!("expected SshConfig, got {other:?}"),
        };
        assert_eq!(cfg.user.as_deref(), Some("root"));
        assert_eq!(cfg.password.as_deref(), Some("sekrit"));
        assert_eq!(
            cfg.private_key_path.as_deref(),
            Some("/home/user/.ssh/id_ed25519")
        );
        // The identity payload must be endpoint-free: no top-level host/port keys.
        let json = serde_json::to_value(cfg).expect("serialize");
        let obj = json.as_object().expect("config is an object");
        assert!(!obj.contains_key("host"), "{json}");
        assert!(!obj.contains_key("port"), "{json}");

        // to_clash_proto round-trips the clash entry unchanged.
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        match (out, proxy) {
            (ClashProxy::Ssh(out), ClashProxy::Ssh(orig)) => assert_eq!(out, orig),
            _ => panic!("expected ssh clash proxy"),
        }
    }

    #[test]
    fn legacy_bridge_clash_extracts_config_but_reconstruct_errors() {
        use crate::clash::{ClashProxy, ClashSsh};

        let proxy = ClashProxy::Ssh(ClashSsh {
            name: "ssh-box".into(),
            server: "example.com".into(),
            port: 22,
            user: "root".into(),
            password: None,
            private_key: None,
            private_key_path: None,
            host_key: None,
            host_key_algorithms: None,
            client_version: None,
        });
        let bridged = SshConfig::try_from_clash(&proxy).expect("bridged clash parse");
        assert_eq!(bridged.schema(), SchemeX::Ssh);
        assert_eq!(bridged.user.as_deref(), Some("root"));
        assert_eq!(bridged.host(), None);
        assert_eq!(bridged.port(), None);
        assert!(bridged.reconstruct().is_err());
        assert!(bridged.to_clash().is_err());
    }

    // ── Sing-box inject_to (Task 15) ──────────────────────────────────────

    use super::super::{EndpointEssentials, InjectOptions, InjectToCoreConf, SupportError};

    #[test]
    fn singbox_inject_writes_proxy_outbound() {
        let cfg = SshConfig {
            user: Some("root".into()),
            password: Some("sekrit".into()),
            private_key: Some("PRIVATE-KEY".into()),
            private_key_path: Some("/home/user/.ssh/id_ed25519".into()),
            private_key_passphrase: Some("passphrase".into()),
            host_key: Some(vec!["ssh-ed25519 AAA".into()]),
            host_key_algorithms: Some(vec!["ssh-ed25519".into()]),
            client_version: Some("SSH-2.0-myclient".into()),
            security: SecurityConfig::default(),
            remarks: None,
        };
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("example.com", 22)),
            InjectOptions::default(),
        )
        .expect("ssh sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "ssh");
        assert_eq!(conf["server"], "example.com");
        assert_eq!(conf["server_port"], 22);
        assert_eq!(conf["user"], "root");
        assert_eq!(conf["password"], "sekrit");
        assert_eq!(conf["private_key"], serde_json::json!(["PRIVATE-KEY"]));
        assert_eq!(conf["private_key_path"], "/home/user/.ssh/id_ed25519");
        assert_eq!(conf["private_key_passphrase"], "passphrase");
        assert_eq!(conf["host_key"], serde_json::json!(["ssh-ed25519 AAA"]));
        assert_eq!(
            conf["host_key_algorithms"],
            serde_json::json!(["ssh-ed25519"])
        );
        assert_eq!(conf["client_version"], "SSH-2.0-myclient");
    }

    #[test]
    fn singbox_inject_defaults_and_endpoint_requirement() {
        let cfg = SshConfig {
            user: None,
            password: None,
            private_key: None,
            private_key_path: None,
            private_key_passphrase: None,
            host_key: None,
            host_key_algorithms: None,
            client_version: None,
            security: SecurityConfig::default(),
            remarks: None,
        };
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("example.com", 22)),
            InjectOptions::default(),
        )
        .expect("ssh sing-box inject");
        assert_eq!(conf["user"], "root");
        assert!(conf.get("password").is_none());
        assert!(conf.get("private_key").is_none());

        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::SingBox, None, InjectOptions::default())
            .expect_err("orphan ssh must be rejected");
        assert!(matches!(err, SupportError::MissingField("server", "ssh")));
    }
}
