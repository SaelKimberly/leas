//! Tor configuration (JSON config only — no share URL format).
//!
//! # Format
//! Tor does not have a standard share URL format. Configuration is only
//! available via JSON config file or UI form.
//!
//! # Fields (sing-box `TorOutboundOptions`)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `executable_path` | `Option<String>` | Tor binary path |
//! | `extra_args` | `Option<Vec<String>>` | Extra CLI arguments |
//! | `data_directory` | `Option<String>` | Tor data directory |
//! | `torrc` | `Option<HashMap<String, String>>` | Additional torrc options |
//!
//! # References
//! - sing-box: `option/tor.go` — `TorOutboundOptions`

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::identity::IdentityWriter;
use crate::clash::{ClashProxy, ClashTor};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::SecurityConfig;
use crate::proto_spec::common::clash_to_endpoint;
use crate::proto_spec::core_mapping;
use crate::proto_spec::{
    CoreType, EndpointEssentials, InjectOptions, InjectToCoreConf, ParseError, ParsedProto,
    ProtoIdentity, ProtoSpec, ProtocolConfig, ProtocolEssentials, ProtocolKind, SupportError,
};
use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText};

/// Tor protocol configuration — the identity payload (sans host/port).
///
/// Tor has no share URL format, so parsing only ever arrives through the Clash
/// path: `server`/`port` become the [`EndpointEssentials`] and this struct
/// carries only endpoint-free protocol parameters.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct TorConfig {
    pub executable_path: Option<String>,
    pub extra_args: Option<Vec<String>>,
    pub data_directory: Option<String>,
    pub torrc: Option<std::collections::HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub remarks: Option<TinyText>,
}

impl TorConfig {
    /// Tor does not support URL format — always returns an error.
    pub fn try_parse_proto(_raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        Err(ParseError::Unknown(
            "Tor does not support URL format".into(),
        ))
    }

    /// Tor does not support URL format — always returns an error.
    pub fn reconstruct_proto(&self, _endpoint: &EndpointEssentials) -> Result<String, ParseError> {
        Err(ParseError::Unknown(
            "Tor does not support URL format".into(),
        ))
    }

    /// Serialize this endpoint-free config plus the endpoint to a Clash proxy
    /// entry. Endpoint host/port are taken from `endpoint`.
    pub fn to_clash_proto(
        &self,
        endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        let name = self.remarks.as_deref().unwrap_or("").to_string();
        Ok(ClashProxy::Tor(ClashTor {
            name,
            server: endpoint.host.clone(),
            port: endpoint.port,
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials (the only parse source for Tor); the
    /// config payload is endpoint-free.
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Tor(c) => {
                let config = Self {
                    executable_path: None,
                    extra_args: None,
                    data_directory: None,
                    torrc: None,
                    security: SecurityConfig::default(),
                    remarks: match c.name.as_str() {
                        "" => None,
                        s => Some(TinyText::from(s)),
                    },
                };
                Ok(ParsedProto {
                    endpoints: vec![clash_to_endpoint(&c.server, c.port)],
                    protocol: ProtocolEssentials {
                        proto_kind: ProtocolKind::Tor,
                        core_type: core_mapping::resolve_core(ProtocolKind::Tor, None, None),
                        config: ProtocolConfig::Tor(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown("expected tor clash proxy".into())),
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
impl ProtoSpec for TorConfig {
    /// Tor does not support URL format — always returns an error.
    fn try_parse(_raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        Err(ParseError::Unknown(
            "Tor does not support URL format".into(),
        ))
    }

    /// Tor does not support URL format — always returns an error.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::Unknown(
            "Tor does not support URL format".into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Tor
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
            ProtocolConfig::Tor(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "tor clash proxy parsed to a non-tor config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "tor config no longer stores host/port; use TorConfig::to_clash_proto(endpoint)".into(),
        ))
    }
}

/// Per-kind identity tags (see [`super::identity`] for the reserved ranges).
const ID_EXECUTABLE_PATH: u8 = 0x50;
const ID_EXTRA_ARGS: u8 = 0x51;
const ID_DATA_DIRECTORY: u8 = 0x52;
const ID_TORRC: u8 = 0x53;

impl ProtoIdentity for TorConfig {
    /// Identity fields: everything that reaches the sing-box builder.
    ///
    /// Excluded on purpose: `remarks` (display only). Tor has no credential
    /// fields, so `cred_hash` stays 0 and `uid == sig`.
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("tor");
        super::common::write_security(w, &self.security);
        w.present_str(ID_EXECUTABLE_PATH, self.executable_path.as_deref());
        if let Some(args) = &self.extra_args {
            w.list_str(ID_EXTRA_ARGS, args);
        }
        w.present_str(ID_DATA_DIRECTORY, self.data_directory.as_deref());
        if let Some(torrc) = &self.torrc {
            w.map_str(ID_TORRC, torrc);
        }
    }
}

impl InjectToCoreConf for TorConfig {
    fn inject_to(
        &self,
        core_conf: &mut Value,
        core_type: CoreType,
        _endpoint: Option<&EndpointEssentials>,
        _opts: InjectOptions,
    ) -> Result<(), SupportError> {
        match core_type {
            // Tor is a self-contained outbound (no server field) — the old
            // builder emitted `{ "type": "tor" }` endpoint-less.
            CoreType::SingBox => {
                let mut out = json!({ "tag": "proxy", "type": "tor" });
                if let Some(path) = &self.executable_path {
                    out["executable_path"] = json!(path);
                }
                if let Some(args) = &self.extra_args {
                    out["extra_args"] = json!(args);
                }
                if let Some(dir) = &self.data_directory {
                    out["data_directory"] = json!(dir);
                }
                if let Some(torrc) = &self.torrc {
                    out["torrc"] = json!(torrc);
                }
                *core_conf = out;
                Ok(())
            }
            other @ CoreType::Xray => Err(SupportError::UnsupportedProtocol("tor".into(), other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CoreType, HostKind, ProtoSpec, ProtocolConfig, ProtocolKind};
    use super::TorConfig;
    use crate::proto_spec::common::SecurityConfig;
    use crate::urlx::{RawUrlX, SchemeX};

    #[test]
    fn test_tor_no_url() {
        let url = "tor://user@host:9050";
        let raw = RawUrlX::from(url);
        assert!(TorConfig::try_parse(&raw).is_err());
        assert!(TorConfig::try_parse_proto(&raw).is_err());
    }

    #[test]
    fn clash_import_builds_endpoint_and_config() {
        use crate::clash::{ClashProxy, ClashTor};

        let proxy = ClashProxy::Tor(ClashTor {
            name: "tor-node".into(),
            server: "127.0.0.1".into(),
            port: 9050,
        });
        let parsed = TorConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints.len(), 1);
        assert_eq!(parsed.endpoints[0].host, "127.0.0.1");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Ipv4);
        assert_eq!(parsed.endpoints[0].port, 9050);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Tor);
        assert_eq!(parsed.protocol.core_type, CoreType::SingBox);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::Tor(c) => c,
            other => panic!("expected TorConfig, got {other:?}"),
        };
        assert_eq!(cfg.remarks.as_deref(), Some("tor-node"));
        // The identity payload must be endpoint-free: no top-level host/port keys.
        let json = serde_json::to_value(cfg).expect("serialize");
        let obj = json.as_object().expect("config is an object");
        assert!(!obj.contains_key("host"), "{json}");
        assert!(!obj.contains_key("port"), "{json}");

        // to_clash_proto round-trips the clash entry unchanged.
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        match (out, proxy) {
            (ClashProxy::Tor(out), ClashProxy::Tor(orig)) => assert_eq!(out, orig),
            _ => panic!("expected tor clash proxy"),
        }
    }

    #[test]
    fn legacy_bridge_clash_extracts_config_but_reconstruct_errors() {
        use crate::clash::{ClashProxy, ClashTor};

        let proxy = ClashProxy::Tor(ClashTor {
            name: "tor-node".into(),
            server: "127.0.0.1".into(),
            port: 9050,
        });
        let bridged = TorConfig::try_from_clash(&proxy).expect("bridged clash parse");
        assert_eq!(bridged.schema(), SchemeX::Tor);
        assert_eq!(bridged.host(), None);
        assert_eq!(bridged.port(), None);
        assert!(bridged.reconstruct().is_err());
        assert!(bridged.to_clash().is_err());
    }

    // ── Sing-box inject_to (Task 15) ──────────────────────────────────────

    use super::super::{InjectOptions, InjectToCoreConf, SupportError};

    #[test]
    fn singbox_inject_writes_proxy_outbound() {
        let mut torrc = std::collections::HashMap::new();
        torrc.insert("SocksPort".to_string(), "0".to_string());
        let cfg = TorConfig {
            executable_path: Some("/usr/bin/tor".into()),
            extra_args: Some(vec!["--quiet".into()]),
            data_directory: Some("/var/lib/tor".into()),
            torrc: Some(torrc),
            security: SecurityConfig::default(),
            remarks: None,
        };
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            None, // tor needs no server — endpoint-less is fine
            InjectOptions::default(),
        )
        .expect("tor sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "tor");
        assert_eq!(conf["executable_path"], "/usr/bin/tor");
        assert_eq!(conf["extra_args"], serde_json::json!(["--quiet"]));
        assert_eq!(conf["data_directory"], "/var/lib/tor");
        assert_eq!(conf["torrc"], serde_json::json!({ "SocksPort": "0" }));
    }

    #[test]
    fn singbox_inject_minimal_is_just_tor_type() {
        let cfg = TorConfig {
            executable_path: None,
            extra_args: None,
            data_directory: None,
            torrc: None,
            security: SecurityConfig::default(),
            remarks: None,
        };
        let mut conf = serde_json::json!({});
        cfg.inject_to(&mut conf, CoreType::SingBox, None, InjectOptions::default())
            .expect("tor sing-box inject");
        assert_eq!(conf, serde_json::json!({ "tag": "proxy", "type": "tor" }));
    }

    #[test]
    fn xray_core_is_rejected() {
        let cfg = TorConfig {
            executable_path: None,
            extra_args: None,
            data_directory: None,
            torrc: None,
            security: SecurityConfig::default(),
            remarks: None,
        };
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::Xray, None, InjectOptions::default())
            .expect_err("tor has no xray shape");
        assert!(matches!(
            &err,
            SupportError::UnsupportedProtocol(kind, CoreType::Xray) if kind == "tor"
        ));
    }
}
