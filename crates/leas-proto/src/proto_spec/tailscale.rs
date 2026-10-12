//! Tailscale configuration (JSON config only — no standard share URL format).
//!
//! # Format
//! Tailscale does not have a standard share URL format. Configuration is only
//! available via JSON config file or UI form.
//!
//! # Fields (sing-box `TailscaleEndpointOptions`)
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `hostname` | `Option<String>` | Node hostname |
//! | `auth_key` | `Option<String>` | Auth key for node registration |
//! | `control_url` | `Option<String>` | Control server URL |
//! | `state_directory` | `Option<String>` | Tailscale state directory |
//! | `ephemeral` | `Option<bool>` | Ephemeral node |
//! | `accept_routes` | `Option<bool>` | Accept advertised routes |
//! | `exit_node` | `Option<String>` | Exit node |
//! | `exit_node_allow_lan_access` | `Option<bool>` | Allow LAN while using exit node |
//! | `advertise_routes` | `Option<Vec<String>>` | Routes to advertise |
//!
//! # References
//! - sing-box: `option/tailscale.go` — `TailscaleEndpointOptions`

use serde::{Deserialize, Serialize};

use super::identity::IdentityWriter;
use crate::clash::{ClashProxy, ClashTailscale};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::SecurityConfig;
use crate::proto_spec::common::clash_to_endpoint;
use crate::proto_spec::core_mapping;
use crate::proto_spec::{
    CoreType, EndpointEssentials, InjectOptions, InjectToCoreConf, ParseError, ParsedProto,
    ProtoIdentity, ProtoSpec, ProtocolConfig, ProtocolEssentials, ProtocolKind, SupportError,
};
use serde_json::{Value, json};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText};

/// Tailscale protocol configuration — the identity payload (sans host/port).
///
/// Tailscale has no share URL format, so parsing only ever arrives through the
/// Clash path: `server`/`port` become the [`EndpointEssentials`] and this
/// struct carries only endpoint-free protocol parameters.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct TailscaleConfig {
    pub hostname: Option<String>,
    pub auth_key: Option<String>,
    pub control_url: Option<String>,
    pub state_directory: Option<String>,
    pub ephemeral: Option<bool>,
    pub accept_routes: Option<bool>,
    pub exit_node: Option<String>,
    pub exit_node_allow_lan_access: Option<bool>,
    pub advertise_routes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub remarks: Option<TinyText>,
}

impl TailscaleConfig {
    /// Tailscale does not support URL format — always returns an error.
    pub fn try_parse_proto(_raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        Err(ParseError::Unknown(
            "Tailscale does not support URL format".into(),
        ))
    }

    /// Tailscale does not support URL format — always returns an error.
    pub fn reconstruct_proto(&self, _endpoint: &EndpointEssentials) -> Result<String, ParseError> {
        Err(ParseError::Unknown(
            "Tailscale does not support URL format".into(),
        ))
    }

    /// Serialize this endpoint-free config plus the endpoint to a Clash proxy
    /// entry. Endpoint host/port are taken from `endpoint`.
    pub fn to_clash_proto(
        &self,
        endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        let name = self.remarks.as_deref().unwrap_or("").to_string();
        Ok(ClashProxy::Tailscale(ClashTailscale {
            name,
            server: endpoint.host.clone(),
            port: endpoint.port,
            hostname: self.hostname.clone().unwrap_or_default(),
            auth_key: self.auth_key.clone(),
            control_url: self.control_url.clone(),
            state_dir: self.state_directory.clone(),
            ephemeral: self.ephemeral.unwrap_or(false),
            accept_routes: self.accept_routes.unwrap_or(false),
            exit_node: self.exit_node.clone(),
            exit_node_allow_lan_access: self.exit_node_allow_lan_access,
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials (the only parse source for Tailscale);
    /// the config payload is endpoint-free.
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Tailscale(c) => {
                let config = Self {
                    hostname: match c.hostname.as_str() {
                        "" => None,
                        s => Some(s.to_string()),
                    },
                    auth_key: c.auth_key.clone(),
                    control_url: c.control_url.clone(),
                    state_directory: c.state_dir.clone(),
                    ephemeral: Some(c.ephemeral),
                    accept_routes: Some(c.accept_routes),
                    exit_node: c.exit_node.clone(),
                    exit_node_allow_lan_access: c.exit_node_allow_lan_access,
                    advertise_routes: None,
                    security: SecurityConfig::default(),
                    remarks: match c.name.as_str() {
                        "" => None,
                        s => Some(TinyText::from(s)),
                    },
                };
                Ok(ParsedProto {
                    endpoints: vec![clash_to_endpoint(&c.server, c.port)],
                    protocol: ProtocolEssentials {
                        proto_kind: ProtocolKind::Tailscale,
                        core_type: core_mapping::resolve_core(ProtocolKind::Tailscale, None, None),
                        config: ProtocolConfig::Tailscale(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown("expected tailscale clash proxy".into())),
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
impl ProtoSpec for TailscaleConfig {
    /// Tailscale does not support URL format — always returns an error.
    fn try_parse(_raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        Err(ParseError::Unknown(
            "Tailscale does not support URL format".into(),
        ))
    }

    /// Tailscale does not support URL format — always returns an error.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::Unknown(
            "Tailscale does not support URL format".into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Tailscale
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
            ProtocolConfig::Tailscale(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "tailscale clash proxy parsed to a non-tailscale config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "tailscale config no longer stores host/port; use TailscaleConfig::to_clash_proto(endpoint)"
                .into(),
        ))
    }
}

/// Per-kind identity tags (see [`super::identity`] for the reserved ranges).
const ID_HOSTNAME: u8 = 0x50;
const ID_CONTROL_URL: u8 = 0x51;
const ID_STATE_DIRECTORY: u8 = 0x52;
const ID_EPHEMERAL: u8 = 0x53;
const ID_ACCEPT_ROUTES: u8 = 0x54;
const ID_EXIT_NODE: u8 = 0x55;
const ID_EXIT_NODE_ALLOW_LAN_ACCESS: u8 = 0x56;
const ID_ADVERTISE_ROUTES: u8 = 0x57;

impl ProtoIdentity for TailscaleConfig {
    /// Identity fields: everything that reaches the sing-box builder.
    ///
    /// The three flags default to `false` in the builder (only `Some(true)` is
    /// emitted), so `None` and `Some(false)` are the same identity. Excluded on
    /// purpose: `remarks` (display). Credential: `auth_key`.
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("tailscale");
        super::common::write_security(w, &self.security);
        w.present_str(ID_HOSTNAME, self.hostname.as_deref());
        w.present_str(ID_CONTROL_URL, self.control_url.as_deref());
        w.present_str(ID_STATE_DIRECTORY, self.state_directory.as_deref());
        w.opt_flag(ID_EPHEMERAL, self.ephemeral);
        w.opt_flag(ID_ACCEPT_ROUTES, self.accept_routes);
        w.present_str(ID_EXIT_NODE, self.exit_node.as_deref());
        w.opt_flag(
            ID_EXIT_NODE_ALLOW_LAN_ACCESS,
            self.exit_node_allow_lan_access,
        );
        if let Some(routes) = &self.advertise_routes {
            w.list_str(ID_ADVERTISE_ROUTES, routes);
        }
        w.cred("auth_key", self.auth_key.as_deref().unwrap_or(""));
    }
}

impl InjectToCoreConf for TailscaleConfig {
    fn inject_to(
        &self,
        core_conf: &mut Value,
        core_type: CoreType,
        _endpoint: Option<&EndpointEssentials>,
        _opts: InjectOptions,
    ) -> Result<(), SupportError> {
        match core_type {
            // Tailscale is a self-contained endpoint outbound (no server
            // field) — the old builder emitted `{ "type": "tailscale" }`
            // endpoint-less.
            CoreType::SingBox => {
                let mut out = json!({ "tag": "proxy", "type": "tailscale" });
                if let Some(v) = &self.hostname {
                    out["hostname"] = json!(v);
                }
                if let Some(v) = &self.auth_key {
                    out["auth_key"] = json!(v);
                }
                if let Some(v) = &self.control_url {
                    out["control_url"] = json!(v);
                }
                if let Some(v) = &self.state_directory {
                    out["state_directory"] = json!(v);
                }
                if self.ephemeral == Some(true) {
                    out["ephemeral"] = json!(true);
                }
                if self.accept_routes == Some(true) {
                    out["accept_routes"] = json!(true);
                }
                if let Some(v) = &self.exit_node {
                    out["exit_node"] = json!(v);
                }
                if self.exit_node_allow_lan_access == Some(true) {
                    out["exit_node_allow_lan_access"] = json!(true);
                }
                if let Some(v) = &self.advertise_routes {
                    out["advertise_routes"] = json!(v);
                }
                *core_conf = out;
                Ok(())
            }
            other @ CoreType::Xray => {
                Err(SupportError::UnsupportedProtocol("tailscale".into(), other))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CoreType, HostKind, ProtoSpec, ProtocolConfig, ProtocolKind};
    use super::TailscaleConfig;
    use crate::proto_spec::common::SecurityConfig;
    use crate::urlx::{RawUrlX, SchemeX};

    #[test]
    fn test_tailscale_no_url() {
        let url = "tailscale://host:100";
        let raw = RawUrlX::from(url);
        assert!(TailscaleConfig::try_parse(&raw).is_err());
        assert!(TailscaleConfig::try_parse_proto(&raw).is_err());
    }

    #[test]
    fn clash_import_builds_endpoint_and_config() {
        use crate::clash::{ClashProxy, ClashTailscale};

        let proxy = ClashProxy::Tailscale(ClashTailscale {
            name: "ts-node".into(),
            server: "100.64.0.1".into(),
            port: 100,
            hostname: "node1".into(),
            auth_key: Some("tskey-auth-abc".into()),
            control_url: Some("https://control.example.com".into()),
            state_dir: Some("/var/lib/tailscale".into()),
            ephemeral: true,
            accept_routes: true,
            exit_node: Some("100.64.0.2".into()),
            exit_node_allow_lan_access: Some(true),
        });
        let parsed = TailscaleConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints.len(), 1);
        assert_eq!(parsed.endpoints[0].host, "100.64.0.1");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Ipv4);
        assert_eq!(parsed.endpoints[0].port, 100);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Tailscale);
        assert_eq!(parsed.protocol.core_type, CoreType::SingBox);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::Tailscale(c) => c,
            other => panic!("expected TailscaleConfig, got {other:?}"),
        };
        assert_eq!(cfg.hostname.as_deref(), Some("node1"));
        assert_eq!(cfg.auth_key.as_deref(), Some("tskey-auth-abc"));
        assert_eq!(cfg.ephemeral, Some(true));
        // The identity payload must be endpoint-free: no top-level host/port keys.
        let json = serde_json::to_value(cfg).expect("serialize");
        let obj = json.as_object().expect("config is an object");
        assert!(!obj.contains_key("host"), "{json}");
        assert!(!obj.contains_key("port"), "{json}");

        // to_clash_proto round-trips the clash entry unchanged.
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        match (out, proxy) {
            (ClashProxy::Tailscale(out), ClashProxy::Tailscale(orig)) => assert_eq!(out, orig),
            _ => panic!("expected tailscale clash proxy"),
        }
    }

    #[test]
    fn legacy_bridge_clash_extracts_config_but_reconstruct_errors() {
        use crate::clash::{ClashProxy, ClashTailscale};

        let proxy = ClashProxy::Tailscale(ClashTailscale {
            name: "ts-node".into(),
            server: "100.64.0.1".into(),
            port: 100,
            hostname: "node1".into(),
            auth_key: None,
            control_url: None,
            state_dir: None,
            ephemeral: false,
            accept_routes: false,
            exit_node: None,
            exit_node_allow_lan_access: None,
        });
        let bridged = TailscaleConfig::try_from_clash(&proxy).expect("bridged clash parse");
        assert_eq!(bridged.schema(), SchemeX::Tailscale);
        assert_eq!(bridged.hostname.as_deref(), Some("node1"));
        assert_eq!(bridged.host(), None);
        assert_eq!(bridged.port(), None);
        assert!(bridged.reconstruct().is_err());
        assert!(bridged.to_clash().is_err());
    }

    // ── Sing-box inject_to (Task 15) ──────────────────────────────────────

    use super::super::{InjectOptions, InjectToCoreConf, SupportError};

    #[test]
    fn singbox_inject_writes_proxy_outbound() {
        let cfg = TailscaleConfig {
            hostname: Some("node1".into()),
            auth_key: Some("tskey-auth-abc".into()),
            control_url: Some("https://control.example.com".into()),
            state_directory: Some("/var/lib/tailscale".into()),
            ephemeral: Some(true),
            accept_routes: Some(true),
            exit_node: Some("100.64.0.2".into()),
            exit_node_allow_lan_access: Some(true),
            advertise_routes: Some(vec!["10.0.0.0/24".into()]),
            security: SecurityConfig::default(),
            remarks: None,
        };
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            None, // tailscale needs no server — endpoint-less is fine
            InjectOptions::default(),
        )
        .expect("tailscale sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "tailscale");
        assert_eq!(conf["hostname"], "node1");
        assert_eq!(conf["auth_key"], "tskey-auth-abc");
        assert_eq!(conf["control_url"], "https://control.example.com");
        assert_eq!(conf["state_directory"], "/var/lib/tailscale");
        assert_eq!(conf["ephemeral"], true);
        assert_eq!(conf["accept_routes"], true);
        assert_eq!(conf["exit_node"], "100.64.0.2");
        assert_eq!(conf["exit_node_allow_lan_access"], true);
        assert_eq!(conf["advertise_routes"], serde_json::json!(["10.0.0.0/24"]));
    }

    #[test]
    fn singbox_inject_false_flags_are_omitted() {
        let cfg = TailscaleConfig {
            hostname: None,
            auth_key: None,
            control_url: None,
            state_directory: None,
            ephemeral: Some(false),
            accept_routes: Some(false),
            exit_node: None,
            exit_node_allow_lan_access: Some(false),
            advertise_routes: None,
            security: SecurityConfig::default(),
            remarks: None,
        };
        let mut conf = serde_json::json!({});
        cfg.inject_to(&mut conf, CoreType::SingBox, None, InjectOptions::default())
            .expect("tailscale sing-box inject");
        assert_eq!(
            conf,
            serde_json::json!({ "tag": "proxy", "type": "tailscale" })
        );
    }

    #[test]
    fn xray_core_is_rejected() {
        let cfg = TailscaleConfig {
            hostname: None,
            auth_key: None,
            control_url: None,
            state_directory: None,
            ephemeral: None,
            accept_routes: None,
            exit_node: None,
            exit_node_allow_lan_access: None,
            advertise_routes: None,
            security: SecurityConfig::default(),
            remarks: None,
        };
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::Xray, None, InjectOptions::default())
            .expect_err("tailscale has no xray shape");
        assert!(matches!(
            &err,
            SupportError::UnsupportedProtocol(kind, CoreType::Xray) if kind == "tailscale"
        ));
    }
}
