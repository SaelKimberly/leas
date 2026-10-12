use leas_db::models::{DnsSetting, Endpoint, Protocol, RoutingRule};
use leas_proto::proto_spec::{CoreType, InjectOptions, InjectToCoreConf};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{BuildError, BuildParams, build_hosts_map, endpoint_essentials, protocol_config};

// ── Xray JSON config structs ────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XrayConfig {
    pub log: LogConfig,
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub routing: RoutingConfig,
    pub dns: DnsConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<StatsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<ApiConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyConfig>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogConfig {
    pub loglevel: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inbound {
    pub listen: String,
    pub port: u16,
    pub protocol: &'static str,
    pub settings: Value,
    pub sniffing: Value,
    pub tag: String,
}

/// A proxy outbound. The protocol-specific block (settings + streamSettings)
/// is produced by `protocol.config.inject_to(...)` (Tasks 14/15) and
/// deserialized here; `settings`/`stream_settings` tolerate absence so
/// injectors may omit stream settings for plain-TCP outbounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Outbound {
    pub tag: String,
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub settings: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_settings: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingConfig {
    pub domain_strategy: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub balancers: Vec<Value>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsConfig {
    pub servers: Vec<Value>,
    pub hosts: Value,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct StatsConfig {}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiConfig {
    pub tag: &'static str,
    pub services: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConfig {
    pub levels: Value,
    pub system: Value,
}

// ── Builder ──────────────────────────────────────────────────────────

pub struct XrayConfigBuilder;

impl XrayConfigBuilder {
    /// Build an xray-core config. `core_type` (Xray, already resolved from the
    /// per-pair link) is handed to `inject_to` for the proxy outbound.
    pub fn build(
        endpoint: &Endpoint,
        addresses: &[std::net::IpAddr],
        protocol: &Protocol,
        core_type: CoreType,
        params: &BuildParams,
        routing: &[RoutingRule],
        dns: &DnsSetting,
    ) -> Result<XrayConfig, BuildError> {
        let mut config = skeleton(params, routing, dns);
        config.outbounds = vec![
            build_proxy_outbound(
                endpoint,
                addresses,
                protocol,
                core_type,
                params.skip_cert_verify,
            )?,
            build_dns_outbound(),
            build_direct_outbound(),
            build_block_outbound(),
        ];
        Ok(config)
    }
}

/// Assemble the outbound-free skeleton: log, inbounds, routing, DNS, and the
/// stats/api/policy block. `build` fills in the outbounds afterwards.
fn skeleton(params: &BuildParams, routing: &[RoutingRule], dns: &DnsSetting) -> XrayConfig {
    let (stats, api, policy) = if params.v2ray_api_enabled {
        (
            Some(StatsConfig {}),
            Some(ApiConfig {
                tag: "api",
                services: vec!["HandlerService", "LoggerService", "StatsService"],
            }),
            Some(PolicyConfig {
                levels: json!({
                    "0": {
                        "statsUserUplink": true,
                        "statsUserDownlink": true
                    }
                }),
                system: json!({
                    "statsInboundUplink": true,
                    "statsOutboundUplink": true
                }),
            }),
        )
    } else {
        (None, None, None)
    };

    XrayConfig {
        log: LogConfig {
            loglevel: params.log_level.clone(),
        },
        inbounds: build_inbounds(params),
        outbounds: vec![],
        routing: build_routing(routing, params.v2ray_api_enabled),
        dns: build_dns(dns),
        stats,
        api,
        policy,
    }
}

// ── Inbound construction ─────────────────────────────────────────────

fn build_inbounds(params: &BuildParams) -> Vec<Inbound> {
    let mut inbounds = vec![Inbound {
        listen: params.listen.clone(),
        port: params.socks_port,
        protocol: "socks",
        settings: json!({
            "auth": "noauth",
            "udp": true,
            "ip": "127.0.0.1"
        }),
        sniffing: json!({
            "enabled": params.sniffing,
            "destOverride": ["http", "tls", "quic"]
        }),
        tag: "socks-in".to_string(),
    }];

    if let Some(http_port) = params.http_port {
        inbounds.push(Inbound {
            listen: params.listen.clone(),
            port: http_port,
            protocol: "http",
            settings: json!({}),
            sniffing: json!({}),
            tag: "http-in".to_string(),
        });
    }

    // API inbound for gRPC Commander — only when stats/api enabled
    if params.v2ray_api_enabled {
        inbounds.push(Inbound {
            listen: "127.0.0.1".into(),
            port: super::API_PORT,
            protocol: "dokodemo-door",
            settings: json!({ "address": "127.0.0.1" }),
            sniffing: json!({ "enabled": false, "destOverride": [] }),
            tag: "api".into(),
        });
    }
    inbounds
}

// ── Outbound construction ────────────────────────────────────────────

/// The proxy outbound: `protocol.config.inject_to(...)` writes the
/// protocol-specific block (settings + streamSettings) into `conf`, which is
/// then deserialized into [`Outbound`]. The tag is owned by the builder
/// ("proxy" single / "proxy-{i}" multi). `skip_cert_verify` is forwarded as a
/// build-time override so TLS `insecure` reflects the user setting.
fn build_proxy_outbound(
    endpoint: &Endpoint,
    addresses: &[std::net::IpAddr],
    protocol: &Protocol,
    core_type: CoreType,
    skip_cert_verify: bool,
) -> Result<Outbound, BuildError> {
    let mut conf = json!({});
    protocol_config(protocol)?.inject_to(
        &mut conf,
        core_type,
        Some(&endpoint_essentials(endpoint, addresses)),
        InjectOptions { skip_cert_verify },
    )?;
    let mut outbound: Outbound = serde_json::from_value(conf)?;
    outbound.tag = "proxy".to_string();
    Ok(outbound)
}

fn build_dns_outbound() -> Outbound {
    Outbound {
        tag: "dns-out".to_string(),
        protocol: "dns".to_string(),
        settings: json!({}),
        stream_settings: None,
    }
}

fn build_direct_outbound() -> Outbound {
    Outbound {
        tag: "direct".to_string(),
        protocol: "freedom".to_string(),
        settings: json!({ "domainStrategy": "UseIP" }),
        stream_settings: None,
    }
}

fn build_block_outbound() -> Outbound {
    Outbound {
        tag: "block".to_string(),
        protocol: "blackhole".to_string(),
        settings: json!({ "response": { "type": "http" } }),
        stream_settings: None,
    }
}

// ── Routing ──────────────────────────────────────────────────────────

fn build_routing(rules: &[RoutingRule], v2ray_api_enabled: bool) -> RoutingConfig {
    let mut json_rules: Vec<Value> = Vec::new();
    // Only add API routing rule when v2ray_api is enabled.
    // When disabled (e.g. real ping temp core), no "api" inbound/outbound exist.
    if v2ray_api_enabled {
        json_rules.push(json!({
            "type": "field",
            "inboundTag": ["api"],
            "outboundTag": "api"
        }));
    }
    json_rules.extend(rules.iter().filter_map(|r| {
        // xray-core 26+ rejects routing rules with no match condition
        // (domain/ip/inboundTag/port/sourcePort/network/protocol). Skip them.
        let has_matcher = !r.domains.is_empty()
            || !r.ips.is_empty()
            || !r.inbound_tags.is_empty()
            || !r.ports.is_empty()
            || !r.source_ports.is_empty()
            || r.network.is_some()
            || !r.protocols.is_empty();
        if !has_matcher {
            return None;
        }
        let mut rule = json!({ "type": "field" });
        if !r.domains.is_empty() {
            rule["domain"] = json!(r.domains);
        }
        if !r.ips.is_empty() {
            rule["ip"] = json!(r.ips);
        }
        if !r.inbound_tags.is_empty() {
            rule["inboundTag"] = json!(r.inbound_tags);
        }
        if !r.ports.is_empty() {
            rule["port"] = json!(r.ports);
        }
        if !r.source_ports.is_empty() {
            rule["sourcePort"] = json!(r.source_ports);
        }
        if let Some(network) = &r.network {
            rule["network"] = json!(network);
        }
        if !r.protocols.is_empty() {
            rule["protocol"] = json!(r.protocols);
        }
        if let Some(matcher) = &r.domain_matcher {
            rule["domainMatcher"] = json!(matcher);
        }
        // outboundTag or balancerTag
        if let Some(tag) = &r.outbound_tag {
            rule["outboundTag"] = json!(tag);
        } else if let Some(tag) = &r.balancer_tag {
            rule["balancerTag"] = json!(tag);
        } else {
            // Skip rules without a target outbound
            return None;
        }
        Some(rule)
    }));
    RoutingConfig {
        domain_strategy: "AsIs".to_string(),
        rules: json_rules,
        balancers: vec![],
    }
}

// ── DNS ──────────────────────────────────────────────────────────────

fn build_dns(dns: &DnsSetting) -> DnsConfig {
    let servers: Vec<Value> = dns.servers.iter().map(|s| json!(s)).collect();
    DnsConfig {
        servers,
        hosts: build_hosts_map(&dns.hosts),
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use leas_db::models::RoutingRule;
    use leas_proto::proto_spec::ProtocolKind;

    fn assert_xray_top_level(json: &Value) {
        assert!(json.get("log").is_some(), "missing log");
        assert!(json.get("inbounds").is_some(), "missing inbounds");
        assert!(json.get("outbounds").is_some(), "missing outbounds");
        assert!(json.get("routing").is_some(), "missing routing");
        assert!(json.get("dns").is_some(), "missing dns");
        assert!(json.get("stats").is_some(), "missing stats");
        assert!(json.get("api").is_some(), "missing api");
        assert!(json.get("policy").is_some(), "missing policy");
    }

    fn test_endpoint_protocol_link() -> (Endpoint, Protocol, leas_db::models::ProfileStats) {
        let endpoint = super::super::tests::endpoint("example.com", 443);
        let protocol =
            super::super::tests::protocol(ProtocolKind::Vless, super::super::tests::vless_config());
        (endpoint, protocol, super::super::tests::link())
    }

    fn domain_rule() -> RoutingRule {
        RoutingRule {
            id: "r1".to_string(),
            group_id: None,
            r#type: 0,
            domain_matcher: None,
            domains: vec!["example.com".to_string(), "test.org".to_string()],
            ips: Vec::new(),
            inbound_tags: Vec::new(),
            ports: Vec::new(),
            source_ports: Vec::new(),
            network: Some("tcp".to_string()),
            protocols: Vec::new(),
            domain_strategy: None,
            outbound_tag: Some("direct".to_string()),
            balancer_tag: None,
            rule_set_file: None,
            rule_set_url: None,
            sort_order: Some(0),
        }
    }

    #[test]
    fn xray_build_vless_full_config() {
        // Real inject_to (T14) now builds the full vless outbound; assert the
        // complete config, not an error.
        let (endpoint, protocol, _link) = test_endpoint_protocol_link();
        let (params, rules, dns) = super::super::tests::default_params();
        let config = XrayConfigBuilder::build(
            &endpoint,
            &[],
            &protocol,
            CoreType::Xray,
            &params,
            &rules,
            &dns,
        )
        .expect("vless xray build must succeed");
        let json = serde_json::to_value(&config).unwrap();
        assert_xray_top_level(&json);
        let outbounds = json["outbounds"].as_array().unwrap();
        let proxy = outbounds
            .iter()
            .find(|o| o["tag"] == "proxy")
            .expect("proxy outbound");
        assert_eq!(proxy["protocol"], "vless");
        assert_eq!(proxy["settings"]["vnext"][0]["address"], "example.com");
        assert_eq!(proxy["settings"]["vnext"][0]["port"], 443);
        assert_eq!(
            proxy["settings"]["vnext"][0]["users"][0]["id"],
            "00000000-0000-0000-0000-000000000000"
        );
        let tags: Vec<&str> = outbounds.iter().filter_map(|o| o["tag"].as_str()).collect();
        for required in ["dns-out", "direct", "block"] {
            assert!(tags.contains(&required), "missing {required} outbound");
        }
    }

    #[test]
    fn xray_build_unloaded_config_returns_error() {
        use toasty::Deferred;
        let (endpoint, mut protocol, _link) = test_endpoint_protocol_link();
        protocol.config = Deferred::default();
        let (params, rules, dns) = super::super::tests::default_params();
        let err = XrayConfigBuilder::build(
            &endpoint,
            &[],
            &protocol,
            CoreType::Xray,
            &params,
            &rules,
            &dns,
        )
        .expect_err("unloaded config must be rejected");
        assert!(
            err.to_string().contains("not loaded"),
            "error must mention the unloaded config: {err}"
        );
    }

    #[test]
    fn xray_rejects_reality_without_public_key() {
        // Restores the T13-removed old-builder test: a vless reality profile
        // without publicKey/SNI kills xray-core at startup (empty
        // "realitySettings"/"password"), so the builder refuses it as a
        // SupportError::Config — real validation, not a stub error.
        let endpoint = super::super::tests::endpoint("example.com", 443);
        let protocol = super::super::tests::protocol(
            ProtocolKind::Vless,
            super::super::tests::vless_reality_without_key_config(),
        );
        let (params, rules, dns) = super::super::tests::default_params();
        let err = XrayConfigBuilder::build(
            &endpoint,
            &[],
            &protocol,
            CoreType::Xray,
            &params,
            &rules,
            &dns,
        )
        .expect_err("reality without publicKey must be rejected");
        assert!(
            err.to_string().contains("reality"),
            "error must mention reality: {err}"
        );
        assert!(matches!(
            err,
            BuildError::Support(leas_proto::proto_spec::SupportError::Config(_))
        ));
    }

    #[test]
    fn xray_shadowsocks_rejects_unsupported_cipher() {
        // aes-256-cfb is not in xray-core's CipherType enum — build-time
        // refusal (old builder behavior: the core would die on startup).
        let endpoint = super::super::tests::endpoint("example.com", 443);
        let protocol = super::super::tests::protocol(
            ProtocolKind::Shadowsocks,
            super::super::tests::ss_config("aes-256-cfb"),
        );
        let (params, rules, dns) = super::super::tests::default_params();
        let err = XrayConfigBuilder::build(
            &endpoint,
            &[],
            &protocol,
            CoreType::Xray,
            &params,
            &rules,
            &dns,
        )
        .expect_err("xray-core cannot build aes-256-cfb");
        assert!(
            err.to_string().contains("aes-256-cfb"),
            "error must name the cipher: {err}"
        );
    }

    #[test]
    fn xray_shadowsocks2022_builds() {
        // xray-core builds 2022-blake3 ciphers under protocol "shadowsocks".
        let endpoint = super::super::tests::endpoint("example.com", 443);
        let protocol = super::super::tests::protocol(
            ProtocolKind::Shadowsocks2022,
            super::super::tests::ss_config("2022-blake3-aes-128-gcm"),
        );
        let (params, rules, dns) = super::super::tests::default_params();
        let config = XrayConfigBuilder::build(
            &endpoint,
            &[],
            &protocol,
            CoreType::Xray,
            &params,
            &rules,
            &dns,
        )
        .expect("ss-2022 xray build must succeed");
        let json = serde_json::to_value(&config).unwrap();
        let proxy = json["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "proxy")
            .unwrap();
        assert_eq!(proxy["protocol"], "shadowsocks");
        assert_eq!(
            proxy["settings"]["servers"][0]["method"],
            "2022-blake3-aes-128-gcm"
        );
    }

    #[test]
    fn xray_hysteria2_full_config() {
        // Restores the old xray_hysteria2_config test on the typed config,
        // pinned to the vendored xray-core shape: protocol "hysteria"
        // (unified outbound, version 2 = hysteria2), auth in
        // streamSettings.hysteriaSettings, TLS in security/tlsSettings.
        let endpoint = super::super::tests::endpoint("example.com", 443);
        let protocol = super::super::tests::protocol(
            ProtocolKind::Hysteria2,
            super::super::tests::hy2_config(),
        );
        let (params, rules, dns) = super::super::tests::default_params();
        let config = XrayConfigBuilder::build(
            &endpoint,
            &[],
            &protocol,
            CoreType::Xray,
            &params,
            &rules,
            &dns,
        )
        .expect("hy2 xray build must succeed");
        let json = serde_json::to_value(&config).unwrap();
        assert_xray_top_level(&json);
        let proxy = json["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "proxy")
            .expect("proxy outbound");
        assert_eq!(proxy["protocol"], "hysteria");
        assert_eq!(proxy["settings"]["version"], 2);
        assert_eq!(proxy["settings"]["address"], "example.com");
        assert!(
            proxy["settings"].get("auth").is_none(),
            "no auth in settings"
        );
        // auth lives in the hysteria transport settings.
        assert_eq!(proxy["streamSettings"]["network"], "hysteria");
        assert_eq!(
            proxy["streamSettings"]["hysteriaSettings"]["auth"],
            "hy2-secret"
        );
        // TLS placement (Task 16): xray-core hysteria settings carry no TLS
        // (HysteriaClientConfig = {version, address, port}); TLS belongs in
        // streamSettings only — absent here because the typed security is
        // empty.
        assert!(proxy["settings"].get("tls").is_none(), "no TLS in settings");
        assert!(
            proxy["streamSettings"].get("security").is_none(),
            "no TLS security without typed security"
        );
    }

    #[test]
    fn xray_top_level_skeleton() {
        let (params, rules, dns) = super::super::tests::default_params();
        let config = skeleton(&params, &rules, &dns);
        let json = serde_json::to_value(&config).unwrap();
        assert_xray_top_level(&json);
        // Skeleton carries the API inbound + API routing rule
        let inbounds = json["inbounds"].as_array().unwrap();
        assert!(inbounds.iter().any(|i| i["tag"] == "api"));
        let routing_rules = json["routing"]["rules"].as_array().unwrap();
        assert_eq!(routing_rules[0]["inboundTag"][0], "api");
    }

    #[test]
    fn xray_inbounds_default() {
        let (params, _, _) = super::super::tests::default_params();
        let json = serde_json::to_value(build_inbounds(&params)).unwrap();
        let inbounds = json.as_array().unwrap();
        assert_eq!(inbounds.len(), 2, "should have 2 inbounds (SOCKS + API)");
        assert_eq!(inbounds[0]["protocol"], "socks");
        assert_eq!(inbounds[0]["port"], 10808);
        assert_eq!(inbounds[1]["protocol"], "dokodemo-door");
        assert_eq!(inbounds[1]["tag"], "api");
    }

    #[test]
    fn xray_inbounds_with_http() {
        let (mut params, _, _) = super::super::tests::default_params();
        params.http_port = Some(10809);
        let json = serde_json::to_value(build_inbounds(&params)).unwrap();
        let inbounds = json.as_array().unwrap();
        assert_eq!(
            inbounds.len(),
            3,
            "should have 3 inbounds (SOCKS + HTTP + API)"
        );
        assert_eq!(inbounds[0]["protocol"], "socks");
        assert_eq!(inbounds[0]["port"], 10808);
        assert_eq!(inbounds[1]["protocol"], "http");
        assert_eq!(inbounds[1]["port"], 10809);
        assert_eq!(inbounds[2]["protocol"], "dokodemo-door");
        assert_eq!(inbounds[2]["tag"], "api");
    }

    #[test]
    fn xray_routing_with_domain_rule() {
        let rules = vec![domain_rule()];
        let routing = build_routing(&rules, true);
        let json_rules = &routing.rules;
        // First rule is the mandatory API routing rule
        assert_eq!(json_rules.len(), 2);
        assert_eq!(json_rules[0]["inboundTag"][0], "api");
        assert_eq!(json_rules[0]["outboundTag"], "api");
        // Second rule is the user-defined domain rule
        assert_eq!(json_rules[1]["domain"][0], "example.com");
        assert_eq!(json_rules[1]["domain"][1], "test.org");
        assert_eq!(json_rules[1]["network"], "tcp");
        assert_eq!(json_rules[1]["outboundTag"], "direct");
    }

    #[test]
    fn routing_skips_matcher_less_rules() {
        let rule = RoutingRule {
            id: "r1".to_string(),
            group_id: None,
            r#type: 0,
            domain_matcher: None,
            domains: Vec::new(),
            ips: Vec::new(),
            inbound_tags: Vec::new(),
            ports: Vec::new(),
            source_ports: Vec::new(),
            network: None,
            protocols: Vec::new(),
            domain_strategy: None,
            outbound_tag: Some("direct".to_string()),
            balancer_tag: None,
            rule_set_file: None,
            rule_set_url: None,
            sort_order: None,
        };
        let routing = build_routing(&[rule], false);
        assert!(routing.rules.is_empty());
    }

    #[test]
    fn routing_emits_protocols_and_domain_matcher() {
        let rule = RoutingRule {
            id: "r2".to_string(),
            group_id: None,
            r#type: 0,
            domain_matcher: Some("linear".to_string()),
            domains: vec!["example.com".to_string()],
            ips: Vec::new(),
            inbound_tags: Vec::new(),
            ports: Vec::new(),
            source_ports: Vec::new(),
            network: Some("tcp".to_string()),
            protocols: vec!["http".to_string(), "tls".to_string()],
            domain_strategy: None,
            outbound_tag: Some("proxy".to_string()),
            balancer_tag: None,
            rule_set_file: None,
            rule_set_url: None,
            sort_order: None,
        };
        let routing = build_routing(&[rule], false);
        let rule_json = &routing.rules[0];
        assert_eq!(rule_json["domainMatcher"], "linear");
        assert_eq!(rule_json["protocol"], json!(["http", "tls"]));
    }

    #[test]
    fn routing_emits_source_ports_only_rule() {
        // xray DOES emit sourcePort, so a source_ports-only rule is a valid
        // matcher and must not be skipped.
        let rule = RoutingRule {
            id: "r3".to_string(),
            group_id: None,
            r#type: 0,
            domain_matcher: None,
            domains: Vec::new(),
            ips: Vec::new(),
            inbound_tags: Vec::new(),
            ports: Vec::new(),
            source_ports: vec![8080],
            network: None,
            protocols: Vec::new(),
            domain_strategy: None,
            outbound_tag: Some("direct".to_string()),
            balancer_tag: None,
            rule_set_file: None,
            rule_set_url: None,
            sort_order: None,
        };
        let routing = build_routing(&[rule], false);
        assert_eq!(routing.rules.len(), 1);
        assert_eq!(routing.rules[0]["sourcePort"], json!([8080]));
        assert_eq!(routing.rules[0]["outboundTag"], "direct");
    }

    #[test]
    fn xray_dns_skeleton_from_typed_settings() {
        let dns = DnsSetting {
            id: "default".to_string(),
            name: None,
            servers: vec!["1.1.1.1".to_string(), "tls://8.8.8.8".to_string()],
            hosts: vec!["example.com:1.2.3.4".to_string()],
            query_strategy: None,
            disable_cache: false,
            disable_fallback: false,
            client_ip: None,
            cache_ttl_secs: None,
        };
        let config = build_dns(&dns);
        assert_eq!(json!(config.servers), json!(["1.1.1.1", "tls://8.8.8.8"]));
        assert_eq!(config.hosts["example.com"], "1.2.3.4");
    }
}
