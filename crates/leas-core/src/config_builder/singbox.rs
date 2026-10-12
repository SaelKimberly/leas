use leas_db::models::{DnsSetting, Endpoint, Protocol, RoutingRule};
use leas_proto::proto_spec::{CoreType, InjectOptions, InjectToCoreConf};
use serde::Serialize;
use serde_json::{Value, json};

use super::{BuildError, BuildParams, build_hosts_map, endpoint_essentials, protocol_config};

// ── Sing-box JSON config structs ──────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SingBoxConfig {
    pub log: SingBoxLogConfig,
    pub inbounds: Vec<SingBoxInbound>,
    pub outbounds: Vec<Value>,
    pub route: RouteConfig,
    pub dns: SingBoxDnsConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<ExperimentalConfig>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SingBoxLogConfig {
    pub level: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SingBoxInbound {
    #[serde(rename = "type")]
    pub type_: &'static str,
    pub tag: String,
    pub listen: String,
    pub listen_port: u16,
    pub sniff: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RouteConfig {
    pub rules: Vec<Value>,
    pub rule_set: Vec<Value>,
    #[serde(rename = "final")]
    pub final_outbound: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SingBoxDnsConfig {
    pub servers: Vec<Value>,
    pub hosts: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ExperimentalConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v2ray_api: Option<V2RayApi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clash_api: Option<ClashApiOptions>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct V2RayApi {
    pub listen: String,
    pub stats: StatsConfig,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct StatsConfig {
    pub enabled: bool,
    pub outbounds: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ClashApiOptions {
    pub external_controller: String,
}

// ── Builder ──────────────────────────────────────────────────────────

pub struct SingBoxConfigBuilder;
impl SingBoxConfigBuilder {
    /// Build a sing-box config. `core_type` (`SingBox`, already resolved from
    /// the per-pair link) is handed to `inject_to` for the proxy outbound.
    pub fn build(
        endpoint: &Endpoint,
        addresses: &[std::net::IpAddr],
        protocol: &Protocol,
        core_type: CoreType,
        params: &BuildParams,
        routing: &[RoutingRule],
        dns: &DnsSetting,
    ) -> Result<SingBoxConfig, BuildError> {
        let mut config = skeleton(params, routing, dns);
        config.outbounds = vec![
            build_proxy_outbound(endpoint, addresses, protocol, core_type, params)?,
            build_direct_outbound(),
            build_block_outbound(),
        ];
        Ok(config)
    }
}

/// Assemble the outbound-free skeleton: log, socks inbound, routing, DNS, and
/// the experimental (v2ray/clash API) block. `build` fills in the outbounds
/// afterwards.
fn skeleton(params: &BuildParams, routing: &[RoutingRule], dns: &DnsSetting) -> SingBoxConfig {
    SingBoxConfig {
        log: SingBoxLogConfig {
            level: params.log_level.clone(),
        },
        inbounds: vec![SingBoxInbound {
            type_: "socks",
            tag: "socks-in".to_string(),
            listen: params.listen.clone(),
            listen_port: params.socks_port,
            sniff: params.sniffing,
        }],
        outbounds: vec![],
        route: build_routing(routing),
        dns: build_dns(dns),
        experimental: Some(ExperimentalConfig {
            v2ray_api: params.v2ray_api_enabled.then(|| V2RayApi {
                listen: format!("127.0.0.1:{}", super::API_PORT),
                stats: StatsConfig {
                    enabled: true,
                    outbounds: vec!["proxy", "direct"],
                },
            }),
            clash_api: params.clash_api_enabled.then(|| ClashApiOptions {
                external_controller: format!(
                    "127.0.0.1:{}",
                    params.clash_api_port.unwrap_or(super::CLASH_API_PORT)
                ),
            }),
        }),
    }
}

/// The proxy outbound: `protocol.config.inject_to(...)` writes the
/// protocol-specific block (type/server/... + TLS) into `conf`; the builder
/// owns the tag ("proxy" single / "proxy-{i}" multi) and the multiplex block.
fn build_proxy_outbound(
    endpoint: &Endpoint,
    addresses: &[std::net::IpAddr],
    protocol: &Protocol,
    core_type: CoreType,
    params: &BuildParams,
) -> Result<Value, BuildError> {
    let mut out = json!({});
    protocol_config(protocol)?.inject_to(
        &mut out,
        core_type,
        Some(&endpoint_essentials(endpoint, addresses)),
        InjectOptions {
            skip_cert_verify: params.skip_cert_verify,
        },
    )?;
    out["tag"] = json!("proxy");
    // Inject multiplex block if configured
    if let Some(mux_val) = &params.mux {
        out["multiplex"] = mux_val.clone();
    }
    Ok(out)
}

fn build_direct_outbound() -> Value {
    json!({
        "tag": "direct",
        "type": "direct"
    })
}

fn build_block_outbound() -> Value {
    json!({
        "tag": "block",
        "type": "block"
    })
}

// ── Routing ──────────────────────────────────────────────────────────

fn build_routing(rules: &[RoutingRule]) -> RouteConfig {
    let json_rules: Vec<Value> = rules
        .iter()
        .filter_map(|r| {
            // sing-box rejects rules without any match condition
            // (domain/ip_cidr/inbound/port/network/protocol). Skip them.
            // NOTE: source_ports is NOT a matcher here — the sing-box builder
            // does not emit a source_port field, so a source_ports-only rule
            // would otherwise slip through as a catch-all rule.
            let has_matcher = !r.domains.is_empty()
                || !r.ips.is_empty()
                || !r.inbound_tags.is_empty()
                || !r.ports.is_empty()
                || r.network.is_some()
                || !r.protocols.is_empty();
            if !has_matcher {
                return None;
            }
            let mut rule = json!({});
            if !r.domains.is_empty() {
                rule["domain"] = json!(r.domains);
            }
            if !r.ips.is_empty() {
                rule["ip_cidr"] = json!(r.ips);
            }
            if !r.inbound_tags.is_empty() {
                rule["inbound"] = json!(r.inbound_tags);
            }
            if !r.ports.is_empty() {
                rule["port"] = json!(r.ports);
            }
            if let Some(network) = &r.network {
                rule["network"] = json!([network]);
            }
            if !r.protocols.is_empty() {
                rule["protocol"] = json!(r.protocols);
            }
            if let Some(matcher) = &r.domain_matcher {
                rule["domain_matcher"] = json!(matcher);
            }
            if let Some(tag) = &r.outbound_tag {
                rule["outbound"] = json!(tag);
            } else if let Some(tag) = &r.balancer_tag {
                rule["outbound"] = json!(tag);
            } else {
                return None;
            }
            Some(rule)
        })
        .collect();

    RouteConfig {
        rules: json_rules,
        rule_set: vec![],
        final_outbound: "proxy".to_string(),
    }
}

// ── DNS ──────────────────────────────────────────────────────────────

fn build_dns(dns: &DnsSetting) -> SingBoxDnsConfig {
    let servers: Vec<Value> = dns.servers.iter().map(|s| json!(s)).collect();
    SingBoxDnsConfig {
        servers,
        hosts: build_hosts_map(&dns.hosts),
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use leas_db::models::RoutingRule;
    use leas_proto::proto_spec::ProtocolConfig;
    use leas_proto::proto_spec::ProtocolKind;
    use leas_proto::proto_spec::common::SecurityConfig;

    fn assert_singbox_top_level(json: &Value) {
        assert!(json.get("log").is_some(), "missing log");
        assert!(json.get("inbounds").is_some(), "missing inbounds");
        assert!(json.get("outbounds").is_some(), "missing outbounds");
        assert!(json.get("route").is_some(), "missing route");
        assert!(json.get("dns").is_some(), "missing dns");
        assert!(json.get("experimental").is_some(), "missing experimental");
    }

    fn test_endpoint_protocol_link() -> (Endpoint, Protocol, leas_db::models::ProfileStats) {
        let endpoint = super::super::tests::endpoint("example.com", 443);
        let tuic = ProtocolConfig::Tuic(leas_proto::proto_spec::TuicConfig {
            uuid: "00000000-0000-0000-0000-000000000000".to_string(),
            password: "pw".to_string(),
            congestion_control: None,
            udp_relay_mode: None,
            security: SecurityConfig::default(),
            remarks: None,
        });
        let protocol = super::super::tests::protocol(ProtocolKind::Tuic, tuic);
        (endpoint, protocol, super::super::tests::link())
    }

    fn domain_rule() -> RoutingRule {
        RoutingRule {
            id: "r1".to_string(),
            group_id: None,
            r#type: 0,
            domain_matcher: None,
            domains: vec!["example.com".to_string()],
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
            sort_order: Some(0),
        }
    }

    #[test]
    fn singbox_build_tuic_full_config() {
        // Real inject_to (T15) now builds the full tuic outbound; assert the
        // complete config, not an error.
        let (endpoint, protocol, _link) = test_endpoint_protocol_link();
        let (params, rules, dns) = super::super::tests::default_params();
        let config = SingBoxConfigBuilder::build(
            &endpoint,
            &[],
            &protocol,
            CoreType::SingBox,
            &params,
            &rules,
            &dns,
        )
        .expect("tuic sing-box build must succeed");
        let json = serde_json::to_value(&config).unwrap();
        assert_singbox_top_level(&json);
        let outbounds = json["outbounds"].as_array().unwrap();
        let proxy = outbounds
            .iter()
            .find(|o| o["tag"] == "proxy")
            .expect("proxy outbound");
        assert_eq!(proxy["type"], "tuic");
        assert_eq!(proxy["uuid"], "00000000-0000-0000-0000-000000000000");
        assert_eq!(proxy["server"], "example.com");
        assert_eq!(proxy["server_port"], 443);
        assert_eq!(proxy["tls"]["enabled"], true);
        assert_eq!(proxy["tls"]["server_name"], "example.com");
        let tags: Vec<&str> = outbounds.iter().filter_map(|o| o["tag"].as_str()).collect();
        for required in ["direct", "block"] {
            assert!(tags.contains(&required), "missing {required} outbound");
        }
    }

    #[test]
    fn singbox_build_unloaded_config_returns_error() {
        use toasty::Deferred;
        let (endpoint, mut protocol, _link) = test_endpoint_protocol_link();
        protocol.config = Deferred::default();
        let (params, rules, dns) = super::super::tests::default_params();
        let err = SingBoxConfigBuilder::build(
            &endpoint,
            &[],
            &protocol,
            CoreType::SingBox,
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
    fn singbox_shadowsocks_rejects_unsupported_cipher() {
        // salsa20 is supported by neither core — build-time refusal (old
        // builder behavior).
        let endpoint = super::super::tests::endpoint("example.com", 443);
        let protocol = super::super::tests::protocol(
            ProtocolKind::Shadowsocks,
            super::super::tests::ss_config("salsa20"),
        );
        let (params, rules, dns) = super::super::tests::default_params();
        let err = SingBoxConfigBuilder::build(
            &endpoint,
            &[],
            &protocol,
            CoreType::SingBox,
            &params,
            &rules,
            &dns,
        )
        .expect_err("salsa20 is not a sing-box method");
        assert!(
            err.to_string().contains("salsa20"),
            "error must name the cipher: {err}"
        );
    }

    #[test]
    fn singbox_legacy_cipher_builds() {
        // aes-256-cfb is a legacy cipher xray-core cannot build but sing-box
        // supports — must succeed (old builder behavior).
        let endpoint = super::super::tests::endpoint("example.com", 443);
        let protocol = super::super::tests::protocol(
            ProtocolKind::Shadowsocks,
            super::super::tests::ss_config("aes-256-cfb"),
        );
        let (params, rules, dns) = super::super::tests::default_params();
        let config = SingBoxConfigBuilder::build(
            &endpoint,
            &[],
            &protocol,
            CoreType::SingBox,
            &params,
            &rules,
            &dns,
        )
        .expect("legacy cipher sing-box build must succeed");
        let json = serde_json::to_value(&config).unwrap();
        let proxy = json["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "proxy")
            .unwrap();
        assert_eq!(proxy["type"], "shadowsocks");
        assert_eq!(proxy["method"], "aes-256-cfb");
    }

    #[test]
    fn singbox_shadowsocks2022_builds() {
        let endpoint = super::super::tests::endpoint("example.com", 443);
        let protocol = super::super::tests::protocol(
            ProtocolKind::Shadowsocks2022,
            super::super::tests::ss_config("2022-blake3-aes-128-gcm"),
        );
        let (params, rules, dns) = super::super::tests::default_params();
        let config = SingBoxConfigBuilder::build(
            &endpoint,
            &[],
            &protocol,
            CoreType::SingBox,
            &params,
            &rules,
            &dns,
        )
        .expect("ss-2022 sing-box build must succeed");
        let json = serde_json::to_value(&config).unwrap();
        let proxy = json["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "proxy")
            .unwrap();
        assert_eq!(proxy["type"], "shadowsocks");
        assert_eq!(proxy["method"], "2022-blake3-aes-128-gcm");
    }

    #[test]
    fn singbox_wireguard_full_config() {
        // Restores the old wireguard full-config test on the typed config:
        // endpoint is endpoint-less (wg peers carry the server), reserved/mtu/
        // peers/address fields all present.
        let endpoint = super::super::tests::endpoint("", 0);
        let protocol = super::super::tests::protocol(
            ProtocolKind::WireGuard,
            super::super::tests::wg_config(),
        );
        let (params, rules, dns) = super::super::tests::default_params();
        let config = SingBoxConfigBuilder::build(
            &endpoint,
            &[],
            &protocol,
            CoreType::SingBox,
            &params,
            &rules,
            &dns,
        )
        .expect("wireguard sing-box build must succeed");
        let json = serde_json::to_value(&config).unwrap();
        assert_singbox_top_level(&json);
        let proxy = json["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "proxy")
            .expect("proxy outbound");
        assert_eq!(proxy["type"], "wireguard");
        assert_eq!(proxy["mtu"], 1380);
        assert_eq!(proxy["peers"][0]["public_key"], "pubkey789");
        assert_eq!(proxy["peers"][0]["pre_shared_key"], "psk_value");
        assert_eq!(proxy["peers"][0]["reserved"], json!([1, 2, 3]));
        assert_eq!(proxy["address"], json!(["10.0.0.1/24"]));
    }

    #[test]
    fn singbox_hysteria2_full_config() {
        // Restores the old hy2 full-config test on the typed config.
        let endpoint = super::super::tests::endpoint("example.com", 443);
        let protocol = super::super::tests::protocol(
            ProtocolKind::Hysteria2,
            super::super::tests::hy2_config(),
        );
        let (params, rules, dns) = super::super::tests::default_params();
        let config = SingBoxConfigBuilder::build(
            &endpoint,
            &[],
            &protocol,
            CoreType::SingBox,
            &params,
            &rules,
            &dns,
        )
        .expect("hy2 sing-box build must succeed");
        let json = serde_json::to_value(&config).unwrap();
        assert_singbox_top_level(&json);
        let proxy = json["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "proxy")
            .expect("proxy outbound");
        assert_eq!(proxy["type"], "hysteria2");
        assert_eq!(proxy["password"], "hy2-secret");
        assert_eq!(proxy["up_mbps"], 100);
        assert_eq!(proxy["down_mbps"], 100);
        // mandatory TLS block (empty security -> defaults to endpoint host).
        assert_eq!(proxy["tls"]["enabled"], true);
        assert_eq!(proxy["tls"]["server_name"], "example.com");
    }

    #[test]
    fn singbox_v2ray_api_values() {
        // Restores the T13-removed value-level v2ray_api assertions
        // (listen port + stats.enabled + tracked outbounds).
        let (params, rules, dns) = super::super::tests::default_params();
        let config = skeleton(&params, &rules, &dns);
        let json = serde_json::to_value(&config).unwrap();
        let api = &json["experimental"]["v2ray_api"];
        assert_eq!(
            api["listen"],
            format!("127.0.0.1:{}", crate::config_builder::API_PORT)
        );
        assert_eq!(api["stats"]["enabled"], true);
        assert_eq!(api["stats"]["outbounds"], json!(["proxy", "direct"]));
    }

    #[test]
    fn singbox_top_level_skeleton() {
        let (params, rules, dns) = super::super::tests::default_params();
        let config = skeleton(&params, &rules, &dns);
        let json = serde_json::to_value(&config).unwrap();
        assert_singbox_top_level(&json);
        let exp = &json["experimental"];
        assert!(
            exp["v2ray_api"].is_object(),
            "v2ray_api should be present when enabled"
        );
        assert!(exp["clash_api"].is_null(), "clash_api should be absent");
    }

    #[test]
    fn singbox_default_inbound() {
        let (params, rules, dns) = super::super::tests::default_params();
        let config = skeleton(&params, &rules, &dns);
        let json = serde_json::to_value(&config).unwrap();
        let inbounds = json["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0]["type"], "socks");
        assert_eq!(inbounds[0]["listen_port"], 10808);
    }

    #[test]
    fn singbox_clash_api_config() {
        let (mut params, rules, dns) = super::super::tests::default_params();
        params.clash_api_enabled = true;
        let config = skeleton(&params, &rules, &dns);
        let json = serde_json::to_value(&config).unwrap();
        let exp = &json["experimental"];
        assert_eq!(
            exp["clash_api"]["external_controller"],
            format!("127.0.0.1:{}", crate::config_builder::CLASH_API_PORT)
        );
        // v2ray_api should still be present (it was true in default_params)
        assert!(exp["v2ray_api"].is_object(), "v2ray_api should be present");
    }

    #[test]
    fn singbox_route_config() {
        let rules = vec![domain_rule()];
        let route = build_routing(&rules);
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(json["rules"].as_array().unwrap().len(), 1);
        assert_eq!(json["rules"][0]["domain"][0], "example.com");
        assert_eq!(json["rules"][0]["outbound"], "direct");
        assert_eq!(json["final"], "proxy");
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
        let routing = build_routing(&[rule]);
        assert_eq!(routing.rules.len(), 0);
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
        let routing = build_routing(&[rule]);
        let rule_json = &routing.rules[0];
        assert_eq!(rule_json["domain_matcher"], "linear");
        assert_eq!(rule_json["protocol"], json!(["http", "tls"]));
    }

    #[test]
    fn routing_skips_source_ports_only_rules() {
        // The sing-box builder has no source_port field, so a rule whose only
        // match condition is source_ports must be skipped (not emitted as a
        // catch-all rule).
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
        let routing = build_routing(&[rule]);
        assert_eq!(routing.rules.len(), 0);
    }

    #[test]
    fn singbox_dns_skeleton_from_typed_settings() {
        let dns = DnsSetting {
            id: "default".to_string(),
            name: None,
            servers: vec!["1.1.1.1".to_string()],
            hosts: vec!["example.com:1.2.3.4".to_string()],
            query_strategy: None,
            disable_cache: false,
            disable_fallback: false,
            client_ip: None,
            cache_ttl_secs: None,
        };
        let config = build_dns(&dns);
        assert_eq!(json!(config.servers), json!(["1.1.1.1"]));
        assert_eq!(config.hosts["example.com"], "1.2.3.4");
    }
}
