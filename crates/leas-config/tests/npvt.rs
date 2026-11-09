// Fixtures are real client output, not generated vectors:
// - legacy.npvt: supplied by the project owner (NapsterV 124.0.37 export).
// - passphrase.npvs: public SiNAVM channel sample, passphrase `@sinavm`.
// They are small (7.7 KiB total) and keep the two portable paths tied to the
// actual app format rather than to this parser's own encoder.

use leas_config::import_export::ValidationSettings;
use leas_config::npvt::{Bundle, Format, NpvtError, decode, detect};
use leas_config::subscription::parse_subscription_data;
use leas_proto::ProtocolKind;
use leas_proto::proto_spec::ProtocolConfig;
use leas_proto::proto_spec::common::TransportConfig;

const LEGACY: &[u8] = include_bytes!("fixtures/npvt/legacy.npvt");
const PASSPHRASE: &[u8] = include_bytes!("fixtures/npvt/passphrase.npvs");

#[test]
fn legacy_sample_decrypts() {
    assert_eq!(detect(LEGACY), Some(Format::Legacy));
    let bundle = decode(LEGACY, None).expect("legacy sample");
    assert_eq!(bundle.version, 1);
    assert_eq!(bundle.configs.len(), 1);
    assert_eq!(bundle.configs[0]["name"], "@ipV2Ray - Config 🍇 2");
    assert_eq!(bundle.configs[0]["type"], "V2RAY");
    assert_eq!(bundle.configs[0]["address"], "104.17.108.1:443");
    let info = bundle.user_info.expect("legacy user info");
    assert_eq!(info["isLocked"], true);
    assert!(
        info["message"]
            .as_str()
            .is_some_and(|m| m.contains("t.me/ipV2Ray"))
    );
}

#[test]
fn legacy_subscription_prefix_is_accepted() {
    let mut data = b"NPVTSUB1\n".to_vec();
    data.extend_from_slice(LEGACY);
    let bundle = decode(&data, None).expect("prefixed legacy bundle");
    assert_eq!(bundle.configs.len(), 1);
}

#[test]
fn passphrase_v5_sample_decrypts_and_substitutes_fields() {
    assert_eq!(detect(PASSPHRASE), Some(Format::Sealed(5)));
    let bundle = decode(PASSPHRASE, Some("@sinavm")).expect("passphrase sample");
    assert_eq!(bundle.version, 5);
    let subscription = bundle.subscription.expect("5194 carries a subscription");
    assert_eq!(subscription["kind"], "v4-sub");
    assert_eq!(
        subscription["url"],
        "https://sinavm5.soft10.ir:2053/wtawd684didh9rpl/olueudsbno2dt9r2"
    );
    assert_eq!(subscription["autoUpdateHours"], "12");
    assert!(
        bundle
            .creator_message
            .as_deref()
            .is_some_and(|message| message.contains("SiNAVM"))
    );
}

#[test]
fn passphrase_v5_distinguishes_missing_and_wrong_passphrase() {
    assert!(matches!(
        decode(PASSPHRASE, None),
        Err(NpvtError::PassphraseRequired)
    ));
    assert!(matches!(
        decode(PASSPHRASE, Some("not-the-password")),
        Err(NpvtError::Crypt)
    ));
}

#[test]
fn open_bundle_decodes_sentinels() {
    let data = br#"NPVO1
{"configs":[{"name":"a","address":"h:1","type":"v2ray","message":"npvs1:aGk="}]}"#;
    let bundle = decode(data, None).expect("open bundle");
    assert_eq!(bundle.configs.len(), 1);
    assert_eq!(bundle.configs[0]["message"], "hi");
}

#[test]
fn legacy_custom_profile_maps_to_vless_parsed_proto() {
    let bundle = decode(LEGACY, None).expect("legacy sample");
    let config = bundle.typed_configs().pop().expect("one typed config");
    let parsed = config.to_parsed_proto().expect("direct mapping");
    assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Vless);
    assert_eq!(parsed.endpoints[0].host, "104.17.108.1");
    assert_eq!(parsed.endpoints[0].port, 443);
    let ProtocolConfig::Vless(vless) = &parsed.protocol.config else {
        panic!("expected VLESS");
    };
    assert_eq!(vless.uuid, "8376b8b2-e3dd-4d81-bce6-436eb3ba1022");
    let TransportConfig::XHttp(xhttp) = &vless.transport else {
        panic!("expected XHTTP transport");
    };
    assert_eq!(xhttp.path.as_deref(), Some("/"));
    assert_eq!(xhttp.host.as_deref(), Some("ab.xonira.ir"));
    assert_eq!(xhttp.mode.as_deref(), Some("packet-up"));
    assert_eq!(vless.security.sni(), Some("ab.xonira.ir"));
}

#[test]
fn structured_hysteria2_profile_maps_directly() {
    let bundle = Bundle {
        version: 5,
        configs: vec![serde_json::json!({
            "name": "hy2",
            "address": "hy.example:443",
            "type": "v2ray",
            "v2rayProfile": {
                "configType": 9,
                "server": "hy.example",
                "serverPort": "443",
                "password": "secret",
                "security": "tls",
                "sni": "hy.example",
                "insecure": "true",
                "obfsPassword": "obfs",
                "uploadMbps": "20",
                "downloadMbps": "100",
                "portHopping": "30"
            }
        })],
        user_info: None,
        creator_message: None,
        payload: None,
        subscription: None,
    };
    let parsed = bundle.typed_configs()[0]
        .to_parsed_proto()
        .expect("hy2 mapping");
    assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Hysteria2);
    let ProtocolConfig::Hysteria2(hy2) = &parsed.protocol.config else {
        panic!("expected Hysteria2");
    };
    assert_eq!(hy2.auth, "secret");
    assert_eq!(hy2.obfs.as_deref(), Some("salamander"));
    assert_eq!(hy2.obfs_password.as_deref(), Some("obfs"));
    assert_eq!(hy2.up.as_deref(), Some("20"));
    assert_eq!(hy2.down.as_deref(), Some("100"));
    assert_eq!(hy2.hop_interval, Some(30));
    assert_eq!(hy2.security.sni(), Some("hy.example"));
}

#[test]
fn subscription_pipeline_consumes_legacy_directly() {
    let settings = ValidationSettings {
        allow_private_ips: false,
        reject_insecure: false,
    };
    let (profiles, summary) = parse_subscription_data(LEGACY, &settings).expect("NP VT import");
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].parsed.protocol.proto_kind, ProtocolKind::Vless);
    assert_eq!(summary.total_errors, 0);
}

#[test]
fn non_npvt_input_is_rejected() {
    assert!(matches!(
        decode(b"vmess://x", None),
        Err(NpvtError::NotNpvt)
    ));
}
