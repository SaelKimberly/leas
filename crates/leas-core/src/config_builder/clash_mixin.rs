/// Parse Clash mixin YAML/JSON string into a `serde_json::Value`.
/// Tries JSON first (fast path), falls back to YAML via `yaml-rust2`.
pub fn parse_clash_mixin(input: &str) -> Option<serde_json::Value> {
    if input.trim().is_empty() {
        return None;
    }
    // Try JSON first
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(input) {
        return Some(v);
    }
    // Fall back to YAML
    let yaml = yaml_rust2::YamlLoader::load_from_str(input).ok()?;
    if yaml.is_empty() {
        return None;
    }
    yaml_to_value(&yaml[0])
}

fn yaml_to_value(y: &yaml_rust2::Yaml) -> Option<serde_json::Value> {
    Some(match y {
        yaml_rust2::Yaml::Real(s) => {
            if let Ok(f) = s.parse::<f64>() {
                serde_json::json!(f)
            } else {
                serde_json::json!(s)
            }
        }
        yaml_rust2::Yaml::Integer(i) => serde_json::json!(i),
        yaml_rust2::Yaml::String(s) => serde_json::json!(s),
        yaml_rust2::Yaml::Boolean(b) => serde_json::json!(b),
        yaml_rust2::Yaml::Array(arr) => {
            let items: Vec<serde_json::Value> = arr.iter().filter_map(yaml_to_value).collect();
            serde_json::Value::Array(items)
        }
        yaml_rust2::Yaml::Hash(hash) => {
            let mut map = serde_json::Map::new();
            for (k, v) in hash {
                if let Some(key) = k.as_str()
                    && let Some(val) = yaml_to_value(v)
                {
                    map.insert(key.to_string(), val);
                }
            }
            serde_json::Value::Object(map)
        }
        yaml_rust2::Yaml::Null | yaml_rust2::Yaml::BadValue | yaml_rust2::Yaml::Alias(_) => {
            return None;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json() {
        let result = parse_clash_mixin(r#"{"dns":{"enabled":true}}"#).unwrap();
        assert!(result.is_object());
        assert!(result.get("dns").is_some());
    }

    #[test]
    fn parse_yaml() {
        let result = parse_clash_mixin("dns:\n  enabled: true\n").unwrap();
        assert!(result.is_object());
        assert!(result.get("dns").is_some());
    }

    #[test]
    fn parse_yaml_list() {
        let result =
            parse_clash_mixin("rules:\n  - DOMAIN-SUFFIX,example.com,Proxy\n  - MATCH,DIRECT\n")
                .unwrap();
        let rules = result.get("rules").and_then(|v| v.as_array()).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn parse_empty() {
        assert!(parse_clash_mixin("").is_none());
        assert!(parse_clash_mixin("  ").is_none());
    }

    #[test]
    fn parse_invalid() {
        // Garbage that's neither valid JSON nor valid YAML
        assert!(parse_clash_mixin("\0\x01\x02").is_none());
    }
}
