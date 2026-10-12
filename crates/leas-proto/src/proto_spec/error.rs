use crate::proto_spec::CoreType;

/// Errors surfaced by the `InjectToCoreConf` config-builder trait.
#[derive(Debug, thiserror::Error)]
pub enum SupportError {
    #[error("protocol {0} is not supported by core {1}")]
    UnsupportedProtocol(String, CoreType),
    #[error("config error: {0}")]
    Config(String),
    #[error("missing required field {0} for {1}")]
    MissingField(&'static str, &'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_protocol_message() {
        let err = SupportError::UnsupportedProtocol("tuic".into(), CoreType::SingBox);
        assert_eq!(
            err.to_string(),
            "protocol tuic is not supported by core sing-box"
        );
    }

    #[test]
    fn config_message() {
        let err = SupportError::Config("invalid listen address".into());
        assert_eq!(err.to_string(), "config error: invalid listen address");
    }

    #[test]
    fn missing_field_message() {
        let err = SupportError::MissingField("password", "shadowsocks");
        assert_eq!(
            err.to_string(),
            "missing required field password for shadowsocks"
        );
    }
}
