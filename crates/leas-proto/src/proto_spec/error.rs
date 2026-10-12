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
    use rstest::rstest;

    #[rstest]
    #[case::unsupported_protocol(
        SupportError::UnsupportedProtocol("tuic".into(), CoreType::SingBox),
        "protocol tuic is not supported by core sing-box"
    )]
    #[case::config(
        SupportError::Config("invalid listen address".into()),
        "config error: invalid listen address"
    )]
    #[case::missing_field(
        SupportError::MissingField("password", "shadowsocks"),
        "missing required field password for shadowsocks"
    )]
    fn support_error_message(#[case] err: SupportError, #[case] expected: &str) {
        assert_eq!(err.to_string(), expected);
    }
}
