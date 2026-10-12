pub mod clash;
pub mod domain;
pub mod proto_spec;
pub mod urlx;
pub mod utils;
pub use proto_spec::{
    EndpointEssentials, HostKind, ParsedProto, ProtocolEssentials, ProtocolKind, SecurityType,
    TransportType,
};
pub(crate) use urlx::PortSpec;
pub use urlx::SchemeX;

macro_rules! nom_bail {
    ($input: expr, $code: ident) => {{
        return Err(nom::Err::Error(nom::error::Error::new(
            $input,
            nom::error::ErrorKind::$code,
        )));
    }};
}
pub(crate) use nom_bail;
