pub mod host_port;

pub use host_port::host_port_spec;

// restrict to crate internal usage
pub type Span<'a> = &'a [u8];
/// Type alias for nom error
pub type NomError<'a, E = nom::error::Error<Span<'a>>> = nom::Err<E>;
/// Type alias for nom result with tail
pub type RawResult<'a, T = Span<'a>> = ::std::result::Result<(Span<'a>, T), NomError<'a>>;
