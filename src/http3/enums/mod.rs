//! Shared HTTP/3 protocol vocabulary.

pub(super) mod message;
pub(super) mod stream;

pub use message::{Http3HeadersContext, Http3HeadersKind};
pub use stream::{Http3EndpointRole, Http3UniStreamKind};
