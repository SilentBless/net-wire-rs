//! ICMPv6 wire messages (RFC 4443).

mod builder;
mod message;
mod types;

pub use builder::{Icmpv6MessageBuildError, Icmpv6MessageBuilder};
pub use message::{Icmpv6Message, Icmpv6MessageMut};
pub use types::Icmpv6Type;
