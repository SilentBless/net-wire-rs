//! ICMPv6 wire messages (RFC 4443).

mod builder;
#[cfg(all(feature = "icmpv6", feature = "ipv6"))]
mod checksum;
pub(crate) mod message;
mod types;

pub use builder::{Icmpv6MessageBuildError, Icmpv6MessageBuilder};
#[cfg(all(feature = "icmpv6", feature = "ipv6"))]
pub use checksum::Icmpv6ChecksumError;
pub use message::{Icmpv6Message, Icmpv6MessageMut};
pub use types::Icmpv6Type;
