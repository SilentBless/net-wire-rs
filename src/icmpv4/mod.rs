//! ICMPv4 wire messages (RFC 792).

mod builder;
mod layout;
pub(crate) mod message;
mod types;

pub use builder::{Icmpv4MessageBuildError, Icmpv4MessageBuilder};
pub use message::{Icmpv4Message, Icmpv4MessageMut, Icmpv4MessageMutationError};
pub use types::Icmpv4Type;
