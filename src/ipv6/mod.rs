//! IPv6 base-header views and construction (RFC 8200).

pub(crate) mod address;
mod builder;
#[cfg(any(feature = "icmpv6", feature = "udp", feature = "tcp"))]
mod dispatch;
#[cfg(any(feature = "icmpv6", feature = "udp", feature = "tcp"))]
mod error;
#[cfg(feature = "ethernet")]
mod ethernet;
#[cfg(any(feature = "icmpv6", feature = "udp", feature = "tcp"))]
mod extensions;
mod layout;
mod next_header;
mod packet;

pub use address::Ipv6Address;
pub use builder::{Ipv6PacketBuildError, Ipv6PacketBuilder};
#[cfg(any(feature = "icmpv6", feature = "udp", feature = "tcp"))]
pub use error::{Ipv6DispatchError, Ipv6ExtensionTraversalError};
pub use next_header::Ipv6NextHeader;
pub use packet::{Ipv6Packet, Ipv6PacketMut, Ipv6PacketMutationError, Ipv6PayloadLength};
