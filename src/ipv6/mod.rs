//! IPv6 base-header views and construction (RFC 8200).

mod address;
mod builder;
#[cfg(any(feature = "icmpv6", feature = "udp", feature = "tcp"))]
mod dispatch;
#[cfg(any(feature = "icmpv6", feature = "udp", feature = "tcp"))]
mod error;
#[cfg(feature = "ethernet")]
mod ethernet;
#[cfg(any(feature = "icmpv6", feature = "udp", feature = "tcp"))]
mod extensions;
mod next_header;
mod packet;
#[cfg(any(feature = "icmpv6", feature = "udp", feature = "tcp"))]
mod transport;

pub use address::Ipv6Address;
pub use builder::{Ipv6PacketBuildError, Ipv6PacketBuilder};
#[cfg(any(feature = "icmpv6", feature = "udp", feature = "tcp"))]
pub use error::{Ipv6DispatchError, Ipv6ExtensionTraversalError};
pub use next_header::Ipv6NextHeader;
pub use packet::{Ipv6Packet, Ipv6PacketMut, Ipv6PayloadLength};
