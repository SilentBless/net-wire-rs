//! IPv4 protocol values, packet views, and construction (RFC 791).

pub(crate) mod address;
#[cfg(feature = "arp")]
mod arp;
mod builder;
#[cfg(any(feature = "icmpv4", feature = "udp", feature = "tcp"))]
mod dispatch;
#[cfg(feature = "ethernet")]
mod ethernet;
mod layout;
mod packet;
mod protocol;

pub use address::Ipv4Address;
pub use builder::{Ipv4PacketBuildError, Ipv4PacketBuilder};
pub use packet::{Ipv4Packet, Ipv4PacketMut, Ipv4PacketMutationError};
pub use protocol::Ipv4Protocol;
