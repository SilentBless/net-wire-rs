//! Address Resolution Protocol packet views and construction (RFC 826).

mod builder;
#[cfg(feature = "ethernet")]
mod ethernet;
pub(crate) mod packet;
pub(crate) mod types;

pub use builder::{ArpPacketBuildError, ArpPacketBuilder};
pub use packet::{ArpPacket, ArpPacketMut};
pub use types::{ArpHardwareType, ArpOperation, ArpProtocolType};
