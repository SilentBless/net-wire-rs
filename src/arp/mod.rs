//! Address Resolution Protocol packet views and construction (RFC 826).

#[cfg(feature = "ethernet")]
mod ethernet;
mod layout;
pub(crate) mod types;

pub use layout::{
    ArpPacket, ArpPacketBuilder, ArpPacketError, ArpPacketMutationError, ArpPacketViewMut,
    ArpPacketWriteError,
};
pub use types::{ArpHardwareType, ArpOperation, ArpProtocolType};
