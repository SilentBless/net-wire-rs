#![no_std]
#![deny(missing_docs)]

//! Borrowed, allocation-free views of network wire layouts.
//!
//! This crate performs no I/O, allocation, or transport dispatch. The default feature
//! set is empty; `ethernet`, `arp`, `ipv4`, and `ipv6` are independent.

#[cfg(feature = "arp")]
/// ARP packet views, semantic fields, and caller-buffer construction.
pub mod arp;
/// Allocation-free parsing errors.
pub mod error;
#[cfg(feature = "ethernet")]
/// Ethernet II frame views, semantic fields, and caller-buffer construction.
pub mod ethernet;
#[cfg(any(feature = "arp", feature = "ipv4"))]
mod ip;
#[cfg(feature = "ipv4")]
/// IPv4 packet views, semantic fields, and caller-buffer construction.
pub mod ipv4;
#[cfg(feature = "ipv6")]
/// IPv6 packet views, semantic fields, and caller-buffer construction.
pub mod ipv6;

#[cfg(feature = "arp")]
pub use arp::{
    ArpHardwareType, ArpOperation, ArpPacket, ArpPacketBuildError, ArpPacketBuilder, ArpPacketMut,
    ArpProtocolType,
};
pub use error::ParseError;
#[cfg(feature = "ethernet")]
pub use ethernet::{
    EtherType, EthernetFrame, EthernetFrameBuildError, EthernetFrameBuilder, EthernetFrameMut,
    MacAddress,
};
#[cfg(any(feature = "arp", feature = "ipv4"))]
pub use ip::Ipv4Address;
#[cfg(feature = "ipv4")]
pub use ipv4::{Ipv4Packet, Ipv4PacketBuildError, Ipv4PacketBuilder, Ipv4PacketMut, Ipv4Protocol};
#[cfg(feature = "ipv6")]
pub use ipv6::{
    Ipv6Address, Ipv6NextHeader, Ipv6Packet, Ipv6PacketBuildError, Ipv6PacketBuilder,
    Ipv6PacketMut, Ipv6PayloadLength,
};
