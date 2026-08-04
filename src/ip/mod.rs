//! Shared address types used by current Internet-layer protocols.

mod address;

/// IPv4 addresses shared by ARP and IPv4.
pub use address::Ipv4Address;
