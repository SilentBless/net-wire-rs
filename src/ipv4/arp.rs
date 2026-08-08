//! IPv4 address integration for ARP packets.

use super::address::Ipv4Address;
use crate::arp::{packet::ArpPacket, types::ArpProtocolType};

impl ArpPacket<'_> {
    /// Returns the sender IPv4 address when the protocol type is IPv4 and its size is four.
    #[inline]
    pub fn sender_ipv4_address(&self) -> Option<Ipv4Address> {
        if self.protocol_type() != ArpProtocolType::IPV4
            || self.sender_protocol_address().len() != 4
        {
            return None;
        }
        Some(Ipv4Address::new(
            self.sender_protocol_address()
                .try_into()
                .expect("checked address length"),
        ))
    }

    /// Returns the target IPv4 address when the protocol type is IPv4 and its size is four.
    #[inline]
    pub fn target_ipv4_address(&self) -> Option<Ipv4Address> {
        if self.protocol_type() != ArpProtocolType::IPV4
            || self.target_protocol_address().len() != 4
        {
            return None;
        }
        Some(Ipv4Address::new(
            self.target_protocol_address()
                .try_into()
                .expect("checked address length"),
        ))
    }
}
