/// A four-octet IPv4 address in wire order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv4Address([u8; 4]);

impl Ipv4Address {
    /// Constructs an address from wire-order octets.
    #[inline]
    pub const fn new(octets: [u8; 4]) -> Self {
        Self(octets)
    }

    /// Returns wire-order octets.
    #[inline]
    pub const fn octets(self) -> [u8; 4] {
        self.0
    }
}

#[cfg(feature = "arp")]
use crate::arp::{ArpPacket, ArpProtocolType};

#[cfg(feature = "arp")]
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
