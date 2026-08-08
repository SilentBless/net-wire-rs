//! IPv4 packet integration for Ethernet frames.

use super::packet::{Ipv4Packet, Ipv4PacketMut};
use crate::error::ParseError;
use crate::ethernet::{
    ether_type::EtherType,
    frame::{EthernetFrame, EthernetFrameMut},
};

impl<'a> EthernetFrame<'a> {
    /// Parses IPv4 only for the IPv4 EtherType.
    #[inline]
    pub fn ipv4(&self) -> Result<Option<Ipv4Packet<'a>>, ParseError> {
        if self.ether_type() != EtherType::IPV4 {
            return Ok(None);
        }
        Ipv4Packet::parse(self.payload()).map(Some)
    }
}

impl<'a> EthernetFrameMut<'a> {
    /// Parses mutable IPv4 only for the IPv4 EtherType.
    #[inline]
    pub fn ipv4_mut(&mut self) -> Result<Option<Ipv4PacketMut<'_>>, ParseError> {
        if self.ether_type() != EtherType::IPV4 {
            return Ok(None);
        }
        Ipv4PacketMut::parse(self.payload_mut()).map(Some)
    }
}
