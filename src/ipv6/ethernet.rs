use super::packet::{Ipv6Packet, Ipv6PacketMut};
use crate::error::ParseError;
use crate::ethernet::{
    ether_type::EtherType,
    layout::{EthernetFrameView, EthernetFrameViewMut},
};

impl<'a> EthernetFrameView<'a> {
    /// Parses IPv6 only when this frame's EtherType is IPv6.
    #[inline]
    pub fn ipv6(&self) -> Result<Option<Ipv6Packet<'a>>, ParseError> {
        if self.ether_type() != EtherType::IPV6 {
            return Ok(None);
        }
        Ipv6Packet::parse(self.payload()).map(Some)
    }
}

impl<'a> EthernetFrameViewMut<'a> {
    /// Parses mutable IPv6 only when this frame's EtherType is IPv6.
    #[inline]
    pub fn ipv6_mut(&mut self) -> Result<Option<Ipv6PacketMut<'_>>, ParseError> {
        if self.ether_type() != EtherType::IPV6 {
            return Ok(None);
        }
        Ipv6PacketMut::parse(self.payload_mut()).map(Some)
    }
}
