//! IPv6 concrete upper-layer dispatch after extension-header traversal.

use super::{Ipv6NextHeader, Ipv6Packet, Ipv6PacketMut, extensions};
use crate::ParseError;
#[cfg(feature = "icmpv6")]
use crate::{Icmpv6Message, Icmpv6MessageMut};
#[cfg(feature = "tcp")]
use crate::{TcpSegment, TcpSegmentMut};
#[cfg(feature = "udp")]
use crate::{UdpDatagram, UdpDatagramMut};

impl<'a> Ipv6Packet<'a> {
    /// Parses ICMPv6 after traversing supported IPv6 extension headers.
    #[cfg(feature = "icmpv6")]
    #[inline]
    pub fn icmpv6(&self) -> Result<Option<Icmpv6Message<'a>>, ParseError> {
        let traversal = extensions::traverse(
            self.next_header(),
            self.raw_payload_length(),
            self.payload(),
        )?;
        if traversal.non_atomic_fragment || traversal.next_header != Ipv6NextHeader::ICMPV6.raw() {
            return Ok(None);
        }
        Icmpv6Message::parse(&self.payload()[traversal.upper_offset..]).map(Some)
    }

    /// Parses UDP after traversing supported IPv6 extension headers.
    #[cfg(feature = "udp")]
    #[inline]
    pub fn udp(&self) -> Result<Option<UdpDatagram<'a>>, ParseError> {
        let traversal = extensions::traverse(
            self.next_header(),
            self.raw_payload_length(),
            self.payload(),
        )?;
        if traversal.non_atomic_fragment || traversal.next_header != Ipv6NextHeader::UDP.raw() {
            return Ok(None);
        }
        UdpDatagram::parse(&self.payload()[traversal.upper_offset..]).map(Some)
    }

    /// Parses TCP after traversing supported IPv6 extension headers.
    #[cfg(feature = "tcp")]
    #[inline]
    pub fn tcp(&self) -> Result<Option<TcpSegment<'a>>, ParseError> {
        let traversal = extensions::traverse(
            self.next_header(),
            self.raw_payload_length(),
            self.payload(),
        )?;
        if traversal.non_atomic_fragment || traversal.next_header != Ipv6NextHeader::TCP.raw() {
            return Ok(None);
        }
        TcpSegment::parse(&self.payload()[traversal.upper_offset..]).map(Some)
    }
}

impl<'a> Ipv6PacketMut<'a> {
    /// Parses mutable ICMPv6 after traversing supported IPv6 extension headers.
    #[cfg(feature = "icmpv6")]
    #[inline]
    pub fn icmpv6_mut(&mut self) -> Result<Option<Icmpv6MessageMut<'_>>, ParseError> {
        let traversal = extensions::traverse(
            self.next_header(),
            self.raw_payload_length(),
            self.payload(),
        )?;
        if traversal.non_atomic_fragment || traversal.next_header != Ipv6NextHeader::ICMPV6.raw() {
            return Ok(None);
        }
        Icmpv6MessageMut::parse(&mut self.payload_mut()[traversal.upper_offset..]).map(Some)
    }

    /// Parses mutable UDP after traversing supported IPv6 extension headers.
    #[cfg(feature = "udp")]
    #[inline]
    pub fn udp_mut(&mut self) -> Result<Option<UdpDatagramMut<'_>>, ParseError> {
        let traversal = extensions::traverse(
            self.next_header(),
            self.raw_payload_length(),
            self.payload(),
        )?;
        if traversal.non_atomic_fragment || traversal.next_header != Ipv6NextHeader::UDP.raw() {
            return Ok(None);
        }
        UdpDatagramMut::parse(&mut self.payload_mut()[traversal.upper_offset..]).map(Some)
    }

    /// Parses mutable TCP after traversing supported IPv6 extension headers.
    #[cfg(feature = "tcp")]
    #[inline]
    pub fn tcp_mut(&mut self) -> Result<Option<TcpSegmentMut<'_>>, ParseError> {
        let traversal = extensions::traverse(
            self.next_header(),
            self.raw_payload_length(),
            self.payload(),
        )?;
        if traversal.non_atomic_fragment || traversal.next_header != Ipv6NextHeader::TCP.raw() {
            return Ok(None);
        }
        TcpSegmentMut::parse(&mut self.payload_mut()[traversal.upper_offset..]).map(Some)
    }
}
