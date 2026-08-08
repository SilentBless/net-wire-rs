//! IPv6 concrete upper-layer dispatch after extension-header traversal.

use super::error::Ipv6DispatchError;
use super::extensions;
use super::next_header::Ipv6NextHeader;
use super::packet::{Ipv6Packet, Ipv6PacketMut};
#[cfg(feature = "icmpv6")]
use crate::icmpv6::message::{Icmpv6Message, Icmpv6MessageMut};
#[cfg(feature = "tcp")]
use crate::tcp::segment::{TcpSegment, TcpSegmentMut};
#[cfg(feature = "udp")]
use crate::udp::datagram::{UdpDatagram, UdpDatagramMut};

impl<'a> Ipv6Packet<'a> {
    /// Parses ICMPv6 after traversing supported IPv6 extension headers.
    #[cfg(feature = "icmpv6")]
    #[inline]
    pub fn icmpv6(&self) -> Result<Option<Icmpv6Message<'a>>, Ipv6DispatchError> {
        let traversal = extensions::traverse(
            self.next_header(),
            self.raw_payload_length(),
            self.payload(),
        )
        .map_err(Ipv6DispatchError::Traversal)?;
        if traversal.non_atomic_fragment || traversal.next_header != Ipv6NextHeader::ICMPV6.raw() {
            return Ok(None);
        }
        Icmpv6Message::parse(&self.payload()[traversal.upper_offset..])
            .map(Some)
            .map_err(Ipv6DispatchError::UpperLayer)
    }

    /// Parses UDP after traversing supported IPv6 extension headers.
    #[cfg(feature = "udp")]
    #[inline]
    pub fn udp(&self) -> Result<Option<UdpDatagram<'a>>, Ipv6DispatchError> {
        let traversal = extensions::traverse(
            self.next_header(),
            self.raw_payload_length(),
            self.payload(),
        )
        .map_err(Ipv6DispatchError::Traversal)?;
        if traversal.non_atomic_fragment || traversal.next_header != Ipv6NextHeader::UDP.raw() {
            return Ok(None);
        }
        UdpDatagram::parse(&self.payload()[traversal.upper_offset..])
            .map(Some)
            .map_err(Ipv6DispatchError::UpperLayer)
    }

    /// Parses TCP after traversing supported IPv6 extension headers.
    #[cfg(feature = "tcp")]
    #[inline]
    pub fn tcp(&self) -> Result<Option<TcpSegment<'a>>, Ipv6DispatchError> {
        let traversal = extensions::traverse(
            self.next_header(),
            self.raw_payload_length(),
            self.payload(),
        )
        .map_err(Ipv6DispatchError::Traversal)?;
        if traversal.non_atomic_fragment || traversal.next_header != Ipv6NextHeader::TCP.raw() {
            return Ok(None);
        }
        TcpSegment::parse(&self.payload()[traversal.upper_offset..])
            .map(Some)
            .map_err(Ipv6DispatchError::UpperLayer)
    }
}

impl<'a> Ipv6PacketMut<'a> {
    /// Parses mutable ICMPv6 after traversing supported IPv6 extension headers.
    #[cfg(feature = "icmpv6")]
    #[inline]
    pub fn icmpv6_mut(&mut self) -> Result<Option<Icmpv6MessageMut<'_>>, Ipv6DispatchError> {
        let traversal = extensions::traverse(
            self.next_header(),
            self.raw_payload_length(),
            self.payload(),
        )
        .map_err(Ipv6DispatchError::Traversal)?;
        if traversal.non_atomic_fragment || traversal.next_header != Ipv6NextHeader::ICMPV6.raw() {
            return Ok(None);
        }
        Icmpv6MessageMut::parse(&mut self.payload_mut()[traversal.upper_offset..])
            .map(Some)
            .map_err(Ipv6DispatchError::UpperLayer)
    }

    /// Parses mutable UDP after traversing supported IPv6 extension headers.
    #[cfg(feature = "udp")]
    #[inline]
    pub fn udp_mut(&mut self) -> Result<Option<UdpDatagramMut<'_>>, Ipv6DispatchError> {
        let traversal = extensions::traverse(
            self.next_header(),
            self.raw_payload_length(),
            self.payload(),
        )
        .map_err(Ipv6DispatchError::Traversal)?;
        if traversal.non_atomic_fragment || traversal.next_header != Ipv6NextHeader::UDP.raw() {
            return Ok(None);
        }
        UdpDatagramMut::parse(&mut self.payload_mut()[traversal.upper_offset..])
            .map(Some)
            .map_err(Ipv6DispatchError::UpperLayer)
    }

    /// Parses mutable TCP after traversing supported IPv6 extension headers.
    #[cfg(feature = "tcp")]
    #[inline]
    pub fn tcp_mut(&mut self) -> Result<Option<TcpSegmentMut<'_>>, Ipv6DispatchError> {
        let traversal = extensions::traverse(
            self.next_header(),
            self.raw_payload_length(),
            self.payload(),
        )
        .map_err(Ipv6DispatchError::Traversal)?;
        if traversal.non_atomic_fragment || traversal.next_header != Ipv6NextHeader::TCP.raw() {
            return Ok(None);
        }
        TcpSegmentMut::parse(&mut self.payload_mut()[traversal.upper_offset..])
            .map(Some)
            .map_err(Ipv6DispatchError::UpperLayer)
    }
}
