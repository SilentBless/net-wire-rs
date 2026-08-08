//! IPv4 concrete upper-layer dispatch.

use super::packet::{Ipv4Packet, Ipv4PacketMut};
use super::protocol::Ipv4Protocol;
use crate::error::ParseError;
#[cfg(feature = "icmpv4")]
use crate::icmpv4::message::{Icmpv4Message, Icmpv4MessageMut};
#[cfg(feature = "tcp")]
use crate::tcp::segment::{TcpSegment, TcpSegmentMut};
#[cfg(feature = "udp")]
use crate::udp::datagram::{UdpDatagram, UdpDatagramMut};

#[inline]
fn is_non_atomic_fragment(flags_fragment_offset: u16) -> bool {
    flags_fragment_offset & 0x2000 != 0 || flags_fragment_offset & 0x1fff != 0
}

impl<'a> Ipv4Packet<'a> {
    /// Parses ICMPv4 only when this is an unfragmented ICMP packet.
    #[cfg(feature = "icmpv4")]
    #[inline]
    pub fn icmpv4(&self) -> Result<Option<Icmpv4Message<'a>>, ParseError> {
        if self.protocol() != Ipv4Protocol::ICMP
            || is_non_atomic_fragment(self.flags_fragment_offset())
        {
            return Ok(None);
        }
        Icmpv4Message::parse(self.payload()).map(Some)
    }

    /// Parses UDP only when this is an unfragmented UDP packet.
    #[cfg(feature = "udp")]
    #[inline]
    pub fn udp(&self) -> Result<Option<UdpDatagram<'a>>, ParseError> {
        if self.protocol() != Ipv4Protocol::UDP
            || is_non_atomic_fragment(self.flags_fragment_offset())
        {
            return Ok(None);
        }
        UdpDatagram::parse(self.payload()).map(Some)
    }

    /// Parses TCP only when this is an unfragmented TCP packet.
    #[cfg(feature = "tcp")]
    #[inline]
    pub fn tcp(&self) -> Result<Option<TcpSegment<'a>>, ParseError> {
        if self.protocol() != Ipv4Protocol::TCP
            || is_non_atomic_fragment(self.flags_fragment_offset())
        {
            return Ok(None);
        }
        TcpSegment::parse(self.payload()).map(Some)
    }
}

impl<'a> Ipv4PacketMut<'a> {
    /// Parses mutable ICMPv4 only when this is an unfragmented ICMP packet.
    #[cfg(feature = "icmpv4")]
    #[inline]
    pub fn icmpv4_mut(&mut self) -> Result<Option<Icmpv4MessageMut<'_>>, ParseError> {
        if self.protocol() != Ipv4Protocol::ICMP
            || is_non_atomic_fragment(self.flags_fragment_offset())
        {
            return Ok(None);
        }
        Icmpv4MessageMut::parse(self.payload_mut()).map(Some)
    }

    /// Parses mutable UDP only when this is an unfragmented UDP packet.
    #[cfg(feature = "udp")]
    #[inline]
    pub fn udp_mut(&mut self) -> Result<Option<UdpDatagramMut<'_>>, ParseError> {
        if self.protocol() != Ipv4Protocol::UDP
            || is_non_atomic_fragment(self.flags_fragment_offset())
        {
            return Ok(None);
        }
        UdpDatagramMut::parse(self.payload_mut()).map(Some)
    }

    /// Parses mutable TCP only when this is an unfragmented TCP packet.
    #[cfg(feature = "tcp")]
    #[inline]
    pub fn tcp_mut(&mut self) -> Result<Option<TcpSegmentMut<'_>>, ParseError> {
        if self.protocol() != Ipv4Protocol::TCP
            || is_non_atomic_fragment(self.flags_fragment_offset())
        {
            return Ok(None);
        }
        TcpSegmentMut::parse(self.payload_mut()).map(Some)
    }
}
