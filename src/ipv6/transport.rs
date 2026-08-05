//! IPv6 pseudoheader checksum integration for transport protocols.

use super::Ipv6Address;
#[cfg(any(feature = "icmpv6", feature = "tcp"))]
use crate::PseudoHeaderChecksumError;
#[cfg(any(feature = "icmpv6", feature = "tcp", feature = "udp"))]
use crate::checksum::{self, add_ipv6_pseudoheader};
#[cfg(feature = "icmpv6")]
use crate::{Icmpv6Message, Icmpv6MessageMut};
#[cfg(feature = "tcp")]
use crate::{TcpSegment, TcpSegmentMut};
#[cfg(feature = "udp")]
use crate::{UdpDatagram, UdpDatagramMut};

#[cfg(feature = "icmpv6")]
const ICMPV6_NEXT_HEADER: u8 = 58;
#[cfg(feature = "tcp")]
const TCP_NEXT_HEADER: u8 = 6;
#[cfg(feature = "udp")]
const UDP_NEXT_HEADER: u8 = 17;

#[cfg(feature = "tcp")]
impl TcpSegment<'_> {
    /// Checks this TCP segment against its IPv6 pseudoheader.
    pub fn checksum_is_valid_ipv6(
        &self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<bool, PseudoHeaderChecksumError> {
        let length = pseudoheader_length(self.as_bytes())?;
        Ok(checksum_sum(
            self.as_bytes(),
            source,
            destination,
            TCP_NEXT_HEADER,
            length,
        ) == 0xffff)
    }
}

#[cfg(feature = "tcp")]
impl TcpSegmentMut<'_> {
    /// Checks this TCP segment against its IPv6 pseudoheader.
    pub fn checksum_is_valid_ipv6(
        &self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<bool, PseudoHeaderChecksumError> {
        let length = pseudoheader_length(self.as_bytes())?;
        Ok(checksum_sum(
            self.as_bytes(),
            source,
            destination,
            TCP_NEXT_HEADER,
            length,
        ) == 0xffff)
    }

    /// Recomputes this TCP segment's IPv6 pseudoheader checksum.
    pub fn update_checksum_ipv6(
        &mut self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<(), PseudoHeaderChecksumError> {
        let length = pseudoheader_length(self.as_bytes())?;
        let bytes = self.as_bytes();
        let sum =
            checksum_sum_with_zero_checksum(bytes, source, destination, TCP_NEXT_HEADER, length);
        let value = checksum::checksum(sum);
        self.as_bytes_mut()[16..18].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }
}

#[cfg(feature = "icmpv6")]
impl<'a> Icmpv6Message<'a> {
    /// Checks this ICMPv6 message against its IPv6 pseudoheader.
    pub fn checksum_is_valid_ipv6(
        &self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<bool, PseudoHeaderChecksumError> {
        let length = pseudoheader_length(self.as_bytes())?;
        Ok(checksum_sum(
            self.as_bytes(),
            source,
            destination,
            ICMPV6_NEXT_HEADER,
            length,
        ) == 0xffff)
    }
}
#[cfg(feature = "icmpv6")]
impl<'a> Icmpv6MessageMut<'a> {
    /// Checks this ICMPv6 message against its IPv6 pseudoheader.
    pub fn checksum_is_valid_ipv6(
        &self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<bool, PseudoHeaderChecksumError> {
        let length = pseudoheader_length(self.as_bytes())?;
        Ok(checksum_sum(
            self.as_bytes(),
            source,
            destination,
            ICMPV6_NEXT_HEADER,
            length,
        ) == 0xffff)
    }
    /// Recomputes the ICMPv6 checksum using the supplied IPv6 pseudoheader.
    pub fn update_checksum_ipv6(
        &mut self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<(), PseudoHeaderChecksumError> {
        let length = pseudoheader_length(self.as_bytes())?;
        let bytes = self.as_bytes_mut();
        bytes[2..4].fill(0);
        let value = checksum::checksum(checksum_sum(
            bytes,
            source,
            destination,
            ICMPV6_NEXT_HEADER,
            length,
        ));
        bytes[2..4].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }
}
#[cfg(feature = "udp")]
impl<'a> UdpDatagram<'a> {
    /// Checks this datagram against its required IPv6 pseudoheader checksum.
    pub fn checksum_is_valid_ipv6(&self, source: Ipv6Address, destination: Ipv6Address) -> bool {
        self.checksum() != 0
            && checksum_sum(
                self.as_bytes(),
                source,
                destination,
                UDP_NEXT_HEADER,
                self.as_bytes().len() as u32,
            ) == 0xffff
    }
}
#[cfg(feature = "udp")]
impl<'a> UdpDatagramMut<'a> {
    /// Checks this datagram against its required IPv6 pseudoheader checksum.
    pub fn checksum_is_valid_ipv6(&self, source: Ipv6Address, destination: Ipv6Address) -> bool {
        self.checksum() != 0
            && checksum_sum(
                self.as_bytes(),
                source,
                destination,
                UDP_NEXT_HEADER,
                self.as_bytes().len() as u32,
            ) == 0xffff
    }
    /// Recomputes this datagram's IPv6 pseudoheader checksum.
    pub fn update_checksum_ipv6(&mut self, source: Ipv6Address, destination: Ipv6Address) {
        let bytes = self.as_bytes_mut();
        bytes[6..8].fill(0);
        let value = checksum::checksum(checksum_sum(
            bytes,
            source,
            destination,
            UDP_NEXT_HEADER,
            bytes.len() as u32,
        ));
        bytes[6..8].copy_from_slice(&(if value == 0 { 0xffff } else { value }).to_be_bytes());
    }
}
#[cfg(any(feature = "icmpv6", feature = "tcp"))]
fn pseudoheader_length(bytes: &[u8]) -> Result<u32, PseudoHeaderChecksumError> {
    let maximum = usize::try_from(u32::MAX).unwrap_or(usize::MAX);
    u32::try_from(bytes.len()).map_err(|_| PseudoHeaderChecksumError::LengthTooLarge {
        maximum,
        actual: bytes.len(),
    })
}
#[cfg(any(feature = "icmpv6", feature = "tcp", feature = "udp"))]
fn checksum_sum(
    bytes: &[u8],
    source: Ipv6Address,
    destination: Ipv6Address,
    next_header: u8,
    length: u32,
) -> u32 {
    checksum::add_bytes(
        add_ipv6_pseudoheader(
            0,
            source.octets(),
            destination.octets(),
            next_header,
            length,
        ),
        bytes,
    )
}

#[cfg(feature = "tcp")]
fn checksum_sum_with_zero_checksum(
    bytes: &[u8],
    source: Ipv6Address,
    destination: Ipv6Address,
    next_header: u8,
    length: u32,
) -> u32 {
    let sum = add_ipv6_pseudoheader(
        0,
        source.octets(),
        destination.octets(),
        next_header,
        length,
    );
    let sum = checksum::add_bytes(sum, &bytes[..16]);
    let sum = checksum::add_bytes(sum, &[0, 0]);
    checksum::add_bytes(sum, &bytes[18..])
}
