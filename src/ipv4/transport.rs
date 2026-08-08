//! IPv4 pseudoheader checksum integration for transport protocols.

use super::address::Ipv4Address;
#[cfg(any(feature = "tcp", feature = "udp"))]
use crate::checksum::{self, add_ipv4_pseudoheader};
#[cfg(feature = "udp")]
use crate::udp::{UdpDatagram, UdpDatagramMut};
#[cfg(feature = "tcp")]
use crate::{
    pseudoheader::PseudoHeaderChecksumError,
    tcp::{TcpSegment, TcpSegmentMut},
};

#[cfg(feature = "tcp")]
const TCP_PROTOCOL: u8 = 6;
#[cfg(feature = "udp")]
const UDP_PROTOCOL: u8 = 17;

#[cfg(feature = "tcp")]
impl TcpSegment<'_> {
    /// Checks this TCP segment against its IPv4 pseudoheader.
    pub fn checksum_is_valid_ipv4(
        &self,
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> Result<bool, PseudoHeaderChecksumError> {
        Ok(tcp_ipv4_sum(self.as_bytes(), source, destination)? == 0xffff)
    }
}

#[cfg(feature = "tcp")]
impl TcpSegmentMut<'_> {
    /// Checks this TCP segment against its IPv4 pseudoheader.
    pub fn checksum_is_valid_ipv4(
        &self,
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> Result<bool, PseudoHeaderChecksumError> {
        Ok(tcp_ipv4_sum(self.as_bytes(), source, destination)? == 0xffff)
    }

    /// Recomputes this TCP segment's IPv4 pseudoheader checksum.
    pub fn update_checksum_ipv4(
        &mut self,
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> Result<(), PseudoHeaderChecksumError> {
        let sum = tcp_ipv4_sum_with_zero_checksum(self.as_bytes(), source, destination)?;
        let value = checksum::checksum(sum);
        self.as_bytes_mut()[16..18].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }
}

#[cfg(feature = "tcp")]
fn tcp_ipv4_sum(
    bytes: &[u8],
    source: Ipv4Address,
    destination: Ipv4Address,
) -> Result<u32, PseudoHeaderChecksumError> {
    let length = tcp_ipv4_length(bytes)?;
    Ok(checksum::add_bytes(
        add_ipv4_pseudoheader(
            0,
            source.octets(),
            destination.octets(),
            TCP_PROTOCOL,
            length,
        ),
        bytes,
    ))
}

#[cfg(feature = "tcp")]
fn tcp_ipv4_sum_with_zero_checksum(
    bytes: &[u8],
    source: Ipv4Address,
    destination: Ipv4Address,
) -> Result<u32, PseudoHeaderChecksumError> {
    let length = tcp_ipv4_length(bytes)?;
    let sum = add_ipv4_pseudoheader(
        0,
        source.octets(),
        destination.octets(),
        TCP_PROTOCOL,
        length,
    );
    let sum = checksum::add_bytes(sum, &bytes[..16]);
    let sum = checksum::add_bytes(sum, &[0, 0]);
    Ok(checksum::add_bytes(sum, &bytes[18..]))
}

#[cfg(feature = "tcp")]
fn tcp_ipv4_length(bytes: &[u8]) -> Result<u16, PseudoHeaderChecksumError> {
    u16::try_from(bytes.len()).map_err(|_| PseudoHeaderChecksumError::LengthTooLarge {
        maximum: usize::from(u16::MAX),
        actual: bytes.len(),
    })
}

/// The validation state of an IPv4 UDP checksum.
#[cfg(feature = "udp")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpChecksumStatus {
    /// UDP has no IPv4 checksum.
    NotPresent,
    /// The encoded checksum is valid.
    Valid,
    /// The encoded checksum is invalid.
    Invalid,
}

#[cfg(feature = "udp")]
impl UdpDatagram<'_> {
    /// Returns the validation state of this datagram's IPv4 checksum.
    pub fn checksum_status_ipv4(
        &self,
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> UdpChecksumStatus {
        if self.checksum() == 0 {
            return UdpChecksumStatus::NotPresent;
        }
        if udp_checksum_sum(self.as_bytes(), source, destination) == 0xffff {
            UdpChecksumStatus::Valid
        } else {
            UdpChecksumStatus::Invalid
        }
    }
}

#[cfg(feature = "udp")]
impl UdpDatagramMut<'_> {
    /// Returns the validation state of this datagram's IPv4 checksum.
    pub fn checksum_status_ipv4(
        &self,
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> UdpChecksumStatus {
        if self.checksum() == 0 {
            return UdpChecksumStatus::NotPresent;
        }
        if udp_checksum_sum(self.as_bytes(), source, destination) == 0xffff {
            UdpChecksumStatus::Valid
        } else {
            UdpChecksumStatus::Invalid
        }
    }

    /// Recomputes this datagram's IPv4 checksum.
    pub fn update_checksum_ipv4(&mut self, source: Ipv4Address, destination: Ipv4Address) {
        let bytes = self.as_bytes_mut();
        bytes[6..8].fill(0);
        let value = checksum::checksum(udp_checksum_sum(bytes, source, destination));
        bytes[6..8].copy_from_slice(&(if value == 0 { 0xffff } else { value }).to_be_bytes());
    }
}

#[cfg(feature = "udp")]
fn udp_checksum_sum(bytes: &[u8], source: Ipv4Address, destination: Ipv4Address) -> u32 {
    let length = u16::try_from(bytes.len()).expect("UDP length is validated");
    checksum::add_bytes(
        add_ipv4_pseudoheader(
            0,
            source.octets(),
            destination.octets(),
            UDP_PROTOCOL,
            length,
        ),
        bytes,
    )
}
