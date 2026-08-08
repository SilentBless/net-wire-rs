//! TCP checksum integration for IP pseudoheaders.

use core::fmt;

use crate::internet_checksum;
#[cfg(all(feature = "tcp", feature = "ipv4"))]
use crate::internet_checksum::add_ipv4_pseudoheader;
#[cfg(all(feature = "tcp", feature = "ipv6"))]
use crate::internet_checksum::add_ipv6_pseudoheader;
#[cfg(all(feature = "tcp", feature = "ipv4"))]
use crate::ipv4::address::Ipv4Address;
#[cfg(all(feature = "tcp", feature = "ipv6"))]
use crate::ipv6::address::Ipv6Address;
use crate::tcp::segment::{TcpSegment, TcpSegmentMut};

const TCP_PROTOCOL: u8 = 6;

/// Failure to represent a TCP segment length in an IP pseudoheader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpChecksumError {
    /// The message length cannot be represented by the pseudoheader's length field.
    LengthTooLarge {
        /// Largest representable message length on this platform.
        maximum: usize,
        /// Actual message length.
        actual: usize,
    },
}

impl fmt::Display for TcpChecksumError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthTooLarge { maximum, actual } => write!(
                formatter,
                "transport message length {actual} exceeds pseudoheader maximum {maximum}"
            ),
        }
    }
}

#[cfg(all(feature = "tcp", feature = "ipv4"))]
impl TcpSegment<'_> {
    /// Checks this TCP segment against its IPv4 pseudoheader.
    pub fn checksum_is_valid_ipv4(
        &self,
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> Result<bool, TcpChecksumError> {
        Ok(tcp_ipv4_sum(self.as_bytes(), source, destination)? == 0xffff)
    }
}

#[cfg(all(feature = "tcp", feature = "ipv4"))]
impl TcpSegmentMut<'_> {
    /// Checks this TCP segment against its IPv4 pseudoheader.
    pub fn checksum_is_valid_ipv4(
        &self,
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> Result<bool, TcpChecksumError> {
        Ok(tcp_ipv4_sum(self.as_bytes(), source, destination)? == 0xffff)
    }

    /// Recomputes this TCP segment's IPv4 pseudoheader checksum.
    pub fn update_checksum_ipv4(
        &mut self,
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> Result<(), TcpChecksumError> {
        let sum = tcp_ipv4_sum_with_zero_checksum(self.as_bytes(), source, destination)?;
        let value = internet_checksum::checksum(sum);
        self.as_bytes_mut()[16..18].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }
}

#[cfg(all(feature = "tcp", feature = "ipv4"))]
fn tcp_ipv4_sum(
    bytes: &[u8],
    source: Ipv4Address,
    destination: Ipv4Address,
) -> Result<u32, TcpChecksumError> {
    let length = tcp_ipv4_length(bytes)?;
    Ok(internet_checksum::add_bytes(
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

#[cfg(all(feature = "tcp", feature = "ipv4"))]
fn tcp_ipv4_sum_with_zero_checksum(
    bytes: &[u8],
    source: Ipv4Address,
    destination: Ipv4Address,
) -> Result<u32, TcpChecksumError> {
    let length = tcp_ipv4_length(bytes)?;
    let sum = add_ipv4_pseudoheader(
        0,
        source.octets(),
        destination.octets(),
        TCP_PROTOCOL,
        length,
    );
    let sum = internet_checksum::add_bytes(sum, &bytes[..16]);
    let sum = internet_checksum::add_bytes(sum, &[0, 0]);
    Ok(internet_checksum::add_bytes(sum, &bytes[18..]))
}

#[cfg(all(feature = "tcp", feature = "ipv4"))]
fn tcp_ipv4_length(bytes: &[u8]) -> Result<u16, TcpChecksumError> {
    u16::try_from(bytes.len()).map_err(|_| TcpChecksumError::LengthTooLarge {
        maximum: usize::from(u16::MAX),
        actual: bytes.len(),
    })
}

#[cfg(all(feature = "tcp", feature = "ipv6"))]
impl TcpSegment<'_> {
    /// Checks this TCP segment against its IPv6 pseudoheader.
    pub fn checksum_is_valid_ipv6(
        &self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<bool, TcpChecksumError> {
        let length = tcp_ipv6_length(self.as_bytes())?;
        Ok(tcp_ipv6_sum(self.as_bytes(), source, destination, length) == 0xffff)
    }
}

#[cfg(all(feature = "tcp", feature = "ipv6"))]
impl TcpSegmentMut<'_> {
    /// Checks this TCP segment against its IPv6 pseudoheader.
    pub fn checksum_is_valid_ipv6(
        &self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<bool, TcpChecksumError> {
        let length = tcp_ipv6_length(self.as_bytes())?;
        Ok(tcp_ipv6_sum(self.as_bytes(), source, destination, length) == 0xffff)
    }

    /// Recomputes this TCP segment's IPv6 pseudoheader checksum.
    pub fn update_checksum_ipv6(
        &mut self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<(), TcpChecksumError> {
        let length = tcp_ipv6_length(self.as_bytes())?;
        let bytes = self.as_bytes();
        let sum = tcp_ipv6_sum_with_zero_checksum(bytes, source, destination, length);
        let value = internet_checksum::checksum(sum);
        self.as_bytes_mut()[16..18].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }
}

#[cfg(all(feature = "tcp", feature = "ipv6"))]
fn tcp_ipv6_length(bytes: &[u8]) -> Result<u32, TcpChecksumError> {
    let maximum = usize::try_from(u32::MAX).unwrap_or(usize::MAX);
    u32::try_from(bytes.len()).map_err(|_| TcpChecksumError::LengthTooLarge {
        maximum,
        actual: bytes.len(),
    })
}

#[cfg(all(feature = "tcp", feature = "ipv6"))]
fn tcp_ipv6_sum(bytes: &[u8], source: Ipv6Address, destination: Ipv6Address, length: u32) -> u32 {
    internet_checksum::add_bytes(
        add_ipv6_pseudoheader(
            0,
            source.octets(),
            destination.octets(),
            TCP_PROTOCOL,
            length,
        ),
        bytes,
    )
}

#[cfg(all(feature = "tcp", feature = "ipv6"))]
fn tcp_ipv6_sum_with_zero_checksum(
    bytes: &[u8],
    source: Ipv6Address,
    destination: Ipv6Address,
    length: u32,
) -> u32 {
    let sum = add_ipv6_pseudoheader(
        0,
        source.octets(),
        destination.octets(),
        TCP_PROTOCOL,
        length,
    );
    let sum = internet_checksum::add_bytes(sum, &bytes[..16]);
    let sum = internet_checksum::add_bytes(sum, &[0, 0]);
    internet_checksum::add_bytes(sum, &bytes[18..])
}
