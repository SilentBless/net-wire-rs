//! TCP checksum integration for IP pseudoheaders.

use super::segment::{TcpSegment, TcpSegmentMut, TcpSegmentMutationError};
use crate::internet_checksum;
#[cfg(all(feature = "tcp", feature = "ipv4"))]
use crate::internet_checksum::add_ipv4_pseudoheader;
#[cfg(all(feature = "tcp", feature = "ipv6"))]
use crate::internet_checksum::add_ipv6_pseudoheader;
#[cfg(all(feature = "tcp", feature = "ipv4"))]
use crate::ipv4::address::Ipv4Address;
#[cfg(all(feature = "tcp", feature = "ipv6"))]
use crate::ipv6::address::Ipv6Address;
use core::fmt;

const TCP_PROTOCOL: u8 = 6;

/// Failure to represent or update a TCP checksum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpChecksumError {
    /// The message length cannot be represented by the pseudoheader's length field.
    LengthTooLarge {
        /// Largest representable message length on this platform.
        maximum: usize,
        /// Actual message length.
        actual: usize,
    },
    /// A field value could not be encoded at its required wire width.
    InvalidFieldEncoding {
        /// The field whose plan was invalid.
        field: &'static str,
        /// The required fixed width.
        expected: usize,
        /// The encoded width that was produced.
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
            Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "TCP field {field} plan length: expected {expected} bytes, got {actual}"
            ),
        }
    }
}
impl core::error::Error for TcpChecksumError {}
impl From<TcpSegmentMutationError> for TcpChecksumError {
    fn from(error: TcpSegmentMutationError) -> Self {
        match error {
            TcpSegmentMutationError::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            },
        }
    }
}

fn segment_length(header_length: usize, payload_length: usize) -> usize {
    header_length + payload_length
}

struct TcpChecksumParts<'a> {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset: u8,
    reserved: u8,
    flags: u8,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
    options: &'a [u8],
    payload: &'a [u8],
}

fn checksum_sum(parts: TcpChecksumParts<'_>, initial: u32) -> u32 {
    let sum = internet_checksum::add_bytes(initial, &parts.source_port.to_be_bytes());
    let sum = internet_checksum::add_bytes(sum, &parts.destination_port.to_be_bytes());
    let sum = internet_checksum::add_bytes(sum, &parts.sequence_number.to_be_bytes());
    let sum = internet_checksum::add_bytes(sum, &parts.acknowledgment_number.to_be_bytes());
    let sum =
        internet_checksum::add_bytes(sum, &[parts.data_offset << 4 | parts.reserved, parts.flags]);
    let sum = internet_checksum::add_bytes(sum, &parts.window_size.to_be_bytes());
    let sum = internet_checksum::add_bytes(sum, &parts.checksum.to_be_bytes());
    let sum = internet_checksum::add_bytes(sum, &parts.urgent_pointer.to_be_bytes());
    let sum = internet_checksum::add_bytes(sum, parts.options);
    internet_checksum::add_bytes(sum, parts.payload)
}

fn segment_checksum_sum(segment: &TcpSegment<'_>, checksum: u16, initial: u32) -> u32 {
    checksum_sum(
        TcpChecksumParts {
            source_port: segment.source_port(),
            destination_port: segment.destination_port(),
            sequence_number: segment.sequence_number(),
            acknowledgment_number: segment.acknowledgment_number(),
            data_offset: segment.data_offset(),
            reserved: segment.reserved(),
            flags: segment.flags().raw(),
            window_size: segment.window_size(),
            checksum,
            urgent_pointer: segment.urgent_pointer(),
            options: segment.options(),
            payload: segment.payload(),
        },
        initial,
    )
}

fn segment_mut_checksum_sum(segment: &TcpSegmentMut<'_>, checksum: u16, initial: u32) -> u32 {
    checksum_sum(
        TcpChecksumParts {
            source_port: segment.source_port(),
            destination_port: segment.destination_port(),
            sequence_number: segment.sequence_number(),
            acknowledgment_number: segment.acknowledgment_number(),
            data_offset: segment.data_offset(),
            reserved: segment.reserved(),
            flags: segment.flags().raw(),
            window_size: segment.window_size(),
            checksum,
            urgent_pointer: segment.urgent_pointer(),
            options: segment.options(),
            payload: segment.payload(),
        },
        initial,
    )
}

#[cfg(all(feature = "tcp", feature = "ipv4"))]
impl TcpSegment<'_> {
    /// Checks this TCP segment against its IPv4 pseudoheader.
    pub fn checksum_is_valid_ipv4(
        &self,
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> Result<bool, TcpChecksumError> {
        let length = tcp_ipv4_length(segment_length(self.header_length(), self.payload().len()))?;
        let initial = add_ipv4_pseudoheader(
            0,
            source.octets(),
            destination.octets(),
            TCP_PROTOCOL,
            length,
        );
        Ok(internet_checksum::fold(segment_checksum_sum(self, self.checksum(), initial)) == 0xffff)
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
        let length = tcp_ipv4_length(segment_length(self.header_length(), self.payload().len()))?;
        let initial = add_ipv4_pseudoheader(
            0,
            source.octets(),
            destination.octets(),
            TCP_PROTOCOL,
            length,
        );
        Ok(
            internet_checksum::fold(segment_mut_checksum_sum(self, self.checksum(), initial))
                == 0xffff,
        )
    }
    /// Recomputes this TCP segment's IPv4 pseudoheader checksum.
    pub fn update_checksum_ipv4(
        &mut self,
        source: Ipv4Address,
        destination: Ipv4Address,
    ) -> Result<(), TcpChecksumError> {
        let length = tcp_ipv4_length(segment_length(self.header_length(), self.payload().len()))?;
        let initial = add_ipv4_pseudoheader(
            0,
            source.octets(),
            destination.octets(),
            TCP_PROTOCOL,
            length,
        );
        let checksum = internet_checksum::checksum(segment_mut_checksum_sum(self, 0, initial));
        self.set_checksum(checksum).map_err(Into::into)
    }
}
#[cfg(all(feature = "tcp", feature = "ipv4"))]
fn tcp_ipv4_length(length: usize) -> Result<u16, TcpChecksumError> {
    u16::try_from(length).map_err(|_| TcpChecksumError::LengthTooLarge {
        maximum: usize::from(u16::MAX),
        actual: length,
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
        let length = tcp_ipv6_length(segment_length(self.header_length(), self.payload().len()))?;
        let initial = add_ipv6_pseudoheader(
            0,
            source.octets(),
            destination.octets(),
            TCP_PROTOCOL,
            length,
        );
        Ok(internet_checksum::fold(segment_checksum_sum(self, self.checksum(), initial)) == 0xffff)
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
        let length = tcp_ipv6_length(segment_length(self.header_length(), self.payload().len()))?;
        let initial = add_ipv6_pseudoheader(
            0,
            source.octets(),
            destination.octets(),
            TCP_PROTOCOL,
            length,
        );
        Ok(
            internet_checksum::fold(segment_mut_checksum_sum(self, self.checksum(), initial))
                == 0xffff,
        )
    }
    /// Recomputes this TCP segment's IPv6 pseudoheader checksum.
    pub fn update_checksum_ipv6(
        &mut self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<(), TcpChecksumError> {
        let length = tcp_ipv6_length(segment_length(self.header_length(), self.payload().len()))?;
        let initial = add_ipv6_pseudoheader(
            0,
            source.octets(),
            destination.octets(),
            TCP_PROTOCOL,
            length,
        );
        let checksum = internet_checksum::checksum(segment_mut_checksum_sum(self, 0, initial));
        self.set_checksum(checksum).map_err(Into::into)
    }
}
#[cfg(all(feature = "tcp", feature = "ipv6"))]
fn tcp_ipv6_length(length: usize) -> Result<u32, TcpChecksumError> {
    let maximum = usize::try_from(u32::MAX).unwrap_or(usize::MAX);
    u32::try_from(length).map_err(|_| TcpChecksumError::LengthTooLarge {
        maximum,
        actual: length,
    })
}
