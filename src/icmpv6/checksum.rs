//! ICMPv6 checksum integration for IPv6 pseudoheaders.

use core::fmt;

use crate::icmpv6::message::{Icmpv6Message, Icmpv6MessageMut};
use crate::internet_checksum::{self, add_ipv6_pseudoheader};
use crate::ipv6::address::Ipv6Address;

const ICMPV6_NEXT_HEADER: u8 = 58;

/// Failure to represent an ICMPv6 message length in an IPv6 pseudoheader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv6ChecksumError {
    /// The message length cannot be represented by the pseudoheader's length field.
    LengthTooLarge {
        /// Largest representable message length on this platform.
        maximum: usize,
        /// Actual message length.
        actual: usize,
    },
}

impl fmt::Display for Icmpv6ChecksumError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthTooLarge { maximum, actual } => write!(
                formatter,
                "transport message length {actual} exceeds pseudoheader maximum {maximum}"
            ),
        }
    }
}

impl Icmpv6Message<'_> {
    /// Checks this ICMPv6 message against its IPv6 pseudoheader.
    pub fn checksum_is_valid_ipv6(
        &self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<bool, Icmpv6ChecksumError> {
        let length = icmpv6_length(self.as_bytes())?;
        Ok(icmpv6_checksum_sum(self.as_bytes(), source, destination, length) == 0xffff)
    }
}

impl Icmpv6MessageMut<'_> {
    /// Checks this ICMPv6 message against its IPv6 pseudoheader.
    pub fn checksum_is_valid_ipv6(
        &self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<bool, Icmpv6ChecksumError> {
        let length = icmpv6_length(self.as_bytes())?;
        Ok(icmpv6_checksum_sum(self.as_bytes(), source, destination, length) == 0xffff)
    }

    /// Recomputes the ICMPv6 checksum using the supplied IPv6 pseudoheader.
    pub fn update_checksum_ipv6(
        &mut self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<(), Icmpv6ChecksumError> {
        let length = icmpv6_length(self.as_bytes())?;
        let bytes = self.as_bytes_mut();
        bytes[2..4].fill(0);
        let value =
            internet_checksum::checksum(icmpv6_checksum_sum(bytes, source, destination, length));
        bytes[2..4].copy_from_slice(&value.to_be_bytes());
        Ok(())
    }
}

fn icmpv6_length(bytes: &[u8]) -> Result<u32, Icmpv6ChecksumError> {
    let maximum = usize::try_from(u32::MAX).unwrap_or(usize::MAX);
    u32::try_from(bytes.len()).map_err(|_| Icmpv6ChecksumError::LengthTooLarge {
        maximum,
        actual: bytes.len(),
    })
}

fn icmpv6_checksum_sum(
    bytes: &[u8],
    source: Ipv6Address,
    destination: Ipv6Address,
    length: u32,
) -> u32 {
    internet_checksum::add_bytes(
        add_ipv6_pseudoheader(
            0,
            source.octets(),
            destination.octets(),
            ICMPV6_NEXT_HEADER,
            length,
        ),
        bytes,
    )
}
