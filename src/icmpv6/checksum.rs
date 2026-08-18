//! ICMPv6 checksum integration for IPv6 pseudoheaders.

use core::fmt;

use crate::icmpv6::message::{Icmpv6Message, Icmpv6MessageMut, Icmpv6MessageMutationError};
use crate::icmpv6::types::Icmpv6Type;
use crate::internet_checksum::{self, add_ipv6_pseudoheader};
use crate::ipv6::address::Ipv6Address;

const ICMPV6_NEXT_HEADER: u8 = 58;

/// Failure to represent or update an ICMPv6 checksum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv6ChecksumError {
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

impl fmt::Display for Icmpv6ChecksumError {
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
                "ICMPv6 field {field} encoding: expected {expected} bytes, got {actual}"
            ),
        }
    }
}
impl core::error::Error for Icmpv6ChecksumError {}

fn mutation_error(error: Icmpv6MessageMutationError) -> Icmpv6ChecksumError {
    match error {
        Icmpv6MessageMutationError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        } => Icmpv6ChecksumError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
    }
}

impl Icmpv6Message<'_> {
    /// Checks this ICMPv6 message against its IPv6 pseudoheader.
    pub fn checksum_is_valid_ipv6(
        &self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<bool, Icmpv6ChecksumError> {
        let length = icmpv6_length(self.as_bytes().len())?;
        Ok(internet_checksum::fold(icmpv6_checksum_sum(
            source,
            destination,
            self.message_type(),
            self.code(),
            self.checksum(),
            self.body(),
            length,
        )) == 0xffff)
    }
}

impl Icmpv6MessageMut<'_> {
    /// Checks this ICMPv6 message against its IPv6 pseudoheader.
    pub fn checksum_is_valid_ipv6(
        &self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<bool, Icmpv6ChecksumError> {
        let length = icmpv6_length(self.as_bytes().len())?;
        Ok(internet_checksum::fold(icmpv6_checksum_sum(
            source,
            destination,
            self.message_type(),
            self.code(),
            self.checksum(),
            self.body(),
            length,
        )) == 0xffff)
    }

    /// Recomputes the ICMPv6 checksum using the supplied IPv6 pseudoheader.
    pub fn update_checksum_ipv6(
        &mut self,
        source: Ipv6Address,
        destination: Ipv6Address,
    ) -> Result<(), Icmpv6ChecksumError> {
        let length = icmpv6_length(self.as_bytes().len())?;
        let checksum = internet_checksum::checksum(icmpv6_checksum_sum(
            source,
            destination,
            self.message_type(),
            self.code(),
            0,
            self.body(),
            length,
        ));
        self.set_checksum(checksum).map_err(mutation_error)
    }
}

fn icmpv6_length(actual: usize) -> Result<u32, Icmpv6ChecksumError> {
    let maximum = usize::try_from(u32::MAX).unwrap_or(usize::MAX);
    u32::try_from(actual).map_err(|_| Icmpv6ChecksumError::LengthTooLarge { maximum, actual })
}

fn icmpv6_checksum_sum(
    source: Ipv6Address,
    destination: Ipv6Address,
    message_type: Icmpv6Type,
    code: u8,
    checksum: u16,
    body: &[u8],
    length: u32,
) -> u32 {
    let sum = add_ipv6_pseudoheader(
        0,
        source.octets(),
        destination.octets(),
        ICMPV6_NEXT_HEADER,
        length,
    );
    let sum = internet_checksum::add_bytes(sum, &[message_type.raw(), code]);
    let sum = internet_checksum::add_bytes(sum, &checksum.to_be_bytes());
    internet_checksum::add_bytes(sum, body)
}
