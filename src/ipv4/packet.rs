//! IPv4 packet views and header-checksum handling (RFC 791).

use super::address::Ipv4Address;
use super::layout::{
    Ipv4AddressRepr, Ipv4PacketLayout, Ipv4PacketLayoutMutationError, Ipv4PacketLayoutViewMut,
};
use super::protocol::Ipv4Protocol;
use crate::{error::ParseError, internet_checksum};
use core::fmt;

pub(super) const HEADER_LENGTH: usize = 20;

/// An IPv4 field encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4PacketMutationError {
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

impl fmt::Display for Ipv4PacketMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "IPv4 field {field} plan length: expected {expected} bytes, got {actual}"
            ),
        }
    }
}
impl core::error::Error for Ipv4PacketMutationError {}

fn mutation_error(error: Ipv4PacketLayoutMutationError) -> Ipv4PacketMutationError {
    match error {
        Ipv4PacketLayoutMutationError::FieldVersionIhl(error)
        | Ipv4PacketLayoutMutationError::FieldDscpEcn(error)
        | Ipv4PacketLayoutMutationError::FieldTotalLength(error)
        | Ipv4PacketLayoutMutationError::FieldIdentification(error)
        | Ipv4PacketLayoutMutationError::FieldFlagsFragmentOffset(error)
        | Ipv4PacketLayoutMutationError::FieldTtl(error)
        | Ipv4PacketLayoutMutationError::FieldProtocol(error)
        | Ipv4PacketLayoutMutationError::FieldHeaderChecksum(error)
        | Ipv4PacketLayoutMutationError::FieldSource(error)
        | Ipv4PacketLayoutMutationError::FieldDestination(error) => match error {},
        Ipv4PacketLayoutMutationError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => Ipv4PacketMutationError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
    }
}

/// A structurally validated immutable RFC 791 packet view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Packet<'a> {
    layout: Ipv4PacketLayout<'a>,
    header_length: usize,
}

impl<'a> Ipv4Packet<'a> {
    /// Validates RFC 791 structural bounds; use `checksum_is_valid` for checksum acceptance.
    #[inline]
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (header_length, total_length) = validate(bytes)?;
        let layout = Ipv4PacketLayout::view(&bytes[..total_length])
            .without_trailing()
            .map_err(|_| ParseError::Truncated {
                minimum: total_length,
                available: bytes.len(),
            })?;
        Ok(Self {
            layout,
            header_length,
        })
    }
    /// Returns the combined DSCP/ECN octet.
    #[inline]
    pub fn dscp_ecn(&self) -> u8 {
        self.layout.dscp_ecn()
    }
    /// Returns the RFC 791 total-length field.
    #[inline]
    pub fn total_length(&self) -> u16 {
        self.layout.total_length()
    }
    /// Returns the datagram identification.
    #[inline]
    pub fn identification(&self) -> u16 {
        self.layout.identification()
    }
    /// Returns the raw flags and fragment offset.
    #[inline]
    pub fn flags_fragment_offset(&self) -> u16 {
        self.layout.flags_fragment_offset()
    }
    /// Returns the time to live.
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.layout.ttl()
    }
    /// Returns the protocol field, including unknown values.
    #[inline]
    pub fn protocol(&self) -> Ipv4Protocol {
        Ipv4Protocol::new(self.layout.protocol())
    }
    /// Returns the encoded header checksum.
    #[inline]
    pub fn header_checksum(&self) -> u16 {
        self.layout.header_checksum()
    }
    /// Returns the source address.
    #[inline]
    pub fn source(&self) -> Ipv4Address {
        self.layout.source().into_address()
    }
    /// Returns the destination address.
    #[inline]
    pub fn destination(&self) -> Ipv4Address {
        self.layout.destination().into_address()
    }
    /// Returns RFC 791 option bytes included by IHL.
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        &self.layout.body()[..self.header_length - HEADER_LENGTH]
    }
    /// Returns declared payload bytes.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.layout.body()[self.header_length - HEADER_LENGTH..]
    }
    /// Returns exactly the declared IPv4 packet bytes.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.layout.as_bytes()
    }
    /// Checks the one's-complement checksum across the complete IHL, including options.
    #[inline]
    pub fn checksum_is_valid(&self) -> bool {
        internet_checksum::sum(&self.as_bytes()[..self.header_length]) == 0xffff
    }
}

/// A structurally validated mutable RFC 791 packet view.
pub struct Ipv4PacketMut<'a> {
    layout: Ipv4PacketLayoutViewMut<'a>,
    header_length: usize,
}

impl fmt::Debug for Ipv4PacketMut<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ipv4PacketMut")
            .field("bytes", &self.as_bytes())
            .field("header_length", &self.header_length)
            .finish()
    }
}

impl PartialEq for Ipv4PacketMut<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.header_length == other.header_length && self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Ipv4PacketMut<'_> {}

impl<'a> Ipv4PacketMut<'a> {
    /// Validates RFC 791 structural bounds and excludes trailing bytes.
    #[inline]
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        let (header_length, total_length) = validate(bytes)?;
        let available = bytes.len();
        Self::from_exact(&mut bytes[..total_length], header_length).map_err(|_| {
            ParseError::Truncated {
                minimum: total_length,
                available,
            }
        })
    }

    pub(super) fn from_exact(
        bytes: &'a mut [u8],
        header_length: usize,
    ) -> Result<Self, Ipv4PacketRepresentationError> {
        let layout = Ipv4PacketLayoutViewMut::parse_exact_mut(bytes)
            .map_err(|_| Ipv4PacketRepresentationError::InvalidLayout)?;
        Ok(Self {
            layout,
            header_length,
        })
    }

    /// Returns the combined DSCP/ECN octet.
    #[inline]
    pub fn dscp_ecn(&self) -> u8 {
        self.layout.dscp_ecn()
    }
    /// Returns the RFC 791 total-length field.
    #[inline]
    pub fn total_length(&self) -> u16 {
        self.layout.total_length()
    }
    /// Returns the datagram identification.
    #[inline]
    pub fn identification(&self) -> u16 {
        self.layout.identification()
    }
    /// Returns the raw flags and fragment offset.
    #[inline]
    pub fn flags_fragment_offset(&self) -> u16 {
        self.layout.flags_fragment_offset()
    }
    /// Returns the time to live.
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.layout.ttl()
    }
    /// Returns the protocol field, including unknown values.
    #[inline]
    pub fn protocol(&self) -> Ipv4Protocol {
        Ipv4Protocol::new(self.layout.protocol())
    }
    /// Returns the encoded header checksum.
    #[inline]
    pub fn header_checksum(&self) -> u16 {
        self.layout.header_checksum()
    }
    /// Returns the source address.
    #[inline]
    pub fn source(&self) -> Ipv4Address {
        self.layout.source().into_address()
    }
    /// Returns the destination address.
    #[inline]
    pub fn destination(&self) -> Ipv4Address {
        self.layout.destination().into_address()
    }
    /// Returns RFC 791 option bytes included by IHL.
    #[inline]
    pub fn options(&self) -> &[u8] {
        &self.layout.body()[..self.header_length - HEADER_LENGTH]
    }
    /// Returns declared payload bytes.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.layout.body()[self.header_length - HEADER_LENGTH..]
    }
    /// Returns mutable options without updating the checksum.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        let n = self.header_length - HEADER_LENGTH;
        &mut self.layout.body_mut()[..n]
    }
    /// Returns mutable payload bytes.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let n = self.header_length - HEADER_LENGTH;
        &mut self.layout.body_mut()[n..]
    }
    /// Returns exactly the represented IPv4 packet bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.layout.as_bytes()
    }

    /// Replaces DSCP/ECN without updating the checksum.
    #[inline]
    pub fn set_dscp_ecn(&mut self, value: u8) -> Result<(), Ipv4PacketMutationError> {
        self.layout.set_dscp_ecn(value).map_err(mutation_error)
    }
    /// Replaces identification without updating the checksum.
    #[inline]
    pub fn set_identification(&mut self, value: u16) -> Result<(), Ipv4PacketMutationError> {
        self.layout
            .set_identification(value)
            .map_err(mutation_error)
    }
    /// Replaces raw flags and fragment offset without updating the checksum.
    #[inline]
    pub fn set_flags_fragment_offset(&mut self, value: u16) -> Result<(), Ipv4PacketMutationError> {
        self.layout
            .set_flags_fragment_offset(value)
            .map_err(mutation_error)
    }
    /// Replaces TTL without updating the checksum.
    #[inline]
    pub fn set_ttl(&mut self, value: u8) -> Result<(), Ipv4PacketMutationError> {
        self.layout.set_ttl(value).map_err(mutation_error)
    }
    /// Replaces the protocol without updating the checksum.
    #[inline]
    pub fn set_protocol(&mut self, value: Ipv4Protocol) -> Result<(), Ipv4PacketMutationError> {
        self.layout
            .set_protocol(value.raw())
            .map_err(mutation_error)
    }
    /// Replaces the encoded header checksum directly.
    #[inline]
    pub fn set_header_checksum(&mut self, value: u16) -> Result<(), Ipv4PacketMutationError> {
        self.layout
            .set_header_checksum(value)
            .map_err(mutation_error)
    }
    /// Replaces the source without updating the checksum.
    #[inline]
    pub fn set_source(&mut self, value: Ipv4Address) -> Result<(), Ipv4PacketMutationError> {
        self.layout
            .set_source(Ipv4AddressRepr::from_address(value))
            .map_err(mutation_error)
    }
    /// Replaces the destination without updating the checksum.
    #[inline]
    pub fn set_destination(&mut self, value: Ipv4Address) -> Result<(), Ipv4PacketMutationError> {
        self.layout
            .set_destination(Ipv4AddressRepr::from_address(value))
            .map_err(mutation_error)
    }
    /// Recomputes and writes the checksum across the full IHL, including options.
    #[inline]
    pub fn update_header_checksum(&mut self) -> Result<(), Ipv4PacketMutationError> {
        let header = &self.as_bytes()[..self.header_length];
        let sum = internet_checksum::add_bytes(0, &header[..10]);
        let sum = internet_checksum::add_bytes(sum, &[0, 0]);
        let checksum = !internet_checksum::fold(internet_checksum::add_bytes(sum, &header[12..]));
        self.set_header_checksum(checksum)
    }
    /// Checks the current header checksum across the complete IHL.
    #[inline]
    pub fn checksum_is_valid(&self) -> bool {
        internet_checksum::sum(&self.as_bytes()[..self.header_length]) == 0xffff
    }
}

/// Internal IPv4 representation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Ipv4PacketRepresentationError {
    /// A generated representation unexpectedly rejected a prevalidated layout.
    InvalidLayout,
}
impl fmt::Display for Ipv4PacketRepresentationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("generated IPv4 representation rejected a prevalidated layout")
    }
}
impl core::error::Error for Ipv4PacketRepresentationError {}

#[inline]
fn validate(bytes: &[u8]) -> Result<(usize, usize), ParseError> {
    if bytes.len() < HEADER_LENGTH {
        return Err(ParseError::Truncated {
            minimum: HEADER_LENGTH,
            available: bytes.len(),
        });
    }
    let preliminary = Ipv4PacketLayout::view(bytes)
        .without_trailing()
        .map_err(|_| ParseError::Truncated {
            minimum: HEADER_LENGTH,
            available: bytes.len(),
        })?;
    let version = preliminary.version();
    if version != 4 {
        return Err(ParseError::InvalidVersion {
            expected: 4,
            actual: version,
        });
    }
    let header_length = usize::from(preliminary.ihl()) * 4;
    if header_length < HEADER_LENGTH {
        return Err(ParseError::InvalidHeaderLength {
            minimum: HEADER_LENGTH,
            actual: header_length,
        });
    }
    if bytes.len() < header_length {
        return Err(ParseError::Truncated {
            minimum: header_length,
            available: bytes.len(),
        });
    }
    let total_length = usize::from(preliminary.total_length());
    if total_length < header_length {
        return Err(ParseError::InvalidTotalLength {
            header_length,
            total_length,
        });
    }
    if bytes.len() < total_length {
        return Err(ParseError::Truncated {
            minimum: total_length,
            available: bytes.len(),
        });
    }
    Ok((header_length, total_length))
}
