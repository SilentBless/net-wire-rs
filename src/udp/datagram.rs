//! Checked borrowed UDP datagram views.

use super::layout::{
    HEADER_LENGTH, UdpDatagramLayout, UdpDatagramLayoutMutationError, UdpDatagramLayoutViewMut,
};
use crate::error::ParseError;
use core::fmt;

/// A UDP field mutation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpDatagramMutationError {
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

impl fmt::Display for UdpDatagramMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "UDP field {field} plan length: expected {expected} bytes, got {actual}"
            ),
        }
    }
}
impl core::error::Error for UdpDatagramMutationError {}

fn mutation_error(error: UdpDatagramLayoutMutationError) -> UdpDatagramMutationError {
    match error {
        UdpDatagramLayoutMutationError::FieldSourcePort(error)
        | UdpDatagramLayoutMutationError::FieldDestinationPort(error)
        | UdpDatagramLayoutMutationError::FieldLength(error)
        | UdpDatagramLayoutMutationError::FieldChecksum(error) => match error {},
        UdpDatagramLayoutMutationError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => UdpDatagramMutationError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
    }
}

/// A structurally validated UDP datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpDatagram<'a> {
    layout: UdpDatagramLayout<'a>,
}

impl<'a> UdpDatagram<'a> {
    /// Parses a UDP datagram without checking its checksum.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let length = validated_length(bytes)?;
        let layout = UdpDatagramLayout::view(&bytes[..length])
            .without_trailing()
            .map_err(|_| ParseError::Truncated {
                minimum: length,
                available: bytes.len(),
            })?;
        Ok(Self { layout })
    }

    /// Returns the source port.
    #[inline]
    pub fn source_port(&self) -> u16 {
        self.layout.source_port()
    }
    /// Returns the destination port.
    #[inline]
    pub fn destination_port(&self) -> u16 {
        self.layout.destination_port()
    }
    /// Returns the encoded datagram length.
    #[inline]
    pub fn length(&self) -> u16 {
        self.layout.length()
    }
    /// Returns the encoded checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.layout.checksum()
    }
    /// Returns payload bytes.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        self.layout.payload()
    }
    /// Returns all represented datagram bytes.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.layout.as_bytes()
    }
}

/// A mutable structurally validated UDP datagram.
pub struct UdpDatagramMut<'a> {
    layout: UdpDatagramLayoutViewMut<'a>,
}

impl fmt::Debug for UdpDatagramMut<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpDatagramMut")
            .field("bytes", &self.as_bytes())
            .finish()
    }
}

impl PartialEq for UdpDatagramMut<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for UdpDatagramMut<'_> {}

impl<'a> UdpDatagramMut<'a> {
    /// Parses a UDP datagram without checking its checksum.
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        let length = validated_length(bytes)?;
        let available = bytes.len();
        Self::from_exact(&mut bytes[..length]).map_err(|_| ParseError::Truncated {
            minimum: length,
            available,
        })
    }

    pub(super) fn from_exact(bytes: &'a mut [u8]) -> Result<Self, UdpDatagramRepresentationError> {
        let layout = UdpDatagramLayoutViewMut::parse_exact_mut(bytes)
            .map_err(|_| UdpDatagramRepresentationError::InvalidLayout)?;
        Ok(Self { layout })
    }

    pub(super) const fn from_layout(layout: UdpDatagramLayoutViewMut<'a>) -> Self {
        Self { layout }
    }

    /// Returns the source port.
    #[inline]
    pub fn source_port(&self) -> u16 {
        self.layout.source_port()
    }
    /// Returns the destination port.
    #[inline]
    pub fn destination_port(&self) -> u16 {
        self.layout.destination_port()
    }
    /// Returns the encoded datagram length.
    #[inline]
    pub fn length(&self) -> u16 {
        self.layout.length()
    }
    /// Returns the encoded checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.layout.checksum()
    }
    /// Returns payload bytes.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.layout.payload()
    }
    /// Returns mutable payload bytes without updating the checksum.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.layout.payload_mut()
    }
    /// Returns all represented datagram bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.layout.as_bytes()
    }
    /// Replaces the source port without updating the checksum.
    #[inline]
    pub fn set_source_port(&mut self, value: u16) -> Result<(), UdpDatagramMutationError> {
        self.layout.set_source_port(value).map_err(mutation_error)
    }
    /// Replaces the destination port without updating the checksum.
    #[inline]
    pub fn set_destination_port(&mut self, value: u16) -> Result<(), UdpDatagramMutationError> {
        self.layout
            .set_destination_port(value)
            .map_err(mutation_error)
    }
    /// Replaces the encoded checksum directly.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) -> Result<(), UdpDatagramMutationError> {
        self.layout.set_checksum(value).map_err(mutation_error)
    }
}

/// Internal UDP representation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UdpDatagramRepresentationError {
    /// A generated representation unexpectedly rejected a prevalidated layout.
    InvalidLayout,
}

impl fmt::Display for UdpDatagramRepresentationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("generated UDP representation rejected a prevalidated layout")
    }
}
impl core::error::Error for UdpDatagramRepresentationError {}

fn validated_length(bytes: &[u8]) -> Result<usize, ParseError> {
    if bytes.len() < HEADER_LENGTH {
        return Err(ParseError::Truncated {
            minimum: HEADER_LENGTH,
            available: bytes.len(),
        });
    }
    let preliminary = UdpDatagramLayout::view(bytes)
        .without_trailing()
        .map_err(|_| ParseError::Truncated {
            minimum: HEADER_LENGTH,
            available: bytes.len(),
        })?;
    let length = usize::from(preliminary.length());
    if length < HEADER_LENGTH {
        return Err(ParseError::InvalidTotalLength {
            header_length: HEADER_LENGTH,
            total_length: length,
        });
    }
    if bytes.len() < length {
        return Err(ParseError::Truncated {
            minimum: length,
            available: bytes.len(),
        });
    }
    Ok(length)
}
