//! ICMPv4 checked borrowed message views.

use super::layout::{
    HEADER_LENGTH, Icmpv4MessageLayout, Icmpv4MessageLayoutMutationError,
    Icmpv4MessageLayoutViewMut,
};
use super::types::Icmpv4Type;
use crate::{error::ParseError, internet_checksum};
use core::fmt;

/// An ICMPv4 field mutation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv4MessageMutationError {
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

impl fmt::Display for Icmpv4MessageMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "ICMPv4 field {field} plan length: expected {expected} bytes, got {actual}"
            ),
        }
    }
}
impl core::error::Error for Icmpv4MessageMutationError {}

fn mutation_error(error: Icmpv4MessageLayoutMutationError) -> Icmpv4MessageMutationError {
    match error {
        Icmpv4MessageLayoutMutationError::FieldMessageType(error)
        | Icmpv4MessageLayoutMutationError::FieldCode(error)
        | Icmpv4MessageLayoutMutationError::FieldChecksum(error) => match error {},
        Icmpv4MessageLayoutMutationError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => Icmpv4MessageMutationError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
    }
}

#[inline]
pub(super) fn checksum_sum(message_type: Icmpv4Type, code: u8, checksum: u16, body: &[u8]) -> u32 {
    let sum = internet_checksum::add_bytes(0, &[message_type.raw(), code]);
    let sum = internet_checksum::add_bytes(sum, &checksum.to_be_bytes());
    internet_checksum::add_bytes(sum, body)
}

/// A structurally validated ICMPv4 message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv4Message<'a> {
    layout: Icmpv4MessageLayout<'a>,
}

impl<'a> Icmpv4Message<'a> {
    /// Parses a complete ICMPv4 message, without accepting or rejecting its checksum.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() < HEADER_LENGTH {
            return Err(ParseError::Truncated {
                minimum: HEADER_LENGTH,
                available: bytes.len(),
            });
        }
        let layout = Icmpv4MessageLayout::view(bytes)
            .without_trailing()
            .map_err(|_| ParseError::Truncated {
                minimum: HEADER_LENGTH,
                available: bytes.len(),
            })?;
        Ok(Self { layout })
    }
    /// Returns the message type.
    #[inline]
    pub fn message_type(&self) -> Icmpv4Type {
        self.layout.message_type()
    }
    /// Returns the message code.
    #[inline]
    pub fn code(&self) -> u8 {
        self.layout.code()
    }
    /// Returns the encoded checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.layout.checksum()
    }
    /// Returns body bytes after the common header.
    #[inline]
    pub fn body(&self) -> &'a [u8] {
        self.layout.body()
    }
    /// Returns the represented message bytes.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.layout.as_bytes()
    }
    /// Tests the complete message checksum.
    #[inline]
    pub fn checksum_is_valid(&self) -> bool {
        internet_checksum::fold(checksum_sum(
            self.message_type(),
            self.code(),
            self.checksum(),
            self.body(),
        )) == 0xffff
    }
}

/// A mutable structurally validated ICMPv4 message.
pub struct Icmpv4MessageMut<'a> {
    layout: Icmpv4MessageLayoutViewMut<'a>,
}

impl fmt::Debug for Icmpv4MessageMut<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Icmpv4MessageMut")
            .field("bytes", &self.as_bytes())
            .finish()
    }
}

impl PartialEq for Icmpv4MessageMut<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Icmpv4MessageMut<'_> {}

impl<'a> Icmpv4MessageMut<'a> {
    /// Parses a complete ICMPv4 message, without accepting or rejecting its checksum.
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        if bytes.len() < HEADER_LENGTH {
            return Err(ParseError::Truncated {
                minimum: HEADER_LENGTH,
                available: bytes.len(),
            });
        }
        let available = bytes.len();
        let layout = Icmpv4MessageLayoutViewMut::parse_exact_mut(bytes).map_err(|_| {
            ParseError::Truncated {
                minimum: HEADER_LENGTH,
                available,
            }
        })?;
        Ok(Self { layout })
    }

    pub(super) const fn from_layout(layout: Icmpv4MessageLayoutViewMut<'a>) -> Self {
        Self { layout }
    }

    /// Returns the message type.
    #[inline]
    pub fn message_type(&self) -> Icmpv4Type {
        self.layout.message_type()
    }
    /// Returns the message code.
    #[inline]
    pub fn code(&self) -> u8 {
        self.layout.code()
    }
    /// Returns the encoded checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.layout.checksum()
    }
    /// Returns body bytes.
    #[inline]
    pub fn body(&self) -> &[u8] {
        self.layout.body()
    }
    /// Returns mutable body bytes without updating the checksum.
    #[inline]
    pub fn body_mut(&mut self) -> &mut [u8] {
        self.layout.body_mut()
    }
    /// Returns represented bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.layout.as_bytes()
    }
    /// Replaces type without updating checksum.
    #[inline]
    pub fn set_message_type(
        &mut self,
        value: Icmpv4Type,
    ) -> Result<(), Icmpv4MessageMutationError> {
        self.layout.set_message_type(value).map_err(mutation_error)
    }
    /// Replaces code without updating checksum.
    #[inline]
    pub fn set_code(&mut self, value: u8) -> Result<(), Icmpv4MessageMutationError> {
        self.layout.set_code(value).map_err(mutation_error)
    }
    /// Replaces checksum directly.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) -> Result<(), Icmpv4MessageMutationError> {
        self.layout.set_checksum(value).map_err(mutation_error)
    }
    /// Recomputes the complete ICMPv4 checksum.
    #[inline]
    pub fn update_checksum(&mut self) -> Result<(), Icmpv4MessageMutationError> {
        let checksum = internet_checksum::checksum(checksum_sum(
            self.message_type(),
            self.code(),
            0,
            self.body(),
        ));
        self.set_checksum(checksum)
    }
    /// Tests the complete message checksum.
    #[inline]
    pub fn checksum_is_valid(&self) -> bool {
        internet_checksum::fold(checksum_sum(
            self.message_type(),
            self.code(),
            self.checksum(),
            self.body(),
        )) == 0xffff
    }
}
