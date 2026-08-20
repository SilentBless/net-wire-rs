//! ICMPv6 checked borrowed message views.

use core::fmt;

use super::layout::{
    HEADER_LENGTH, Icmpv6MessageLayout, Icmpv6MessageLayoutMutationError,
    Icmpv6MessageLayoutViewMut,
};
use super::types::Icmpv6Type;
use crate::error::ParseError;

/// An ICMPv6 field mutation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv6MessageMutationError {
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

impl fmt::Display for Icmpv6MessageMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "ICMPv6 field {field} plan length: expected {expected} bytes, got {actual}"
            ),
        }
    }
}
impl core::error::Error for Icmpv6MessageMutationError {}

fn mutation_error(error: Icmpv6MessageLayoutMutationError) -> Icmpv6MessageMutationError {
    match error {
        Icmpv6MessageLayoutMutationError::FieldMessageType(error)
        | Icmpv6MessageLayoutMutationError::FieldCode(error)
        | Icmpv6MessageLayoutMutationError::FieldChecksum(error) => match error {},
        Icmpv6MessageLayoutMutationError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => Icmpv6MessageMutationError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
    }
}

/// A structurally validated ICMPv6 message.
///
/// Parsing verifies only the common header. It preserves unknown type and code values and does
/// not reject a message with an invalid checksum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv6Message<'a> {
    layout: Icmpv6MessageLayout<'a>,
}

impl<'a> Icmpv6Message<'a> {
    /// Parses a complete ICMPv6 message without checking its checksum.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() < HEADER_LENGTH {
            return Err(ParseError::Truncated {
                minimum: HEADER_LENGTH,
                available: bytes.len(),
            });
        }
        let layout = Icmpv6MessageLayout::view(bytes)
            .without_trailing()
            .map_err(|_| ParseError::Truncated {
                minimum: HEADER_LENGTH,
                available: bytes.len(),
            })?;
        Ok(Self { layout })
    }

    /// Returns the message type.
    #[inline]
    pub fn message_type(&self) -> Icmpv6Type {
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

    /// Returns bytes after the common header.
    #[inline]
    pub fn body(&self) -> &'a [u8] {
        self.layout.body()
    }

    /// Returns all represented message bytes.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.layout.as_bytes()
    }
}

/// A mutable structurally validated ICMPv6 message.
pub struct Icmpv6MessageMut<'a> {
    layout: Icmpv6MessageLayoutViewMut<'a>,
}

impl fmt::Debug for Icmpv6MessageMut<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Icmpv6MessageMut")
            .field("bytes", &self.as_bytes())
            .finish()
    }
}

impl PartialEq for Icmpv6MessageMut<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Icmpv6MessageMut<'_> {}

impl<'a> Icmpv6MessageMut<'a> {
    /// Parses a complete ICMPv6 message without checking its checksum.
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        if bytes.len() < HEADER_LENGTH {
            return Err(ParseError::Truncated {
                minimum: HEADER_LENGTH,
                available: bytes.len(),
            });
        }
        let available = bytes.len();
        let layout = Icmpv6MessageLayoutViewMut::parse_exact_mut(bytes).map_err(|_| {
            ParseError::Truncated {
                minimum: HEADER_LENGTH,
                available,
            }
        })?;
        Ok(Self { layout })
    }

    pub(super) const fn from_layout(layout: Icmpv6MessageLayoutViewMut<'a>) -> Self {
        Self { layout }
    }

    /// Returns the message type.
    #[inline]
    pub fn message_type(&self) -> Icmpv6Type {
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

    /// Returns bytes after the common header.
    #[inline]
    pub fn body(&self) -> &[u8] {
        self.layout.body()
    }

    /// Returns mutable body bytes without updating the checksum.
    #[inline]
    pub fn body_mut(&mut self) -> &mut [u8] {
        self.layout.body_mut()
    }

    /// Returns all represented message bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.layout.as_bytes()
    }

    /// Replaces the message type without updating the checksum.
    #[inline]
    pub fn set_message_type(
        &mut self,
        value: Icmpv6Type,
    ) -> Result<(), Icmpv6MessageMutationError> {
        self.layout.set_message_type(value).map_err(mutation_error)
    }

    /// Replaces the message code without updating the checksum.
    #[inline]
    pub fn set_code(&mut self, value: u8) -> Result<(), Icmpv6MessageMutationError> {
        self.layout.set_code(value).map_err(mutation_error)
    }

    /// Replaces the encoded checksum directly.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) -> Result<(), Icmpv6MessageMutationError> {
        self.layout.set_checksum(value).map_err(mutation_error)
    }
}
