//! ICMPv6 checked borrowed message views.

use super::Icmpv6Type;
use crate::ParseError;

const HEADER_LENGTH: usize = 4;

/// A structurally validated ICMPv6 message.
///
/// Parsing verifies only the common header. It preserves unknown type and code values and does
/// not reject a message with an invalid checksum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv6Message<'a> {
    bytes: &'a [u8],
}

impl<'a> Icmpv6Message<'a> {
    /// Parses a complete ICMPv6 message without checking its checksum.
    #[inline]
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() < HEADER_LENGTH {
            return Err(ParseError::Truncated {
                minimum: HEADER_LENGTH,
                available: bytes.len(),
            });
        }
        Ok(Self { bytes })
    }

    /// Returns the message type.
    #[inline]
    pub fn message_type(&self) -> Icmpv6Type {
        Icmpv6Type::new(self.bytes[0])
    }

    /// Returns the message code.
    #[inline]
    pub fn code(&self) -> u8 {
        self.bytes[1]
    }

    /// Returns the encoded checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    /// Returns bytes after the common header.
    #[inline]
    pub fn body(&self) -> &'a [u8] {
        &self.bytes[HEADER_LENGTH..]
    }

    /// Returns all represented message bytes.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// A mutable structurally validated ICMPv6 message.
#[derive(Debug, Eq, PartialEq)]
pub struct Icmpv6MessageMut<'a> {
    bytes: &'a mut [u8],
}

impl<'a> Icmpv6MessageMut<'a> {
    /// Parses a complete ICMPv6 message without checking its checksum.
    #[inline]
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        if bytes.len() < HEADER_LENGTH {
            return Err(ParseError::Truncated {
                minimum: HEADER_LENGTH,
                available: bytes.len(),
            });
        }
        Ok(Self { bytes })
    }

    pub(crate) fn from_validated(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the message type.
    #[inline]
    pub fn message_type(&self) -> Icmpv6Type {
        Icmpv6Type::new(self.bytes[0])
    }

    /// Returns the message code.
    #[inline]
    pub fn code(&self) -> u8 {
        self.bytes[1]
    }

    /// Returns the encoded checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    /// Returns bytes after the common header.
    #[inline]
    pub fn body(&self) -> &[u8] {
        &self.bytes[HEADER_LENGTH..]
    }

    /// Returns mutable body bytes without updating the checksum.
    #[inline]
    pub fn body_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[HEADER_LENGTH..]
    }

    /// Returns all represented message bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Returns all represented message bytes mutably without updating the checksum.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }

    /// Replaces the message type without updating the checksum.
    #[inline]
    pub fn set_message_type(&mut self, value: Icmpv6Type) {
        self.bytes[0] = value.raw();
    }

    /// Replaces the message code without updating the checksum.
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        self.bytes[1] = value;
    }

    /// Replaces the encoded checksum directly.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        self.bytes[2..4].copy_from_slice(&value.to_be_bytes());
    }
}
