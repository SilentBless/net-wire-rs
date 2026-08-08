//! ICMPv4 checked borrowed message views.

use super::types::Icmpv4Type;
use crate::{error::ParseError, internet_checksum};

pub(super) const HEADER_LENGTH: usize = 4;

/// A structurally validated ICMPv4 message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv4Message<'a> {
    bytes: &'a [u8],
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
        Ok(Self { bytes })
    }
    /// Returns the message type.
    pub fn message_type(&self) -> Icmpv4Type {
        Icmpv4Type::new(self.bytes[0])
    }
    /// Returns the message code.
    pub fn code(&self) -> u8 {
        self.bytes[1]
    }
    /// Returns the encoded checksum.
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }
    /// Returns body bytes after the common header.
    pub fn body(&self) -> &'a [u8] {
        &self.bytes[HEADER_LENGTH..]
    }
    /// Returns the represented message bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Tests the complete message checksum.
    pub fn checksum_is_valid(&self) -> bool {
        internet_checksum::sum(self.bytes) == 0xffff
    }
}

/// A mutable structurally validated ICMPv4 message.
#[derive(Debug, Eq, PartialEq)]
pub struct Icmpv4MessageMut<'a> {
    bytes: &'a mut [u8],
}
impl<'a> Icmpv4MessageMut<'a> {
    /// Parses a complete ICMPv4 message, without accepting or rejecting its checksum.
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
    pub fn message_type(&self) -> Icmpv4Type {
        Icmpv4Type::new(self.bytes[0])
    }
    /// Returns the message code.
    pub fn code(&self) -> u8 {
        self.bytes[1]
    }
    /// Returns the encoded checksum.
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }
    /// Returns body bytes.
    pub fn body(&self) -> &[u8] {
        &self.bytes[HEADER_LENGTH..]
    }
    /// Returns mutable body bytes without updating the checksum.
    pub fn body_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[HEADER_LENGTH..]
    }
    /// Returns represented bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Returns represented bytes mutably.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }
    /// Replaces type without updating checksum.
    pub fn set_message_type(&mut self, value: Icmpv4Type) {
        self.bytes[0] = value.raw();
    }
    /// Replaces code without updating checksum.
    pub fn set_code(&mut self, value: u8) {
        self.bytes[1] = value;
    }
    /// Replaces checksum directly.
    pub fn set_checksum(&mut self, value: u16) {
        self.bytes[2..4].copy_from_slice(&value.to_be_bytes());
    }
    /// Recomputes the complete ICMPv4 checksum.
    pub fn update_checksum(&mut self) {
        self.bytes[2..4].fill(0);
        let value = internet_checksum::checksum(internet_checksum::add_bytes(0, self.bytes));
        self.set_checksum(value);
    }
    /// Tests the complete ICMPv4 checksum.
    pub fn checksum_is_valid(&self) -> bool {
        internet_checksum::sum(self.bytes) == 0xffff
    }
}
