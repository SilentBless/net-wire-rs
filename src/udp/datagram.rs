//! Checked borrowed UDP datagram views.

use crate::ParseError;

const HEADER_LENGTH: usize = 8;

/// The validation state of an IPv4 UDP checksum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpChecksumStatus {
    /// UDP has no IPv4 checksum.
    NotPresent,
    /// The encoded checksum is valid.
    Valid,
    /// The encoded checksum is invalid.
    Invalid,
}

/// A structurally validated UDP datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpDatagram<'a> {
    bytes: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    /// Parses a UDP datagram without checking its checksum.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let length = validated_length(bytes)?;
        Ok(Self {
            bytes: &bytes[..length],
        })
    }

    /// Returns the source port.
    #[inline]
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }
    /// Returns the destination port.
    #[inline]
    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }
    /// Returns the encoded datagram length.
    #[inline]
    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.bytes[4], self.bytes[5]])
    }
    /// Returns the encoded checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[6], self.bytes[7]])
    }
    /// Returns payload bytes.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[HEADER_LENGTH..]
    }
    /// Returns all represented datagram bytes.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// A mutable structurally validated UDP datagram.
#[derive(Debug, Eq, PartialEq)]
pub struct UdpDatagramMut<'a> {
    bytes: &'a mut [u8],
}

impl<'a> UdpDatagramMut<'a> {
    /// Parses a UDP datagram without checking its checksum.
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        let length = validated_length(bytes)?;
        Ok(Self {
            bytes: &mut bytes[..length],
        })
    }

    pub(crate) fn from_validated(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the source port.
    #[inline]
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }
    /// Returns the destination port.
    #[inline]
    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }
    /// Returns the encoded datagram length.
    #[inline]
    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.bytes[4], self.bytes[5]])
    }
    /// Returns the encoded checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[6], self.bytes[7]])
    }
    /// Returns payload bytes.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[HEADER_LENGTH..]
    }
    /// Returns mutable payload bytes without updating the checksum.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[HEADER_LENGTH..]
    }
    /// Returns all represented datagram bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Returns all represented datagram bytes mutably without updating the checksum.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }
    /// Replaces the source port without updating the checksum.
    #[inline]
    pub fn set_source_port(&mut self, value: u16) {
        self.bytes[0..2].copy_from_slice(&value.to_be_bytes());
    }
    /// Replaces the destination port without updating the checksum.
    #[inline]
    pub fn set_destination_port(&mut self, value: u16) {
        self.bytes[2..4].copy_from_slice(&value.to_be_bytes());
    }
    /// Replaces the encoded checksum directly.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        self.bytes[6..8].copy_from_slice(&value.to_be_bytes());
    }
}

fn validated_length(bytes: &[u8]) -> Result<usize, ParseError> {
    if bytes.len() < HEADER_LENGTH {
        return Err(ParseError::Truncated {
            minimum: HEADER_LENGTH,
            available: bytes.len(),
        });
    }
    let length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    if length == 0 || length < HEADER_LENGTH {
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
