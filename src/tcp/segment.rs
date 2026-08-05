//! Checked borrowed TCP segment views.

use super::TcpFlags;
use crate::ParseError;

const HEADER_LENGTH: usize = 20;

/// A structurally validated TCP segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSegment<'a> {
    bytes: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    /// Parses a complete TCP segment without checking its checksum.
    #[inline]
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        validate(bytes)?;
        Ok(Self { bytes })
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

    /// Returns the sequence number.
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        u32::from_be_bytes(self.bytes[4..8].try_into().expect("validated TCP header"))
    }

    /// Returns the acknowledgment number.
    #[inline]
    pub fn acknowledgment_number(&self) -> u32 {
        u32::from_be_bytes(self.bytes[8..12].try_into().expect("validated TCP header"))
    }

    /// Returns the data offset in four-octet words.
    #[inline]
    pub fn data_offset(&self) -> u8 {
        self.bytes[12] >> 4
    }

    /// Returns the header length in octets.
    #[inline]
    pub fn header_length(&self) -> usize {
        usize::from(self.data_offset()) * 4
    }

    /// Returns the four reserved header bits.
    #[inline]
    pub fn reserved(&self) -> u8 {
        self.bytes[12] & 0x0f
    }

    /// Returns TCP control flags with their raw wire value preserved.
    #[inline]
    pub fn flags(&self) -> TcpFlags {
        TcpFlags::new(self.bytes[13])
    }

    /// Returns the window size.
    #[inline]
    pub fn window_size(&self) -> u16 {
        u16::from_be_bytes([self.bytes[14], self.bytes[15]])
    }

    /// Returns the encoded checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[16], self.bytes[17]])
    }

    /// Returns the urgent pointer.
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes([self.bytes[18], self.bytes[19]])
    }

    /// Returns header options.
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        &self.bytes[HEADER_LENGTH..self.header_length()]
    }

    /// Returns payload bytes.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_length()..]
    }

    /// Returns all represented segment bytes.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// A mutable structurally validated TCP segment.
#[derive(Debug, Eq, PartialEq)]
pub struct TcpSegmentMut<'a> {
    bytes: &'a mut [u8],
}

impl<'a> TcpSegmentMut<'a> {
    /// Parses a complete TCP segment without checking its checksum.
    #[inline]
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        validate(bytes)?;
        Ok(Self { bytes })
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

    /// Returns the sequence number.
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        u32::from_be_bytes(self.bytes[4..8].try_into().expect("validated TCP header"))
    }

    /// Returns the acknowledgment number.
    #[inline]
    pub fn acknowledgment_number(&self) -> u32 {
        u32::from_be_bytes(self.bytes[8..12].try_into().expect("validated TCP header"))
    }

    /// Returns the data offset in four-octet words.
    #[inline]
    pub fn data_offset(&self) -> u8 {
        self.bytes[12] >> 4
    }

    /// Returns the header length in octets.
    #[inline]
    pub fn header_length(&self) -> usize {
        usize::from(self.data_offset()) * 4
    }

    /// Returns the four reserved header bits.
    #[inline]
    pub fn reserved(&self) -> u8 {
        self.bytes[12] & 0x0f
    }

    /// Returns TCP control flags with their raw wire value preserved.
    #[inline]
    pub fn flags(&self) -> TcpFlags {
        TcpFlags::new(self.bytes[13])
    }

    /// Returns the window size.
    #[inline]
    pub fn window_size(&self) -> u16 {
        u16::from_be_bytes([self.bytes[14], self.bytes[15]])
    }

    /// Returns the encoded checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[16], self.bytes[17]])
    }

    /// Returns the urgent pointer.
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes([self.bytes[18], self.bytes[19]])
    }

    /// Returns header options.
    #[inline]
    pub fn options(&self) -> &[u8] {
        &self.bytes[HEADER_LENGTH..self.header_length()]
    }

    /// Returns mutable header options without updating the checksum.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        let header_length = self.header_length();
        &mut self.bytes[HEADER_LENGTH..header_length]
    }

    /// Returns payload bytes.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.header_length()..]
    }

    /// Returns mutable payload bytes without updating the checksum.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let header_length = self.header_length();
        &mut self.bytes[header_length..]
    }

    /// Returns all represented segment bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Returns all represented segment bytes mutably without updating the checksum.
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

    /// Replaces the sequence number without updating the checksum.
    #[inline]
    pub fn set_sequence_number(&mut self, value: u32) {
        self.bytes[4..8].copy_from_slice(&value.to_be_bytes());
    }

    /// Replaces the acknowledgment number without updating the checksum.
    #[inline]
    pub fn set_acknowledgment_number(&mut self, value: u32) {
        self.bytes[8..12].copy_from_slice(&value.to_be_bytes());
    }

    /// Replaces flags without updating the checksum.
    #[inline]
    pub fn set_flags(&mut self, value: TcpFlags) {
        self.bytes[13] = value.raw();
    }

    /// Replaces the window size without updating the checksum.
    #[inline]
    pub fn set_window_size(&mut self, value: u16) {
        self.bytes[14..16].copy_from_slice(&value.to_be_bytes());
    }

    /// Replaces the checksum directly.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        self.bytes[16..18].copy_from_slice(&value.to_be_bytes());
    }

    /// Replaces the urgent pointer without updating the checksum.
    #[inline]
    pub fn set_urgent_pointer(&mut self, value: u16) {
        self.bytes[18..20].copy_from_slice(&value.to_be_bytes());
    }
}

fn validate(bytes: &[u8]) -> Result<(), ParseError> {
    if bytes.len() < HEADER_LENGTH {
        return Err(ParseError::Truncated {
            minimum: HEADER_LENGTH,
            available: bytes.len(),
        });
    }
    let header_length = usize::from(bytes[12] >> 4) * 4;
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
    Ok(())
}
