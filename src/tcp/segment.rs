//! Checked borrowed TCP segment views.

use super::flags::TcpFlags;
use super::layout::{
    HEADER_LENGTH, TcpSegmentLayoutMutationError, TcpSegmentLayoutView, TcpSegmentLayoutViewMut,
};
use crate::error::ParseError;
use core::fmt;

/// A TCP field mutation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpSegmentMutationError {
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
impl fmt::Display for TcpSegmentMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "TCP field {field} plan length: expected {expected} bytes, got {actual}"
            ),
        }
    }
}
impl core::error::Error for TcpSegmentMutationError {}

fn mutation_error(error: TcpSegmentLayoutMutationError) -> TcpSegmentMutationError {
    match error {
        TcpSegmentLayoutMutationError::FieldSourcePort(error)
        | TcpSegmentLayoutMutationError::FieldDestinationPort(error)
        | TcpSegmentLayoutMutationError::FieldSequenceNumber(error)
        | TcpSegmentLayoutMutationError::FieldAcknowledgmentNumber(error)
        | TcpSegmentLayoutMutationError::FieldDataOffsetReserved(error)
        | TcpSegmentLayoutMutationError::FieldFlags(error)
        | TcpSegmentLayoutMutationError::FieldWindowSize(error)
        | TcpSegmentLayoutMutationError::FieldChecksum(error)
        | TcpSegmentLayoutMutationError::FieldUrgentPointer(error) => match error {},
        TcpSegmentLayoutMutationError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => TcpSegmentMutationError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
    }
}

/// A structurally validated TCP segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSegment<'a> {
    layout: TcpSegmentLayoutView<'a>,
    header_length: usize,
}
impl<'a> TcpSegment<'a> {
    /// Parses a complete TCP segment without checking its checksum.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let header_length = validated_header_length(bytes)?;
        let layout =
            TcpSegmentLayoutView::parse_exact(bytes).map_err(|_| ParseError::Truncated {
                minimum: HEADER_LENGTH,
                available: bytes.len(),
            })?;
        Ok(Self {
            layout,
            header_length,
        })
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
    /// Returns the sequence number.
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        self.layout.sequence_number()
    }
    /// Returns the acknowledgment number.
    #[inline]
    pub fn acknowledgment_number(&self) -> u32 {
        self.layout.acknowledgment_number()
    }
    /// Returns the data offset in four-octet words.
    #[inline]
    pub fn data_offset(&self) -> u8 {
        self.layout.data_offset()
    }
    /// Returns the header length in octets.
    #[inline]
    pub fn header_length(&self) -> usize {
        self.header_length
    }
    /// Returns the four reserved header bits.
    #[inline]
    pub fn reserved(&self) -> u8 {
        self.layout.reserved()
    }
    /// Returns TCP control flags with their raw wire value preserved.
    #[inline]
    pub fn flags(&self) -> TcpFlags {
        self.layout.flags()
    }
    /// Returns the window size.
    #[inline]
    pub fn window_size(&self) -> u16 {
        self.layout.window_size()
    }
    /// Returns the encoded checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.layout.checksum()
    }
    /// Returns the urgent pointer.
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        self.layout.urgent_pointer()
    }
    /// Returns header options.
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        &self.layout.body()[..self.header_length - HEADER_LENGTH]
    }
    /// Returns payload bytes.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.layout.body()[self.header_length - HEADER_LENGTH..]
    }
    /// Returns all represented segment bytes.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.layout.as_bytes()
    }
}

/// A mutable structurally validated TCP segment.
pub struct TcpSegmentMut<'a> {
    layout: TcpSegmentLayoutViewMut<'a>,
    header_length: usize,
}
impl fmt::Debug for TcpSegmentMut<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TcpSegmentMut")
            .field("bytes", &self.as_bytes())
            .finish()
    }
}
impl PartialEq for TcpSegmentMut<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.header_length == other.header_length && self.as_bytes() == other.as_bytes()
    }
}
impl Eq for TcpSegmentMut<'_> {}
impl<'a> TcpSegmentMut<'a> {
    /// Parses a complete TCP segment without checking its checksum.
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        let header_length = validated_header_length(bytes)?;
        let available = bytes.len();
        let layout =
            TcpSegmentLayoutViewMut::parse_exact_mut(bytes).map_err(|_| ParseError::Truncated {
                minimum: HEADER_LENGTH,
                available,
            })?;
        Ok(Self {
            layout,
            header_length,
        })
    }
    pub(super) const fn from_layout(
        layout: TcpSegmentLayoutViewMut<'a>,
        header_length: usize,
    ) -> Self {
        Self {
            layout,
            header_length,
        }
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
    /// Returns the sequence number.
    #[inline]
    pub fn sequence_number(&self) -> u32 {
        self.layout.sequence_number()
    }
    /// Returns the acknowledgment number.
    #[inline]
    pub fn acknowledgment_number(&self) -> u32 {
        self.layout.acknowledgment_number()
    }
    /// Returns the data offset in four-octet words.
    #[inline]
    pub fn data_offset(&self) -> u8 {
        self.layout.data_offset()
    }
    /// Returns the header length in octets.
    #[inline]
    pub fn header_length(&self) -> usize {
        self.header_length
    }
    /// Returns the four reserved header bits.
    #[inline]
    pub fn reserved(&self) -> u8 {
        self.layout.reserved()
    }
    /// Returns TCP control flags with their raw wire value preserved.
    #[inline]
    pub fn flags(&self) -> TcpFlags {
        self.layout.flags()
    }
    /// Returns the window size.
    #[inline]
    pub fn window_size(&self) -> u16 {
        self.layout.window_size()
    }
    /// Returns the encoded checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.layout.checksum()
    }
    /// Returns the urgent pointer.
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        self.layout.urgent_pointer()
    }
    /// Returns header options.
    #[inline]
    pub fn options(&self) -> &[u8] {
        &self.layout.body()[..self.header_length - HEADER_LENGTH]
    }
    /// Returns mutable header options without updating the checksum.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        let options_length = self.header_length - HEADER_LENGTH;
        &mut self.layout.body_mut()[..options_length]
    }
    /// Returns payload bytes.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.layout.body()[self.header_length - HEADER_LENGTH..]
    }
    /// Returns mutable payload bytes without updating the checksum.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let options_length = self.header_length - HEADER_LENGTH;
        &mut self.layout.body_mut()[options_length..]
    }
    /// Returns all represented segment bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.layout.as_bytes()
    }
    /// Replaces the source port without updating the checksum.
    #[inline]
    pub fn set_source_port(&mut self, value: u16) -> Result<(), TcpSegmentMutationError> {
        self.layout.set_source_port(value).map_err(mutation_error)
    }
    /// Replaces the destination port without updating the checksum.
    #[inline]
    pub fn set_destination_port(&mut self, value: u16) -> Result<(), TcpSegmentMutationError> {
        self.layout
            .set_destination_port(value)
            .map_err(mutation_error)
    }
    /// Replaces the sequence number without updating the checksum.
    #[inline]
    pub fn set_sequence_number(&mut self, value: u32) -> Result<(), TcpSegmentMutationError> {
        self.layout
            .set_sequence_number(value)
            .map_err(mutation_error)
    }
    /// Replaces the acknowledgment number without updating the checksum.
    #[inline]
    pub fn set_acknowledgment_number(&mut self, value: u32) -> Result<(), TcpSegmentMutationError> {
        self.layout
            .set_acknowledgment_number(value)
            .map_err(mutation_error)
    }
    /// Replaces flags without updating the checksum.
    #[inline]
    pub fn set_flags(&mut self, value: TcpFlags) -> Result<(), TcpSegmentMutationError> {
        self.layout.set_flags(value).map_err(mutation_error)
    }
    /// Replaces the window size without updating the checksum.
    #[inline]
    pub fn set_window_size(&mut self, value: u16) -> Result<(), TcpSegmentMutationError> {
        self.layout.set_window_size(value).map_err(mutation_error)
    }
    /// Replaces the checksum directly.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) -> Result<(), TcpSegmentMutationError> {
        self.layout.set_checksum(value).map_err(mutation_error)
    }
    /// Replaces the urgent pointer without updating the checksum.
    #[inline]
    pub fn set_urgent_pointer(&mut self, value: u16) -> Result<(), TcpSegmentMutationError> {
        self.layout
            .set_urgent_pointer(value)
            .map_err(mutation_error)
    }
}

fn validated_header_length(bytes: &[u8]) -> Result<usize, ParseError> {
    if bytes.len() < HEADER_LENGTH {
        return Err(ParseError::Truncated {
            minimum: HEADER_LENGTH,
            available: bytes.len(),
        });
    }
    let layout = TcpSegmentLayoutView::parse_exact(bytes).map_err(|_| ParseError::Truncated {
        minimum: HEADER_LENGTH,
        available: bytes.len(),
    })?;
    let header_length = usize::from(layout.data_offset()) * 4;
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
    Ok(header_length)
}
