//! TCP caller-buffer builder.

use super::flags::TcpFlags;
use super::layout::{HEADER_LENGTH, TcpSegmentLayoutBuilder, TcpSegmentLayoutWriteError};
use super::segment::TcpSegmentMut;
use core::fmt;

/// Failure to construct a TCP segment in caller-provided storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpSegmentBuildError {
    /// The source port was not supplied.
    MissingSourcePort,
    /// The destination port was not supplied.
    MissingDestinationPort,
    /// Options are not a multiple of four octets or exceed forty octets.
    InvalidOptionsLength,
    /// The requested segment length cannot be represented as a `usize`.
    SegmentLengthTooLarge,
    /// The buffer cannot hold the requested segment.
    BufferTooShort {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
    /// A field value could not be encoded at its required wire width.
    InvalidFieldEncoding {
        /// The field whose encoding was invalid.
        field: &'static str,
        /// The required fixed width.
        expected: usize,
        /// The encoded width that was produced.
        actual: usize,
    },
    /// The validated segment could not be represented by the TCP layout.
    InvalidRepresentation,
}
impl fmt::Display for TcpSegmentBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSourcePort => f.write_str("missing TCP source port"),
            Self::MissingDestinationPort => f.write_str("missing TCP destination port"),
            Self::InvalidOptionsLength => f.write_str("invalid TCP options length"),
            Self::SegmentLengthTooLarge => f.write_str("TCP segment length exceeds platform limit"),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "TCP buffer is too short: need {required} bytes, have {available}"
            ),
            Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => write!(
                f,
                "TCP field {field} encoding: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidRepresentation => {
                f.write_str("validated TCP segment could not be represented")
            }
        }
    }
}
impl core::error::Error for TcpSegmentBuildError {}
fn representation_error(error: TcpSegmentLayoutWriteError) -> TcpSegmentBuildError {
    match error {
        TcpSegmentLayoutWriteError::FieldSourcePort(error)
        | TcpSegmentLayoutWriteError::FieldDestinationPort(error)
        | TcpSegmentLayoutWriteError::FieldSequenceNumber(error)
        | TcpSegmentLayoutWriteError::FieldAcknowledgmentNumber(error)
        | TcpSegmentLayoutWriteError::FieldDataOffsetReserved(error)
        | TcpSegmentLayoutWriteError::FieldFlags(error)
        | TcpSegmentLayoutWriteError::FieldWindowSize(error)
        | TcpSegmentLayoutWriteError::FieldChecksum(error)
        | TcpSegmentLayoutWriteError::FieldUrgentPointer(error) => match error {},
        TcpSegmentLayoutWriteError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => TcpSegmentBuildError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
        TcpSegmentLayoutWriteError::MissingContext { .. }
        | TcpSegmentLayoutWriteError::InvalidCodecWidth { .. }
        | TcpSegmentLayoutWriteError::InvalidRangeSource { .. }
        | TcpSegmentLayoutWriteError::ConflictingRangeSources { .. }
        | TcpSegmentLayoutWriteError::InvalidPrefixPlanLength { .. }
        | TcpSegmentLayoutWriteError::InvalidLayoutExtent { .. }
        | TcpSegmentLayoutWriteError::OutputTooShort { .. }
        | TcpSegmentLayoutWriteError::MissingField { .. } => {
            TcpSegmentBuildError::InvalidRepresentation
        }
    }
}

/// Builds a TCP header in caller-owned storage.
pub struct TcpSegmentBuilder<'a, 'b> {
    buffer: &'a mut [u8],
    payload_length: usize,
    options: &'b [u8],
    source_port: Option<u16>,
    destination_port: Option<u16>,
    sequence_number: u32,
    acknowledgment_number: u32,
    flags: TcpFlags,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
}
impl<'a, 'b> TcpSegmentBuilder<'a, 'b> {
    /// Starts a builder for `payload_length` bytes, which are left untouched.
    pub fn new(buffer: &'a mut [u8], payload_length: usize) -> Self {
        Self {
            buffer,
            payload_length,
            options: &[],
            source_port: None,
            destination_port: None,
            sequence_number: 0,
            acknowledgment_number: 0,
            flags: TcpFlags::new(0),
            window_size: 0,
            checksum: 0,
            urgent_pointer: 0,
        }
    }
    /// Supplies the source port.
    pub fn source_port(mut self, value: u16) -> Self {
        self.source_port = Some(value);
        self
    }
    /// Supplies the destination port.
    pub fn destination_port(mut self, value: u16) -> Self {
        self.destination_port = Some(value);
        self
    }
    /// Supplies copied header options.
    pub fn options(mut self, value: &'b [u8]) -> Self {
        self.options = value;
        self
    }
    /// Supplies the sequence number.
    pub fn sequence_number(mut self, value: u32) -> Self {
        self.sequence_number = value;
        self
    }
    /// Supplies the acknowledgment number.
    pub fn acknowledgment_number(mut self, value: u32) -> Self {
        self.acknowledgment_number = value;
        self
    }
    /// Supplies flags.
    pub fn flags(mut self, value: TcpFlags) -> Self {
        self.flags = value;
        self
    }
    /// Supplies the window size.
    pub fn window_size(mut self, value: u16) -> Self {
        self.window_size = value;
        self
    }
    /// Supplies the checksum.
    pub fn checksum(mut self, value: u16) -> Self {
        self.checksum = value;
        self
    }
    /// Supplies the urgent pointer.
    pub fn urgent_pointer(mut self, value: u16) -> Self {
        self.urgent_pointer = value;
        self
    }
    /// Validates inputs and writes only the TCP header and options.
    pub fn build(self) -> Result<TcpSegmentMut<'a>, TcpSegmentBuildError> {
        let source_port = self
            .source_port
            .ok_or(TcpSegmentBuildError::MissingSourcePort)?;
        let destination_port = self
            .destination_port
            .ok_or(TcpSegmentBuildError::MissingDestinationPort)?;
        if self.options.len() > 40 || !self.options.len().is_multiple_of(4) {
            return Err(TcpSegmentBuildError::InvalidOptionsLength);
        }
        let header_length = HEADER_LENGTH
            .checked_add(self.options.len())
            .ok_or(TcpSegmentBuildError::SegmentLengthTooLarge)?;
        let segment_length = header_length
            .checked_add(self.payload_length)
            .ok_or(TcpSegmentBuildError::SegmentLengthTooLarge)?;
        if self.buffer.len() < segment_length {
            return Err(TcpSegmentBuildError::BufferTooShort {
                required: segment_length,
                available: self.buffer.len(),
            });
        }
        let data_offset_reserved = u8::try_from(header_length / 4)
            .map_err(|_| TcpSegmentBuildError::InvalidRepresentation)?
            << 4;
        let (mut layout, _) = TcpSegmentLayoutBuilder::new()
            .source_port(source_port)
            .destination_port(destination_port)
            .sequence_number(self.sequence_number)
            .acknowledgment_number(self.acknowledgment_number)
            .data_offset_reserved(data_offset_reserved)
            .flags(self.flags)
            .window_size(self.window_size)
            .checksum(self.checksum)
            .urgent_pointer(self.urgent_pointer)
            .body_existing(
                self.options
                    .len()
                    .checked_add(self.payload_length)
                    .ok_or(TcpSegmentBuildError::SegmentLengthTooLarge)?,
            )
            .build_into(&mut self.buffer[..segment_length])
            .map_err(representation_error)?;
        layout.body_mut()[..self.options.len()].copy_from_slice(self.options);
        Ok(TcpSegmentMut::from_layout(layout, header_length))
    }
}
