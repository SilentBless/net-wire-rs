//! UDP caller-buffer builder.

use super::datagram::UdpDatagramMut;
use super::layout::{HEADER_LENGTH, UdpDatagramLayoutBuilder, UdpDatagramLayoutWriteError};
use core::fmt;

/// Failure to construct a UDP datagram in caller-provided storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpDatagramBuildError {
    /// The destination port was not supplied.
    MissingDestinationPort,
    /// The requested datagram length cannot be represented in the UDP length field.
    DatagramLengthTooLarge,
    /// The buffer cannot hold the requested datagram.
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
    /// The validated datagram could not be represented by the UDP layout.
    InvalidRepresentation,
}
impl fmt::Display for UdpDatagramBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDestinationPort => formatter.write_str("missing UDP destination port"),
            Self::DatagramLengthTooLarge => {
                formatter.write_str("UDP datagram length exceeds u16::MAX")
            }
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                formatter,
                "UDP buffer is too short: need {required} bytes, have {available}"
            ),
            Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "UDP field {field} encoding: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidRepresentation => {
                formatter.write_str("validated UDP datagram could not be represented")
            }
        }
    }
}
impl core::error::Error for UdpDatagramBuildError {}

fn representation_error(error: UdpDatagramLayoutWriteError) -> UdpDatagramBuildError {
    match error {
        UdpDatagramLayoutWriteError::FieldSourcePort(error)
        | UdpDatagramLayoutWriteError::FieldDestinationPort(error)
        | UdpDatagramLayoutWriteError::FieldLength(error)
        | UdpDatagramLayoutWriteError::FieldChecksum(error) => match error {},
        UdpDatagramLayoutWriteError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => UdpDatagramBuildError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
        UdpDatagramLayoutWriteError::MissingContext { .. }
        | UdpDatagramLayoutWriteError::InvalidCodecWidth { .. }
        | UdpDatagramLayoutWriteError::InvalidRangeSource { .. }
        | UdpDatagramLayoutWriteError::ConflictingRangeSources { .. }
        | UdpDatagramLayoutWriteError::InvalidPrefixPlanLength { .. }
        | UdpDatagramLayoutWriteError::InvalidLayoutExtent { .. }
        | UdpDatagramLayoutWriteError::OutputTooShort { .. }
        | UdpDatagramLayoutWriteError::MissingField { .. } => {
            UdpDatagramBuildError::InvalidRepresentation
        }
    }
}

/// Builds a UDP header in caller-owned storage.
pub struct UdpDatagramBuilder<'a> {
    buffer: &'a mut [u8],
    payload_length: usize,
    source_port: u16,
    destination_port: Option<u16>,
    checksum: u16,
}
impl<'a> UdpDatagramBuilder<'a> {
    /// Starts a builder for `payload_length` bytes, which are left untouched.
    #[inline]
    pub fn new(buffer: &'a mut [u8], payload_length: usize) -> Self {
        Self {
            buffer,
            payload_length,
            source_port: 0,
            destination_port: None,
            checksum: 0,
        }
    }
    /// Supplies the source port; it defaults to zero.
    #[inline]
    pub fn source_port(mut self, value: u16) -> Self {
        self.source_port = value;
        self
    }
    /// Supplies the destination port.
    #[inline]
    pub fn destination_port(mut self, value: u16) -> Self {
        self.destination_port = Some(value);
        self
    }
    /// Supplies the encoded checksum; it defaults to zero.
    #[inline]
    pub fn checksum(mut self, value: u16) -> Self {
        self.checksum = value;
        self
    }
    /// Validates all inputs, then writes only the UDP header.
    pub fn build(self) -> Result<UdpDatagramMut<'a>, UdpDatagramBuildError> {
        let destination_port = self
            .destination_port
            .ok_or(UdpDatagramBuildError::MissingDestinationPort)?;
        let length = HEADER_LENGTH
            .checked_add(self.payload_length)
            .ok_or(UdpDatagramBuildError::DatagramLengthTooLarge)?;
        let encoded_length =
            u16::try_from(length).map_err(|_| UdpDatagramBuildError::DatagramLengthTooLarge)?;
        if self.buffer.len() < length {
            return Err(UdpDatagramBuildError::BufferTooShort {
                required: length,
                available: self.buffer.len(),
            });
        }
        let (layout, _) = UdpDatagramLayoutBuilder::new()
            .source_port(self.source_port)
            .destination_port(destination_port)
            .length(encoded_length)
            .checksum(self.checksum)
            .payload_existing(self.payload_length)
            .build_into(&mut self.buffer[..length])
            .map_err(representation_error)?;
        Ok(UdpDatagramMut::from_layout(layout))
    }
}
