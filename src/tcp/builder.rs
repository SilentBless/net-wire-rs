//! TCP caller-buffer builder.

use super::flags::TcpFlags;
use super::segment::{HEADER_LENGTH, TcpSegmentMut};
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

        let bytes = &mut self.buffer[..segment_length];
        bytes[0..2].copy_from_slice(&source_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&destination_port.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.sequence_number.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.acknowledgment_number.to_be_bytes());
        bytes[12] = u8::try_from(header_length / 4).expect("TCP header length fits") << 4;
        bytes[13] = self.flags.raw();
        bytes[14..16].copy_from_slice(&self.window_size.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());
        bytes[HEADER_LENGTH..header_length].copy_from_slice(self.options);
        Ok(TcpSegmentMut::from_validated(bytes))
    }
}
