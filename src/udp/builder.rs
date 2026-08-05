//! UDP caller-buffer builder.

use super::UdpDatagramMut;
use core::fmt;

const HEADER_LENGTH: usize = 8;

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
        let bytes = &mut self.buffer[..length];
        bytes[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&destination_port.to_be_bytes());
        bytes[4..6].copy_from_slice(&encoded_length.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.checksum.to_be_bytes());
        Ok(UdpDatagramMut::from_validated(bytes))
    }
}
