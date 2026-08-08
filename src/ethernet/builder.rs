use core::fmt;

use super::address::MacAddress;
use super::ether_type::EtherType;
use super::frame::{EthernetFrameMut, HEADER_LENGTH};

const DESTINATION: core::ops::Range<usize> = 0..6;
const SOURCE: core::ops::Range<usize> = 6..12;
const ETHER_TYPE: core::ops::Range<usize> = 12..14;

/// An allocation-free failure while constructing an Ethernet II frame.
///
/// These failures apply to the destination/source/type header prescribed by
/// [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EthernetFrameBuildError {
    /// No destination address was supplied.
    MissingDestination,
    /// No source address was supplied.
    MissingSource,
    /// No protocol type was supplied.
    MissingEtherType,
    /// Header length plus the requested payload length overflowed `usize`.
    LengthOverflow {
        /// Fixed RFC 894 header length used in the attempted addition.
        header_length: usize,
        /// Requested payload length used in the attempted addition.
        payload_length: usize,
    },
    /// The caller buffer cannot hold the requested header and payload.
    BufferTooShort {
        /// Required header-plus-payload length.
        required: usize,
        /// Available caller-buffer length.
        available: usize,
    },
}

impl fmt::Display for EthernetFrameBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDestination => formatter.write_str("missing Ethernet destination address"),
            Self::MissingSource => formatter.write_str("missing Ethernet source address"),
            Self::MissingEtherType => formatter.write_str("missing Ethernet protocol type"),
            Self::LengthOverflow {
                header_length,
                payload_length,
            } => write!(
                formatter,
                "Ethernet frame length overflow: {header_length} + {payload_length}"
            ),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                formatter,
                "Ethernet buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

/// An allocation-free builder for an Ethernet II header in a caller-provided buffer.
///
/// It writes the destination, source, and protocol-type header specified by
/// [RFC 894](https://www.rfc-editor.org/rfc/rfc894), never generates FCS bytes, and
/// leaves the declared payload contents to the caller.
pub struct EthernetFrameBuilder<'a> {
    buffer: &'a mut [u8],
    payload_length: usize,
    destination: Option<MacAddress>,
    source: Option<MacAddress>,
    ether_type: Option<EtherType>,
}

impl<'a> EthernetFrameBuilder<'a> {
    /// Starts construction in `buffer` with an explicit payload length.
    ///
    /// `build` will represent exactly the RFC 894 header followed by this many payload
    /// octets; it does not write payload and never generates FCS bytes.
    #[inline]
    pub fn new(buffer: &'a mut [u8], payload_length: usize) -> Self {
        Self {
            buffer,
            payload_length,
            destination: None,
            source: None,
            ether_type: None,
        }
    }

    /// Supplies the destination address for the Ethernet header in
    /// [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
    #[inline]
    pub fn destination(mut self, destination: MacAddress) -> Self {
        self.destination = Some(destination);
        self
    }

    /// Supplies the source address for the Ethernet header in
    /// [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
    #[inline]
    pub fn source(mut self, source: MacAddress) -> Self {
        self.source = Some(source);
        self
    }

    /// Supplies the protocol type for the Ethernet header in
    /// [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
    #[inline]
    pub fn ether_type(mut self, ether_type: EtherType) -> Self {
        self.ether_type = Some(ether_type);
        self
    }

    /// Validates required fields and capacity, then writes exactly the Ethernet II header.
    ///
    /// Validation completes before any write. On success, the returned view is restricted
    /// to the RFC 894 header plus the declared payload; payload and trailing capacity are
    /// unchanged, and FCS bytes are never generated.
    #[inline]
    pub fn build(self) -> Result<EthernetFrameMut<'a>, EthernetFrameBuildError> {
        let destination = self
            .destination
            .ok_or(EthernetFrameBuildError::MissingDestination)?;
        let source = self.source.ok_or(EthernetFrameBuildError::MissingSource)?;
        let ether_type = self
            .ether_type
            .ok_or(EthernetFrameBuildError::MissingEtherType)?;
        let frame_length = HEADER_LENGTH.checked_add(self.payload_length).ok_or(
            EthernetFrameBuildError::LengthOverflow {
                header_length: HEADER_LENGTH,
                payload_length: self.payload_length,
            },
        )?;
        if self.buffer.len() < frame_length {
            return Err(EthernetFrameBuildError::BufferTooShort {
                required: frame_length,
                available: self.buffer.len(),
            });
        }

        let bytes = &mut self.buffer[..frame_length];
        bytes[DESTINATION].copy_from_slice(&destination.octets());
        bytes[SOURCE].copy_from_slice(&source.octets());
        bytes[ETHER_TYPE].copy_from_slice(&ether_type.raw().to_be_bytes());
        Ok(EthernetFrameMut::from_validated(bytes))
    }
}
