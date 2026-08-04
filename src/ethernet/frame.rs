use core::fmt;

use crate::ParseError;

use super::{EtherType, MacAddress};

const HEADER_LEN: usize = 14;
const DESTINATION: core::ops::Range<usize> = 0..6;
const SOURCE: core::ops::Range<usize> = 6..12;
const ETHER_TYPE: core::ops::Range<usize> = 12..14;

/// A validated immutable borrow of one Ethernet II frame.
///
/// The fixed destination, source, and protocol-type header order follows
/// [RFC 894](https://www.rfc-editor.org/rfc/rfc894). Callers must remove any frame check
/// sequence (FCS) before parsing because every supplied byte after the fixed header is
/// payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthernetFrame<'a> {
    bytes: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    /// Validates and borrows an Ethernet II frame.
    ///
    /// The parser rejects inputs shorter than the 14-octet destination/source/type
    /// header described by [RFC 894](https://www.rfc-editor.org/rfc/rfc894). Every
    /// remaining supplied octet is exposed unchanged as payload; callers must remove any
    /// frame check sequence (FCS) before parsing. No minimum payload length is imposed by
    /// this wire view.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        validate_frame_length(bytes.len())?;
        Ok(Self { bytes })
    }

    /// Returns the destination Ethernet address.
    ///
    /// RFC 894 places the destination address in the first six octets of the Ethernet
    /// header: <https://www.rfc-editor.org/rfc/rfc894>.
    #[inline]
    pub fn destination(&self) -> MacAddress {
        MacAddress::new(
            self.bytes[DESTINATION]
                .try_into()
                .expect("validated header"),
        )
    }

    /// Returns the source Ethernet address.
    ///
    /// RFC 894 places the source address immediately after the destination address:
    /// <https://www.rfc-editor.org/rfc/rfc894>.
    #[inline]
    pub fn source(&self) -> MacAddress {
        MacAddress::new(self.bytes[SOURCE].try_into().expect("validated header"))
    }

    /// Returns the Ethernet protocol type.
    ///
    /// RFC 894 places the two-octet protocol type after the source address and transmits
    /// it most-significant octet first: <https://www.rfc-editor.org/rfc/rfc894>.
    #[inline]
    pub fn ether_type(&self) -> EtherType {
        EtherType::new(u16::from_be_bytes(
            self.bytes[ETHER_TYPE].try_into().expect("validated header"),
        ))
    }

    /// Returns the payload bytes following the fixed Ethernet II header.
    ///
    /// This is the data field after the type field in the RFC 894 Ethernet encapsulation:
    /// <https://www.rfc-editor.org/rfc/rfc894>. The returned slice borrows the input.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[HEADER_LEN..]
    }

    /// Returns all represented frame bytes.
    ///
    /// The byte layout is the destination/source/type/payload order described by
    /// [RFC 894](https://www.rfc-editor.org/rfc/rfc894). Callers must remove any frame
    /// check sequence (FCS) before parsing; it cannot be distinguished from payload here.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// A validated mutable borrow of one Ethernet II frame.
///
/// Its fixed header uses the destination, source, and protocol-type order described by
/// [RFC 894](https://www.rfc-editor.org/rfc/rfc894). Callers must remove any frame check
/// sequence (FCS) before parsing because every supplied byte after the fixed header is
/// payload.
#[derive(Debug, Eq, PartialEq)]
pub struct EthernetFrameMut<'a> {
    bytes: &'a mut [u8],
}

impl<'a> EthernetFrameMut<'a> {
    /// Validates and mutably borrows an Ethernet II frame.
    ///
    /// The parser rejects inputs shorter than the 14-octet destination/source/type
    /// header described by [RFC 894](https://www.rfc-editor.org/rfc/rfc894). Every
    /// remaining supplied octet is payload and remains available for independent protocol
    /// parsing; callers must remove any frame check sequence (FCS) before parsing.
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        validate_frame_length(bytes.len())?;
        Ok(Self { bytes })
    }

    /// Returns the destination Ethernet address.
    ///
    /// RFC 894 assigns the first six header octets to the destination address:
    /// <https://www.rfc-editor.org/rfc/rfc894>.
    #[inline]
    pub fn destination(&self) -> MacAddress {
        MacAddress::new(
            self.bytes[DESTINATION]
                .try_into()
                .expect("validated header"),
        )
    }

    /// Returns the source Ethernet address.
    ///
    /// RFC 894 assigns the next six header octets to the source address:
    /// <https://www.rfc-editor.org/rfc/rfc894>.
    #[inline]
    pub fn source(&self) -> MacAddress {
        MacAddress::new(self.bytes[SOURCE].try_into().expect("validated header"))
    }

    /// Returns the Ethernet protocol type.
    ///
    /// RFC 894 places this two-octet, most-significant-octet-first field after the source
    /// address: <https://www.rfc-editor.org/rfc/rfc894>.
    #[inline]
    pub fn ether_type(&self) -> EtherType {
        EtherType::new(u16::from_be_bytes(
            self.bytes[ETHER_TYPE].try_into().expect("validated header"),
        ))
    }

    /// Replaces the destination Ethernet address.
    ///
    /// This writes the first six header octets assigned to the destination address by
    /// [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
    #[inline]
    pub fn set_destination(&mut self, address: MacAddress) {
        self.bytes[DESTINATION].copy_from_slice(&address.octets());
    }

    /// Replaces the source Ethernet address.
    ///
    /// This writes the six header octets assigned to the source address by
    /// [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
    #[inline]
    pub fn set_source(&mut self, address: MacAddress) {
        self.bytes[SOURCE].copy_from_slice(&address.octets());
    }

    /// Replaces the Ethernet protocol type.
    ///
    /// This writes the most-significant-octet-first type field specified by
    /// [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
    #[inline]
    pub fn set_ether_type(&mut self, ether_type: EtherType) {
        self.bytes[ETHER_TYPE].copy_from_slice(&ether_type.raw().to_be_bytes());
    }

    /// Returns the payload bytes following the fixed Ethernet II header.
    ///
    /// This borrows the data field after the type field in RFC 894's encapsulation:
    /// <https://www.rfc-editor.org/rfc/rfc894>.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[HEADER_LEN..]
    }

    /// Returns mutable payload bytes following the fixed Ethernet II header.
    ///
    /// This mutably borrows the data field after the type field in RFC 894's
    /// encapsulation: <https://www.rfc-editor.org/rfc/rfc894>.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[HEADER_LEN..]
    }

    /// Returns all represented frame bytes.
    ///
    /// The represented order is destination, source, type, then payload as described by
    /// [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Returns all represented mutable frame bytes.
    ///
    /// The represented order is destination, source, type, then payload as described by
    /// [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }
}

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
        let frame_length = HEADER_LEN.checked_add(self.payload_length).ok_or(
            EthernetFrameBuildError::LengthOverflow {
                header_length: HEADER_LEN,
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
        Ok(EthernetFrameMut { bytes })
    }
}

fn validate_frame_length(available: usize) -> Result<(), ParseError> {
    if available < HEADER_LEN {
        return Err(ParseError::Truncated {
            minimum: HEADER_LEN,
            available,
        });
    }
    Ok(())
}
