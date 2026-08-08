use crate::error::ParseError;

use super::address::MacAddress;
use super::ether_type::EtherType;

pub(super) const HEADER_LENGTH: usize = 14;
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
        &self.bytes[HEADER_LENGTH..]
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
    pub(super) fn from_validated(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }

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
        &self.bytes[HEADER_LENGTH..]
    }

    /// Returns mutable payload bytes following the fixed Ethernet II header.
    ///
    /// This mutably borrows the data field after the type field in RFC 894's
    /// encapsulation: <https://www.rfc-editor.org/rfc/rfc894>.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[HEADER_LENGTH..]
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

fn validate_frame_length(available: usize) -> Result<(), ParseError> {
    if available < HEADER_LENGTH {
        return Err(ParseError::Truncated {
            minimum: HEADER_LENGTH,
            available,
        });
    }
    Ok(())
}
