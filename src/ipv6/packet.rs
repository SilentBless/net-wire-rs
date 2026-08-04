use super::{Ipv6Address, Ipv6NextHeader, Ipv6PacketBuildError};
use crate::ParseError;
#[cfg(feature = "ethernet")]
use crate::{EtherType, EthernetFrame, EthernetFrameMut};

pub(super) const HEADER_LENGTH: usize = 40;

/// Meaning of the IPv6 base header's 16-bit Payload Length field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6PayloadLength {
    /// A nonzero payload length declared directly by the base header.
    Declared(u16),
    /// A zero field whose payload extent cannot be resolved from the base header alone.
    ///
    /// RFC 8200 section 3 reserves zero for a Jumbo Payload option. At this parsing layer,
    /// supplied trailing bytes may instead be absent or include lower-layer padding.
    Unspecified,
}

/// A structurally validated immutable IPv6 base-header view.
///
/// Parsing implements the fixed header from RFC 8200 section 3. It does not traverse extension
/// headers. A nonzero Payload Length bounds the view exactly; a zero field retains every supplied
/// trailing byte as an unresolved tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv6Packet<'a> {
    bytes: &'a [u8],
}

impl<'a> Ipv6Packet<'a> {
    /// Validates the fixed header, version, and any nonzero declared payload extent.
    #[inline]
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let packet_length = validate(bytes)?;
        Ok(Self {
            bytes: &bytes[..packet_length],
        })
    }

    /// Returns the eight-bit traffic class.
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        ((self.bytes[0] & 0x0f) << 4) | (self.bytes[1] >> 4)
    }

    /// Returns the 20-bit flow label.
    #[inline]
    pub fn flow_label(&self) -> u32 {
        (u32::from(self.bytes[1] & 0x0f) << 16)
            | (u32::from(self.bytes[2]) << 8)
            | u32::from(self.bytes[3])
    }

    /// Interprets the base header's Payload Length field without resolving Jumbo Payload options.
    #[inline]
    pub fn payload_length(&self) -> Ipv6PayloadLength {
        match self.raw_payload_length() {
            0 => Ipv6PayloadLength::Unspecified,
            value => Ipv6PayloadLength::Declared(value),
        }
    }

    /// Returns the raw 16-bit Payload Length field.
    #[inline]
    pub fn raw_payload_length(&self) -> u16 {
        u16::from_be_bytes(self.bytes[4..6].try_into().expect("validated IPv6 header"))
    }

    /// Returns the Next Header value, preserving unknown values.
    #[inline]
    pub fn next_header(&self) -> Ipv6NextHeader {
        Ipv6NextHeader::new(self.bytes[6])
    }

    /// Returns the hop limit.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.bytes[7]
    }

    /// Returns the source address.
    #[inline]
    pub fn source(&self) -> Ipv6Address {
        Ipv6Address::new(self.bytes[8..24].try_into().expect("validated IPv6 header"))
    }

    /// Returns the destination address.
    #[inline]
    pub fn destination(&self) -> Ipv6Address {
        Ipv6Address::new(
            self.bytes[24..40]
                .try_into()
                .expect("validated IPv6 header"),
        )
    }

    /// Returns bytes after the fixed header.
    ///
    /// For a nonzero Payload Length these are exactly the declared payload. For a zero field they
    /// are an unresolved tail that may be empty payload, lower-layer padding, or Jumbo Payload
    /// content; extension-header handling must resolve that distinction.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[HEADER_LENGTH..]
    }

    /// Returns all bytes represented by this base-header view.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// A structurally validated mutable IPv6 base-header view.
#[derive(Debug, Eq, PartialEq)]
pub struct Ipv6PacketMut<'a> {
    bytes: &'a mut [u8],
}

impl<'a> Ipv6PacketMut<'a> {
    /// Validates the fixed header, version, and any nonzero declared payload extent.
    #[inline]
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        let packet_length = validate(bytes)?;
        Ok(Self::from_validated(&mut bytes[..packet_length]))
    }

    pub(super) fn from_validated(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the eight-bit traffic class.
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        ((self.bytes[0] & 0x0f) << 4) | (self.bytes[1] >> 4)
    }

    /// Returns the 20-bit flow label.
    #[inline]
    pub fn flow_label(&self) -> u32 {
        (u32::from(self.bytes[1] & 0x0f) << 16)
            | (u32::from(self.bytes[2]) << 8)
            | u32::from(self.bytes[3])
    }

    /// Interprets the Payload Length field without resolving Jumbo Payload options.
    #[inline]
    pub fn payload_length(&self) -> Ipv6PayloadLength {
        match self.raw_payload_length() {
            0 => Ipv6PayloadLength::Unspecified,
            value => Ipv6PayloadLength::Declared(value),
        }
    }

    /// Returns the raw 16-bit Payload Length field.
    #[inline]
    pub fn raw_payload_length(&self) -> u16 {
        u16::from_be_bytes(self.bytes[4..6].try_into().expect("validated IPv6 header"))
    }

    /// Returns the Next Header value, preserving unknown values.
    #[inline]
    pub fn next_header(&self) -> Ipv6NextHeader {
        Ipv6NextHeader::new(self.bytes[6])
    }

    /// Returns the hop limit.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.bytes[7]
    }

    /// Returns the source address.
    #[inline]
    pub fn source(&self) -> Ipv6Address {
        Ipv6Address::new(self.bytes[8..24].try_into().expect("validated IPv6 header"))
    }

    /// Returns the destination address.
    #[inline]
    pub fn destination(&self) -> Ipv6Address {
        Ipv6Address::new(
            self.bytes[24..40]
                .try_into()
                .expect("validated IPv6 header"),
        )
    }

    /// Returns bytes after the fixed header, with zero-field ambiguity as documented on `Ipv6Packet`.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[HEADER_LENGTH..]
    }

    /// Returns bytes after the fixed header mutably.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[HEADER_LENGTH..]
    }

    /// Returns all represented bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Returns all represented bytes mutably.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }

    /// Replaces the traffic class while preserving version and flow-label bits.
    #[inline]
    pub fn set_traffic_class(&mut self, value: u8) {
        self.bytes[0] = (self.bytes[0] & 0xf0) | (value >> 4);
        self.bytes[1] = (self.bytes[1] & 0x0f) | (value << 4);
    }

    /// Replaces the flow label, or leaves the packet unchanged when it exceeds 20 bits.
    #[inline]
    pub fn set_flow_label(&mut self, value: u32) -> Result<(), Ipv6PacketBuildError> {
        if value > 0x000f_ffff {
            return Err(Ipv6PacketBuildError::FlowLabelTooLarge);
        }
        self.bytes[1] = (self.bytes[1] & 0xf0) | ((value >> 16) as u8);
        self.bytes[2] = (value >> 8) as u8;
        self.bytes[3] = value as u8;
        Ok(())
    }

    /// Replaces the Next Header value.
    #[inline]
    pub fn set_next_header(&mut self, value: Ipv6NextHeader) {
        self.bytes[6] = value.raw();
    }

    /// Replaces the hop limit.
    #[inline]
    pub fn set_hop_limit(&mut self, value: u8) {
        self.bytes[7] = value;
    }

    /// Replaces the source address.
    #[inline]
    pub fn set_source(&mut self, value: Ipv6Address) {
        self.bytes[8..24].copy_from_slice(&value.octets());
    }

    /// Replaces the destination address.
    #[inline]
    pub fn set_destination(&mut self, value: Ipv6Address) {
        self.bytes[24..40].copy_from_slice(&value.octets());
    }
}

#[inline]
fn validate(bytes: &[u8]) -> Result<usize, ParseError> {
    if bytes.len() < HEADER_LENGTH {
        return Err(ParseError::Truncated {
            minimum: HEADER_LENGTH,
            available: bytes.len(),
        });
    }
    let version = bytes[0] >> 4;
    if version != 6 {
        return Err(ParseError::InvalidVersion {
            expected: 6,
            actual: version,
        });
    }
    let payload_length = usize::from(u16::from_be_bytes(
        bytes[4..6].try_into().expect("validated IPv6 header"),
    ));
    if payload_length == 0 {
        return Ok(bytes.len());
    }
    let packet_length = HEADER_LENGTH + payload_length;
    if bytes.len() < packet_length {
        return Err(ParseError::Truncated {
            minimum: packet_length,
            available: bytes.len(),
        });
    }
    Ok(packet_length)
}

#[cfg(feature = "ethernet")]
impl<'a> EthernetFrame<'a> {
    /// Parses IPv6 only when this frame's EtherType is IPv6.
    #[inline]
    pub fn ipv6(&self) -> Result<Option<Ipv6Packet<'a>>, ParseError> {
        if self.ether_type() != EtherType::IPV6 {
            return Ok(None);
        }
        Ipv6Packet::parse(self.payload()).map(Some)
    }
}

#[cfg(feature = "ethernet")]
impl<'a> EthernetFrameMut<'a> {
    /// Parses mutable IPv6 only when this frame's EtherType is IPv6.
    #[inline]
    pub fn ipv6_mut(&mut self) -> Result<Option<Ipv6PacketMut<'_>>, ParseError> {
        if self.ether_type() != EtherType::IPV6 {
            return Ok(None);
        }
        Ipv6PacketMut::parse(self.payload_mut()).map(Some)
    }
}
