use core::fmt;

use super::address::Ipv6Address;
use super::layout::{
    HEADER_LENGTH, Ipv6AddressRepr, Ipv6PacketLayout, Ipv6PacketLayoutMutationError,
    Ipv6PacketLayoutViewMut,
};
use super::next_header::Ipv6NextHeader;
use crate::error::ParseError;

/// Meaning of the IPv6 base header's 16-bit Payload Length field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6PayloadLength {
    /// A nonzero payload length declared directly by the base header.
    Declared(u16),
    /// A zero field whose nonempty payload extent cannot be resolved from the base header alone.
    ///
    /// An ordinary empty payload also encodes zero. A nonempty tail may include a Jumbo Payload
    /// option or lower-layer padding and cannot be resolved at this parsing layer.
    Unspecified,
}

/// An IPv6 field mutation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6PacketMutationError {
    /// The flow label exceeds its 20-bit field.
    FlowLabelTooLarge,
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

impl fmt::Display for Ipv6PacketMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FlowLabelTooLarge => formatter.write_str("IPv6 flow label exceeds 20 bits"),
            Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "IPv6 field {field} plan length: expected {expected} bytes, got {actual}"
            ),
        }
    }
}
impl core::error::Error for Ipv6PacketMutationError {}

fn mutation_error(error: Ipv6PacketLayoutMutationError) -> Ipv6PacketMutationError {
    match error {
        Ipv6PacketLayoutMutationError::FieldFirstWord(error)
        | Ipv6PacketLayoutMutationError::FieldPayloadLength(error)
        | Ipv6PacketLayoutMutationError::FieldNextHeader(error)
        | Ipv6PacketLayoutMutationError::FieldHopLimit(error)
        | Ipv6PacketLayoutMutationError::FieldSource(error)
        | Ipv6PacketLayoutMutationError::FieldDestination(error) => match error {},
        Ipv6PacketLayoutMutationError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => Ipv6PacketMutationError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
    }
}

/// A structurally validated immutable IPv6 base-header view.
///
/// Parsing implements the fixed header from RFC 8200 section 3. It does not traverse extension
/// headers. A nonzero Payload Length bounds the view exactly; a zero field retains every supplied
/// trailing byte as an unresolved tail; zero with no trailing bytes is an ordinary empty payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv6Packet<'a> {
    layout: Ipv6PacketLayout<'a>,
}

impl<'a> Ipv6Packet<'a> {
    /// Validates the fixed header, version, and any nonzero declared payload extent.
    #[inline]
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let packet_length = validate(bytes)?;
        let layout = Ipv6PacketLayout::view(&bytes[..packet_length])
            .without_trailing()
            .map_err(|_| ParseError::Truncated {
                minimum: packet_length,
                available: bytes.len(),
            })?;
        Ok(Self { layout })
    }

    /// Returns the eight-bit traffic class.
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        self.layout.traffic_class() as u8
    }

    /// Returns the 20-bit flow label.
    #[inline]
    pub fn flow_label(&self) -> u32 {
        self.layout.flow_label()
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
        self.layout.payload_length()
    }

    /// Returns the Next Header value, preserving unknown values.
    #[inline]
    pub fn next_header(&self) -> Ipv6NextHeader {
        Ipv6NextHeader::new(self.layout.next_header())
    }

    /// Returns the hop limit.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.layout.hop_limit()
    }

    /// Returns the source address.
    #[inline]
    pub fn source(&self) -> Ipv6Address {
        self.layout.source().into_address()
    }

    /// Returns the destination address.
    #[inline]
    pub fn destination(&self) -> Ipv6Address {
        self.layout.destination().into_address()
    }

    /// Returns bytes after the fixed header.
    ///
    /// For a nonzero Payload Length these are exactly the declared payload. For a zero field they
    /// are an unresolved nonempty tail that may be lower-layer padding or Jumbo Payload content;
    /// an empty tail is an ordinary empty payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        self.layout.payload()
    }

    /// Returns all bytes represented by this base-header view.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.layout.as_bytes()
    }
}

/// A structurally validated mutable IPv6 base-header view.
pub struct Ipv6PacketMut<'a> {
    layout: Ipv6PacketLayoutViewMut<'a>,
}

impl fmt::Debug for Ipv6PacketMut<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ipv6PacketMut")
            .field("bytes", &self.as_bytes())
            .finish()
    }
}

impl PartialEq for Ipv6PacketMut<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Ipv6PacketMut<'_> {}

impl<'a> Ipv6PacketMut<'a> {
    /// Validates the fixed header, version, and any nonzero declared payload extent.
    #[inline]
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, ParseError> {
        let packet_length = validate(bytes)?;
        let available = bytes.len();
        Self::from_exact(&mut bytes[..packet_length]).map_err(|_| ParseError::Truncated {
            minimum: packet_length,
            available,
        })
    }

    pub(super) fn from_exact(bytes: &'a mut [u8]) -> Result<Self, Ipv6PacketRepresentationError> {
        let layout = Ipv6PacketLayoutViewMut::parse_exact_mut(bytes)
            .map_err(|_| Ipv6PacketRepresentationError::InvalidLayout)?;
        Ok(Self { layout })
    }

    pub(super) const fn from_layout(layout: Ipv6PacketLayoutViewMut<'a>) -> Self {
        Self { layout }
    }

    /// Returns the eight-bit traffic class.
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        self.layout.traffic_class() as u8
    }

    /// Returns the 20-bit flow label.
    #[inline]
    pub fn flow_label(&self) -> u32 {
        self.layout.flow_label()
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
        self.layout.payload_length()
    }

    /// Returns the Next Header value, preserving unknown values.
    #[inline]
    pub fn next_header(&self) -> Ipv6NextHeader {
        Ipv6NextHeader::new(self.layout.next_header())
    }

    /// Returns the hop limit.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.layout.hop_limit()
    }

    /// Returns the source address.
    #[inline]
    pub fn source(&self) -> Ipv6Address {
        self.layout.source().into_address()
    }

    /// Returns the destination address.
    #[inline]
    pub fn destination(&self) -> Ipv6Address {
        self.layout.destination().into_address()
    }

    /// Returns bytes after the fixed header, with zero-field ambiguity as documented on `Ipv6Packet`.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.layout.payload()
    }

    /// Returns bytes after the fixed header mutably.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.layout.payload_mut()
    }

    /// Returns all represented bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.layout.as_bytes()
    }

    /// Replaces the traffic class while preserving version and flow-label bits.
    #[inline]
    pub fn set_traffic_class(&mut self, value: u8) -> Result<(), Ipv6PacketMutationError> {
        let first_word = (self.layout.first_word() & !(0xff_u32 << 20)) | (u32::from(value) << 20);
        self.layout
            .set_first_word(first_word)
            .map_err(mutation_error)
    }

    /// Replaces the flow label.
    #[inline]
    pub fn set_flow_label(&mut self, value: u32) -> Result<(), Ipv6PacketMutationError> {
        if value > 0x000f_ffff {
            return Err(Ipv6PacketMutationError::FlowLabelTooLarge);
        }
        let first_word = (self.layout.first_word() & !0x000f_ffff) | value;
        self.layout
            .set_first_word(first_word)
            .map_err(mutation_error)
    }

    /// Replaces the Next Header value.
    #[inline]
    pub fn set_next_header(
        &mut self,
        value: Ipv6NextHeader,
    ) -> Result<(), Ipv6PacketMutationError> {
        self.layout
            .set_next_header(value.raw())
            .map_err(mutation_error)
    }

    /// Replaces the hop limit.
    #[inline]
    pub fn set_hop_limit(&mut self, value: u8) -> Result<(), Ipv6PacketMutationError> {
        self.layout.set_hop_limit(value).map_err(mutation_error)
    }

    /// Replaces the source address.
    #[inline]
    pub fn set_source(&mut self, value: Ipv6Address) -> Result<(), Ipv6PacketMutationError> {
        self.layout
            .set_source(Ipv6AddressRepr::from_address(value))
            .map_err(mutation_error)
    }

    /// Replaces the destination address.
    #[inline]
    pub fn set_destination(&mut self, value: Ipv6Address) -> Result<(), Ipv6PacketMutationError> {
        self.layout
            .set_destination(Ipv6AddressRepr::from_address(value))
            .map_err(mutation_error)
    }
}

/// Internal IPv6 representation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Ipv6PacketRepresentationError {
    /// A generated representation unexpectedly rejected a prevalidated layout.
    InvalidLayout,
}

impl fmt::Display for Ipv6PacketRepresentationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("generated IPv6 representation rejected a prevalidated layout")
    }
}
impl core::error::Error for Ipv6PacketRepresentationError {}

#[inline]
fn validate(bytes: &[u8]) -> Result<usize, ParseError> {
    if bytes.len() < HEADER_LENGTH {
        return Err(ParseError::Truncated {
            minimum: HEADER_LENGTH,
            available: bytes.len(),
        });
    }
    let layout = Ipv6PacketLayout::view(bytes)
        .without_trailing()
        .map_err(|_| ParseError::Truncated {
            minimum: HEADER_LENGTH,
            available: bytes.len(),
        })?;
    let version = layout.version();
    if version != 6 {
        return Err(ParseError::InvalidVersion {
            expected: 6,
            actual: version as u8,
        });
    }
    let payload_length = usize::from(layout.payload_length());
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
