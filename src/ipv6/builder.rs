use core::fmt;

use super::address::Ipv6Address;
use super::layout::{
    HEADER_LENGTH, Ipv6AddressRepr, Ipv6PacketLayoutBuilder, Ipv6PacketLayoutWriteError,
};
use super::next_header::Ipv6NextHeader;
use super::packet::Ipv6PacketMut;

/// Failure while validating an IPv6 builder request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6PacketBuildError {
    /// No Next Header value was supplied.
    MissingNextHeader,
    /// No hop limit was supplied.
    MissingHopLimit,
    /// No source address was supplied.
    MissingSource,
    /// No destination address was supplied.
    MissingDestination,
    /// The flow label exceeds its 20-bit field.
    FlowLabelTooLarge,
    /// The payload exceeds the base header's 16-bit Payload Length field.
    PayloadLengthTooLarge,
    /// The caller buffer cannot hold the base header and declared payload.
    BufferTooShort {
        /// Required packet length.
        required: usize,
        /// Available buffer length.
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
    /// The validated packet could not be represented by the IPv6 layout.
    InvalidRepresentation,
}

impl fmt::Display for Ipv6PacketBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingNextHeader => formatter.write_str("missing IPv6 Next Header value"),
            Self::MissingHopLimit => formatter.write_str("missing IPv6 hop limit"),
            Self::MissingSource => formatter.write_str("missing IPv6 source address"),
            Self::MissingDestination => formatter.write_str("missing IPv6 destination address"),
            Self::FlowLabelTooLarge => formatter.write_str("IPv6 flow label exceeds 20 bits"),
            Self::PayloadLengthTooLarge => {
                formatter.write_str("IPv6 payload length exceeds 65535 octets")
            }
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                formatter,
                "IPv6 buffer is too short: need {required} bytes, have {available}"
            ),
            Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "IPv6 field {field} encoding: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidRepresentation => {
                formatter.write_str("validated IPv6 packet could not be represented")
            }
        }
    }
}
impl core::error::Error for Ipv6PacketBuildError {}

fn representation_error(error: Ipv6PacketLayoutWriteError) -> Ipv6PacketBuildError {
    match error {
        Ipv6PacketLayoutWriteError::FieldFirstWord(error)
        | Ipv6PacketLayoutWriteError::FieldPayloadLength(error)
        | Ipv6PacketLayoutWriteError::FieldNextHeader(error)
        | Ipv6PacketLayoutWriteError::FieldHopLimit(error)
        | Ipv6PacketLayoutWriteError::FieldSource(error)
        | Ipv6PacketLayoutWriteError::FieldDestination(error) => match error {},
        Ipv6PacketLayoutWriteError::InvalidPlanLength {
            field,
            expected,
            actual,
        } => Ipv6PacketBuildError::InvalidFieldEncoding {
            field,
            expected,
            actual,
        },
        Ipv6PacketLayoutWriteError::MissingContext { .. }
        | Ipv6PacketLayoutWriteError::InvalidCodecWidth { .. }
        | Ipv6PacketLayoutWriteError::InvalidRangeSource { .. }
        | Ipv6PacketLayoutWriteError::ConflictingRangeSources { .. }
        | Ipv6PacketLayoutWriteError::InvalidPrefixPlanLength { .. }
        | Ipv6PacketLayoutWriteError::InvalidLayoutExtent { .. }
        | Ipv6PacketLayoutWriteError::OutputTooShort { .. }
        | Ipv6PacketLayoutWriteError::MissingField { .. } => {
            Ipv6PacketBuildError::InvalidRepresentation
        }
    }
}

/// Builds an RFC 8200 base header in a caller-provided packet buffer.
///
/// The builder validates every field and capacity before writing. It writes only the
/// 40-octet base header; declared payload bytes and trailing capacity remain unchanged.
pub struct Ipv6PacketBuilder<'buffer> {
    buffer: &'buffer mut [u8],
    payload_length: usize,
    next_header: Option<Ipv6NextHeader>,
    hop_limit: Option<u8>,
    source: Option<Ipv6Address>,
    destination: Option<Ipv6Address>,
    traffic_class: u8,
    flow_label: u32,
}

impl<'buffer> Ipv6PacketBuilder<'buffer> {
    /// Starts a builder for an ordinary payload of `payload_length` octets.
    ///
    /// A zero length produces an ordinary zero Payload Length field and no Jumbo Payload option.
    #[inline]
    pub fn new(buffer: &'buffer mut [u8], payload_length: usize) -> Self {
        Self {
            buffer,
            payload_length,
            next_header: None,
            hop_limit: None,
            source: None,
            destination: None,
            traffic_class: 0,
            flow_label: 0,
        }
    }

    /// Supplies the Next Header field.
    #[inline]
    pub fn next_header(mut self, value: Ipv6NextHeader) -> Self {
        self.next_header = Some(value);
        self
    }

    /// Supplies the hop limit.
    #[inline]
    pub fn hop_limit(mut self, value: u8) -> Self {
        self.hop_limit = Some(value);
        self
    }

    /// Supplies the source address.
    #[inline]
    pub fn source(mut self, value: Ipv6Address) -> Self {
        self.source = Some(value);
        self
    }

    /// Supplies the destination address.
    #[inline]
    pub fn destination(mut self, value: Ipv6Address) -> Self {
        self.destination = Some(value);
        self
    }

    /// Supplies the traffic class.
    #[inline]
    pub fn traffic_class(mut self, value: u8) -> Self {
        self.traffic_class = value;
        self
    }

    /// Supplies the 20-bit flow label.
    #[inline]
    pub fn flow_label(mut self, value: u32) -> Self {
        self.flow_label = value;
        self
    }

    /// Validates the request and writes the RFC 8200 base header.
    #[inline]
    pub fn build(self) -> Result<Ipv6PacketMut<'buffer>, Ipv6PacketBuildError> {
        let next_header = self
            .next_header
            .ok_or(Ipv6PacketBuildError::MissingNextHeader)?;
        let hop_limit = self
            .hop_limit
            .ok_or(Ipv6PacketBuildError::MissingHopLimit)?;
        let source = self.source.ok_or(Ipv6PacketBuildError::MissingSource)?;
        let destination = self
            .destination
            .ok_or(Ipv6PacketBuildError::MissingDestination)?;
        if self.flow_label > 0x000f_ffff {
            return Err(Ipv6PacketBuildError::FlowLabelTooLarge);
        }
        let payload_length = u16::try_from(self.payload_length)
            .map_err(|_| Ipv6PacketBuildError::PayloadLengthTooLarge)?;
        let packet_length = HEADER_LENGTH + usize::from(payload_length);
        if self.buffer.len() < packet_length {
            return Err(Ipv6PacketBuildError::BufferTooShort {
                required: packet_length,
                available: self.buffer.len(),
            });
        }

        let first_word = (6_u32 << 28) | (u32::from(self.traffic_class) << 20) | self.flow_label;
        let (layout, _) = Ipv6PacketLayoutBuilder::new()
            .first_word(first_word)
            .payload_length(payload_length)
            .next_header(next_header.raw())
            .hop_limit(hop_limit)
            .source(Ipv6AddressRepr::from_address(source))
            .destination(Ipv6AddressRepr::from_address(destination))
            .payload_existing(self.payload_length)
            .build_into(&mut self.buffer[..packet_length])
            .map_err(representation_error)?;
        Ok(Ipv6PacketMut::from_layout(layout))
    }
}
