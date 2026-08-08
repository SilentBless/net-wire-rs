use core::fmt;

use super::address::Ipv6Address;
use super::next_header::Ipv6NextHeader;
use super::packet::{HEADER_LENGTH, Ipv6PacketMut};

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
        if self.payload_length > u16::MAX as usize {
            return Err(Ipv6PacketBuildError::PayloadLengthTooLarge);
        }
        let packet_length = HEADER_LENGTH + self.payload_length;
        if self.buffer.len() < packet_length {
            return Err(Ipv6PacketBuildError::BufferTooShort {
                required: packet_length,
                available: self.buffer.len(),
            });
        }

        let bytes = &mut self.buffer[..packet_length];
        bytes[0] = 0x60 | (self.traffic_class >> 4);
        bytes[1] = (self.traffic_class << 4) | ((self.flow_label >> 16) as u8);
        bytes[2] = (self.flow_label >> 8) as u8;
        bytes[3] = self.flow_label as u8;
        bytes[4..6].copy_from_slice(&(self.payload_length as u16).to_be_bytes());
        bytes[6] = next_header.raw();
        bytes[7] = hop_limit;
        bytes[8..24].copy_from_slice(&source.octets());
        bytes[24..40].copy_from_slice(&destination.octets());

        Ok(Ipv6PacketMut::from_validated(bytes))
    }
}
