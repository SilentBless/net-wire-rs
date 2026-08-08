//! Allocation-free parsing and partitioning of complete QUIC UDP datagrams.

use core::iter::FusedIterator;

use super::header::{
    QuicLongHeader, QuicLongPacketType, QuicShortHeader, QuicShortHeaderContext, QuicVersion,
};
use super::long::QuicProtectedLongPacket;
use super::parse::QuicPacketParseError;
use super::terminal::{QuicRetryPacket, QuicVersionNegotiationPacket};

/// A borrowed unknown-version QUIC long packet occupying the complete datagram remainder.
///
/// QUIC does not define a version-specific packet boundary for an unknown version. This view
/// therefore owns the complete datagram remainder and makes no version-specific claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicUnknownLongPacket<'a> {
    header: QuicLongHeader<'a>,
    bytes: &'a [u8],
}

impl<'a> QuicUnknownLongPacket<'a> {
    /// Returns the exact parsed invariant long-header prefix.
    pub const fn header(self) -> QuicLongHeader<'a> {
        self.header
    }

    /// Returns the complete datagram remainder, including the invariant header.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

/// One borrowed QUIC packet partitioned from a supplied UDP datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicPacket<'a> {
    /// A length-delimited v1 or v2 protected Initial, 0-RTT, or Handshake packet.
    ProtectedLong(QuicProtectedLongPacket<'a>),
    /// A Version Negotiation packet, which consumes the datagram remainder.
    VersionNegotiation(QuicVersionNegotiationPacket<'a>),
    /// A Retry packet, which consumes the datagram remainder.
    Retry(QuicRetryPacket<'a>),
    /// A short-header packet, which consumes the datagram remainder.
    Short(QuicShortHeader<'a>),
    /// An unknown nonzero-version long packet occupying the complete datagram remainder.
    ///
    /// QUIC does not define a version-specific packet boundary for an unknown version, so
    /// iteration stops here rather than guessing a suffix boundary. [`Self::as_bytes`] returns
    /// the complete remaining datagram for this variant.
    UnknownLong(QuicUnknownLongPacket<'a>),
}

impl<'a> QuicPacket<'a> {
    /// Returns the exact complete packet bytes represented by this variant.
    pub const fn as_bytes(self) -> &'a [u8] {
        match self {
            Self::ProtectedLong(packet) => packet.as_bytes(),
            Self::VersionNegotiation(packet) => packet.as_bytes(),
            Self::Retry(packet) => packet.as_bytes(),
            Self::Short(packet) => packet.as_bytes(),
            Self::UnknownLong(packet) => packet.as_bytes(),
        }
    }

    /// Returns the raw first byte.
    pub const fn first_byte(self) -> u8 {
        match self {
            Self::ProtectedLong(packet) => packet.header().first_byte(),
            Self::VersionNegotiation(packet) => packet.header().first_byte(),
            Self::Retry(packet) => packet.header().first_byte(),
            Self::Short(packet) => packet.first_byte(),
            Self::UnknownLong(packet) => packet.header().first_byte(),
        }
    }

    /// Returns whether this packet uses the long-header form.
    pub const fn is_long_header(self) -> bool {
        !matches!(self, Self::Short(_))
    }
}

/// A validated borrowed QUIC UDP datagram.
///
/// Construction performs a complete partitioning pass. Consequently, successful construction
/// means every byte belongs to a structurally recognized packet or to a terminal opaque
/// unknown-version long packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicDatagram<'a> {
    bytes: &'a [u8],
    short_context: Option<QuicShortHeaderContext>,
}

impl<'a> QuicDatagram<'a> {
    /// Validates and borrows one complete QUIC UDP datagram.
    pub fn parse(
        bytes: &'a [u8],
        short_context: Option<QuicShortHeaderContext>,
    ) -> Result<Self, QuicPacketParseError> {
        if bytes.is_empty() {
            return Err(QuicPacketParseError::EmptyDatagram);
        }

        for packet in QuicPackets::new(bytes, short_context) {
            packet?;
        }
        Ok(Self {
            bytes,
            short_context,
        })
    }

    /// Returns the exact supplied UDP datagram bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns a new iterator over this datagram's validated packet partitions.
    pub const fn packets(self) -> QuicPackets<'a> {
        QuicPackets::new(self.bytes, self.short_context)
    }
}

/// A fallible, fused iterator that partitions one QUIC UDP datagram.
///
/// On an error, this iterator permanently exhausts itself to avoid resuming after an uncertain
/// packet boundary.
#[derive(Clone, Debug)]
pub struct QuicPackets<'a> {
    remaining: &'a [u8],
    short_context: Option<QuicShortHeaderContext>,
    exhausted: bool,
}

impl<'a> QuicPackets<'a> {
    /// Creates an iterator that partitions one supplied UDP datagram as it is consumed.
    ///
    /// Unlike [`QuicDatagram::parse`], this constructor does not validate before iteration.
    pub const fn new(bytes: &'a [u8], short_context: Option<QuicShortHeaderContext>) -> Self {
        Self {
            remaining: bytes,
            short_context,
            exhausted: false,
        }
    }
}

impl<'a> Iterator for QuicPackets<'a> {
    type Item = Result<QuicPacket<'a>, QuicPacketParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted || self.remaining.is_empty() {
            self.exhausted = true;
            return None;
        }

        let bytes = self.remaining;
        let result = if bytes[0] & 0x80 == 0 {
            let context = match self.short_context {
                Some(context) => context,
                None => return self.fail(QuicPacketParseError::ShortHeaderContextRequired),
            };
            QuicShortHeader::parse(bytes, context).map(QuicPacket::Short)
        } else {
            match QuicLongHeader::parse(bytes) {
                Err(error) => Err(error),
                Ok(header) if header.version() == QuicVersion::NEGOTIATION => {
                    QuicVersionNegotiationPacket::parse(bytes).map(QuicPacket::VersionNegotiation)
                }
                Ok(header) => match header.long_packet_type() {
                    Some(QuicLongPacketType::Retry) => {
                        QuicRetryPacket::parse(bytes).map(QuicPacket::Retry)
                    }
                    Some(_) => QuicProtectedLongPacket::parse(bytes).map(|(packet, suffix)| {
                        self.remaining = suffix;
                        QuicPacket::ProtectedLong(packet)
                    }),
                    None => Ok(QuicPacket::UnknownLong(QuicUnknownLongPacket {
                        header,
                        bytes,
                    })),
                },
            }
        };

        match result {
            Ok(
                packet @ (QuicPacket::Short(_)
                | QuicPacket::VersionNegotiation(_)
                | QuicPacket::Retry(_)
                | QuicPacket::UnknownLong(_)),
            ) => {
                self.remaining = &[];
                self.exhausted = true;
                Some(Ok(packet))
            }
            Ok(packet) => Some(Ok(packet)),
            Err(error) => self.fail(error),
        }
    }
}

impl FusedIterator for QuicPackets<'_> {}

impl<'a> QuicPackets<'a> {
    fn fail(
        &mut self,
        error: QuicPacketParseError,
    ) -> Option<Result<QuicPacket<'a>, QuicPacketParseError>> {
        self.remaining = &[];
        self.exhausted = true;
        Some(Err(error))
    }
}
