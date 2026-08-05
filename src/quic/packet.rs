//! QUIC long- and short-header borrowed views.

use super::{QuicConnectionId, QuicLongPacketType, QuicPacketParseError, QuicVersion};

mod datagram;
mod long;
mod terminal;
mod unprotected;

pub use datagram::{QuicDatagram, QuicPacket, QuicPackets, QuicUnknownLongPacket};
pub use long::QuicProtectedLongPacket;
pub use terminal::{QuicRetryPacket, QuicVersionIter, QuicVersionNegotiationPacket};
pub use unprotected::{
    QuicPacketNumberLen, QuicTruncatedPacketNumber, QuicUnprotectedLongHeader,
    QuicUnprotectedShortHeader,
};

const HEADER_FORM_BIT: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
const LONG_TYPE_SHIFT: u8 = 4;
const LONG_TYPE_MASK: u8 = 0x03;

/// Caller-supplied information needed to delimit a QUIC short-header destination ID.
///
/// Short headers omit their destination connection-ID length on the wire. The context
/// therefore carries that length as a `usize`, without imposing a long-header wire-field
/// limit on the caller.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QuicShortHeaderContext {
    destination_connection_id_len: usize,
}

impl QuicShortHeaderContext {
    /// Creates context with the known short-header destination connection-ID length.
    pub const fn new(destination_connection_id_len: usize) -> Self {
        Self {
            destination_connection_id_len,
        }
    }

    /// Returns the known short-header destination connection-ID length.
    pub const fn destination_connection_id_len(self) -> usize {
        self.destination_connection_id_len
    }
}

/// A borrowed RFC 8999 invariant QUIC long-header prefix.
///
/// `as_bytes` contains only the invariant prefix structurally owned by this view.
/// The following bytes are available separately through [`Self::version_specific`] and
/// are intentionally not interpreted as a payload by this version-independent layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicLongHeader<'a> {
    bytes: &'a [u8],
    first_byte: u8,
    version: QuicVersion,
    destination_connection_id: QuicConnectionId<'a>,
    source_connection_id: QuicConnectionId<'a>,
    version_specific: &'a [u8],
}

impl<'a> QuicLongHeader<'a> {
    /// Assembles a long-header view from builder-validated wire components.
    pub(crate) const fn from_validated(
        bytes: &'a [u8],
        first_byte: u8,
        version: QuicVersion,
        destination_connection_id: QuicConnectionId<'a>,
        source_connection_id: QuicConnectionId<'a>,
        version_specific: &'a [u8],
    ) -> Self {
        Self {
            bytes,
            first_byte,
            version,
            destination_connection_id,
            source_connection_id,
            version_specific,
        }
    }

    /// Parses exactly the RFC 8999 invariant long-header prefix.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QuicPacketParseError> {
        let first_byte = first_byte(bytes)?;
        if first_byte & HEADER_FORM_BIT == 0 {
            return Err(QuicPacketParseError::WrongHeaderForm {
                expected_long: true,
                first_byte,
            });
        }

        require(bytes, 5)?;
        let version =
            QuicVersion::new(u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]));
        require(bytes, 6)?;
        let destination_len = usize::from(bytes[5]);
        let destination_end = field_end(6, destination_len)?;
        require(bytes, destination_end)?;
        let destination_connection_id = QuicConnectionId::new(&bytes[6..destination_end]);

        let source_len_offset = destination_end;
        let source_start = field_end(source_len_offset, 1)?;
        require(bytes, source_start)?;
        let source_len = usize::from(bytes[source_len_offset]);
        let source_end = field_end(source_start, source_len)?;
        require(bytes, source_end)?;

        Ok(Self {
            bytes: &bytes[..source_end],
            first_byte,
            version,
            destination_connection_id,
            source_connection_id: QuicConnectionId::new(&bytes[source_start..source_end]),
            version_specific: &bytes[source_end..],
        })
    }

    /// Returns the raw first byte, including protected and version-specific bits.
    pub const fn first_byte(self) -> u8 {
        self.first_byte
    }

    /// Returns whether the raw fixed bit is set, without validating it.
    pub const fn has_fixed_bit(self) -> bool {
        self.first_byte & FIXED_BIT != 0
    }

    /// Returns the two raw long-header type bits, without assigning unknown-version semantics.
    pub const fn raw_type_bits(self) -> u8 {
        (self.first_byte >> LONG_TYPE_SHIFT) & LONG_TYPE_MASK
    }

    /// Returns the raw QUIC version value.
    pub const fn version(self) -> QuicVersion {
        self.version
    }

    /// Returns the exact destination connection ID.
    pub const fn destination_connection_id(self) -> QuicConnectionId<'a> {
        self.destination_connection_id
    }

    /// Returns the exact source connection ID.
    pub const fn source_connection_id(self) -> QuicConnectionId<'a> {
        self.source_connection_id
    }

    /// Returns the exact invariant-prefix bytes, excluding version-specific bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns all bytes after the invariant prefix without interpreting them.
    pub const fn version_specific(self) -> &'a [u8] {
        self.version_specific
    }

    /// Returns the version-aware semantic packet type for QUIC v1 or v2 only.
    pub const fn long_packet_type(self) -> Option<QuicLongPacketType> {
        QuicLongPacketType::from_raw(self.version, self.raw_type_bits())
    }
}

/// A borrowed, context-bounded QUIC short header.
///
/// Unlike [`QuicLongHeader::as_bytes`], `as_bytes` returns the complete supplied input.
/// A short header has no wire length, so this view consumes the datagram remainder after
/// the caller-context destination connection ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicShortHeader<'a> {
    bytes: &'a [u8],
    first_byte: u8,
    destination_connection_id: QuicConnectionId<'a>,
    protected_remainder: &'a [u8],
}

impl<'a> QuicShortHeader<'a> {
    /// Assembles a short-header view from builder-validated wire components.
    pub(crate) const fn from_validated(
        bytes: &'a [u8],
        first_byte: u8,
        destination_connection_id: QuicConnectionId<'a>,
        protected_remainder: &'a [u8],
    ) -> Self {
        Self {
            bytes,
            first_byte,
            destination_connection_id,
            protected_remainder,
        }
    }

    /// Parses a short header using caller-supplied destination connection-ID length context.
    pub fn parse(
        bytes: &'a [u8],
        context: QuicShortHeaderContext,
    ) -> Result<Self, QuicPacketParseError> {
        let first_byte = first_byte(bytes)?;
        if first_byte & HEADER_FORM_BIT != 0 {
            return Err(QuicPacketParseError::WrongHeaderForm {
                expected_long: false,
                first_byte,
            });
        }

        let destination_end = field_end(1, context.destination_connection_id_len())?;
        require(bytes, destination_end)?;
        Ok(Self {
            bytes,
            first_byte,
            destination_connection_id: QuicConnectionId::new(&bytes[1..destination_end]),
            protected_remainder: &bytes[destination_end..],
        })
    }

    /// Returns the raw first byte, whose low bits remain protected and uninterpreted.
    pub const fn first_byte(self) -> u8 {
        self.first_byte
    }

    /// Returns whether the raw fixed bit is set, without validating it.
    pub const fn has_fixed_bit(self) -> bool {
        self.first_byte & FIXED_BIT != 0
    }

    /// Returns the exact destination connection ID delimited by the supplied context.
    pub const fn destination_connection_id(self) -> QuicConnectionId<'a> {
        self.destination_connection_id
    }

    /// Returns all bytes after the context-bounded destination connection ID as opaque bytes.
    pub const fn protected_remainder(self) -> &'a [u8] {
        self.protected_remainder
    }

    /// Returns the complete supplied short-packet slice.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

fn first_byte(bytes: &[u8]) -> Result<u8, QuicPacketParseError> {
    bytes
        .first()
        .copied()
        .ok_or(QuicPacketParseError::Incomplete {
            required: 1,
            available: 0,
        })
}

fn field_end(offset: usize, length: usize) -> Result<usize, QuicPacketParseError> {
    offset
        .checked_add(length)
        .ok_or(QuicPacketParseError::LengthOverflow { offset, length })
}

fn require(bytes: &[u8], required: usize) -> Result<(), QuicPacketParseError> {
    if bytes.len() < required {
        return Err(QuicPacketParseError::Incomplete {
            required,
            available: bytes.len(),
        });
    }
    Ok(())
}
