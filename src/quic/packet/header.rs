//! QUIC packet-header layouts and their version and connection-ID vocabulary.

use super::layout::{QuicLongHeaderLayout, QuicLongHeaderLayoutError};
use super::parse::QuicPacketParseError;

/// An exact borrowed opaque QUIC connection ID.
///
/// This scalar deliberately does not impose QUIC versions' 20-byte connection-ID
/// limit. The invariant long-header layout carries an unsigned-byte length, and
/// unknown versions and Version Negotiation must remain representable here.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QuicConnectionId<'a>(&'a [u8]);

impl<'a> QuicConnectionId<'a> {
    /// Creates an opaque connection ID from exact wire bytes.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// Returns the exact connection-ID bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    /// Returns the connection-ID length in bytes.
    pub const fn len(self) -> usize {
        self.0.len()
    }

    /// Returns whether the connection ID is empty.
    pub const fn is_empty(self) -> bool {
        self.0.is_empty()
    }
}

/// Identifies a long-header connection-ID field.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuicConnectionIdField {
    /// The destination connection ID.
    Destination,
    /// The source connection ID.
    Source,
}

/// A raw QUIC version value, preserving unknown and reserved versions.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QuicVersion(u32);

impl QuicVersion {
    /// Version Negotiation (`0x00000000`).
    pub const NEGOTIATION: Self = Self(0);
    /// QUIC version 1 (`0x00000001`).
    pub const V1: Self = Self(1);
    /// QUIC version 2 (`0x6b3343cf`).
    pub const V2: Self = Self(0x6b33_43cf);

    /// Creates a version from its raw wire value.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw wire value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns whether this is a reserved version with the `0x?a?a?a?a` pattern.
    pub const fn is_reserved(self) -> bool {
        self.0 & 0x0f0f_0f0f == 0x0a0a_0a0a
    }
}

impl From<u32> for QuicVersion {
    fn from(raw: u32) -> Self {
        Self::new(raw)
    }
}

impl From<QuicVersion> for u32 {
    fn from(version: QuicVersion) -> Self {
        version.raw()
    }
}

/// A semantic long-header packet type for a known QUIC version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuicLongPacketType {
    /// Initial packet.
    Initial,
    /// 0-RTT packet.
    ZeroRtt,
    /// Handshake packet.
    Handshake,
    /// Retry packet.
    Retry,
}

impl QuicLongPacketType {
    /// Maps a version and its two raw long-header type bits to a semantic packet type.
    pub const fn from_raw(version: QuicVersion, raw_type: u8) -> Option<Self> {
        if raw_type > 3 {
            return None;
        }
        match version {
            QuicVersion::V1 => match raw_type {
                0 => Some(Self::Initial),
                1 => Some(Self::ZeroRtt),
                2 => Some(Self::Handshake),
                _ => Some(Self::Retry),
            },
            QuicVersion::V2 => match raw_type {
                0 => Some(Self::Retry),
                1 => Some(Self::Initial),
                2 => Some(Self::ZeroRtt),
                _ => Some(Self::Handshake),
            },
            _ => None,
        }
    }

    /// Maps this semantic packet type to its two raw long-header type bits for a version.
    pub const fn raw_type(self, version: QuicVersion) -> Option<u8> {
        match version {
            QuicVersion::V1 => match self {
                Self::Initial => Some(0),
                Self::ZeroRtt => Some(1),
                Self::Handshake => Some(2),
                Self::Retry => Some(3),
            },
            QuicVersion::V2 => match self {
                Self::Initial => Some(1),
                Self::ZeroRtt => Some(2),
                Self::Handshake => Some(3),
                Self::Retry => Some(0),
            },
            _ => None,
        }
    }
}

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
    // The generated view is the sole physical layout owner. Cached semantic values retain the
    // established const public accessors without recreating layout arithmetic.
    layout: QuicLongHeaderLayout<'a>,
    bytes: &'a [u8],
    first_byte: u8,
    version: QuicVersion,
    destination_connection_id: QuicConnectionId<'a>,
    source_connection_id: QuicConnectionId<'a>,
    version_specific: &'a [u8],
}

impl<'a> QuicLongHeader<'a> {
    /// Parses exactly the RFC 8999 invariant long-header prefix.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QuicPacketParseError> {
        let first_byte = first_byte(bytes)?;
        if first_byte & HEADER_FORM_BIT == 0 {
            return Err(QuicPacketParseError::WrongHeaderForm {
                expected_long: true,
                first_byte,
            });
        }
        let (layout, version_specific) = QuicLongHeaderLayout::view(bytes)
            .with_remainder()
            .map_err(|error| layout_error(error, bytes.len()))?;
        Ok(Self {
            bytes: layout.as_bytes(),
            first_byte: layout.first_byte(),
            version: layout.version(),
            destination_connection_id: QuicConnectionId::new(layout.destination_connection_id()),
            source_connection_id: QuicConnectionId::new(layout.source_connection_id()),
            layout,
            version_specific,
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

fn layout_error(error: QuicLongHeaderLayoutError, input_len: usize) -> QuicPacketParseError {
    match error {
        QuicLongHeaderLayoutError::InputTooShort {
            expected,
            available,
            ..
        } => QuicPacketParseError::Incomplete {
            required: input_len - available + expected,
            available: input_len,
        },
        QuicLongHeaderLayoutError::TrailingBytes { .. }
        | QuicLongHeaderLayoutError::InvalidCodecWidth { .. }
        | QuicLongHeaderLayoutError::InvalidRangeSource { .. }
        | QuicLongHeaderLayoutError::RangeEndBeforeStart { .. }
        | QuicLongHeaderLayoutError::InvalidPrefixExtent { .. } => {
            QuicPacketParseError::InvalidRepresentation
        }
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
