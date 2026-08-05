//! QUIC version, connection-ID, stream-direction, and long-header packet-type scalar values.

/// Identifies whether a QUIC stream is bidirectional or unidirectional.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuicStreamDirection {
    /// A stream carrying data in both directions.
    Bidirectional,
    /// A stream carrying data in one direction.
    Unidirectional,
}

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
