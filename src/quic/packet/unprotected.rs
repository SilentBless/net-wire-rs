//! Checked overlays for caller-unprotected QUIC packet headers.
//!
//! These views only associate externally unmasked header material with accepted protected packet
//! structure. They do not apply header protection, authenticate packets, decrypt payloads, or
//! reconstruct full packet numbers.

use super::super::QuicUnprotectedHeaderError;
use super::{QuicProtectedLongPacket, QuicShortHeader};

const LONG_PRESERVED_MASK: u8 = 0xf0;
const SHORT_PRESERVED_MASK: u8 = 0xe0;

/// The encoded width of a QUIC truncated packet number.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuicPacketNumberLen {
    /// A one-byte truncated packet number.
    One,
    /// A two-byte truncated packet number.
    Two,
    /// A three-byte truncated packet number.
    Three,
    /// A four-byte truncated packet number.
    Four,
}

impl QuicPacketNumberLen {
    /// Returns the encoded packet-number width in bytes.
    pub const fn byte_len(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
            Self::Four => 4,
        }
    }

    const fn from_first_byte(first_byte: u8) -> Self {
        match first_byte & 0x03 {
            0 => Self::One,
            1 => Self::Two,
            2 => Self::Three,
            _ => Self::Four,
        }
    }
}

/// Exact caller-supplied bytes of a truncated QUIC packet number.
///
/// This does not reconstruct a full packet number from an expected packet number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicTruncatedPacketNumber<'a> {
    bytes: &'a [u8],
    encoded_len: QuicPacketNumberLen,
}

impl<'a> QuicTruncatedPacketNumber<'a> {
    const fn new(bytes: &'a [u8], encoded_len: QuicPacketNumberLen) -> Self {
        Self { bytes, encoded_len }
    }

    /// Returns the exact caller-supplied unprotected packet-number bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the packet number's encoded width.
    pub const fn encoded_len(self) -> QuicPacketNumberLen {
        self.encoded_len
    }

    /// Returns the big-endian truncated packet-number value.
    pub fn value(self) -> u32 {
        self.bytes
            .iter()
            .fold(0, |value, &byte| (value << 8) | u32::from(byte))
    }
}

/// A checked caller-unprotected overlay of an accepted QUIC v1 or v2 protected long packet.
///
/// The supplied packet-number bytes may be external unmasking output in separate storage. This
/// view verifies only their width and physical capacity in the protected packet; it neither
/// authenticates the bytes nor requires them to alias the protected packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicUnprotectedLongHeader<'packet, 'unprotected> {
    protected_packet: QuicProtectedLongPacket<'packet>,
    unprotected_first_byte: u8,
    packet_number: QuicTruncatedPacketNumber<'unprotected>,
}

impl<'packet, 'unprotected> QuicUnprotectedLongHeader<'packet, 'unprotected> {
    /// Associates externally unmasked long-header material with an accepted protected packet.
    ///
    /// This validates preserved first-byte bits, supplied packet-number width, and physical
    /// packet-number capacity in that order. It performs no cryptographic operation.
    pub fn new(
        protected_packet: QuicProtectedLongPacket<'packet>,
        unprotected_first_byte: u8,
        unprotected_packet_number: &'unprotected [u8],
    ) -> Result<Self, QuicUnprotectedHeaderError> {
        validate(
            protected_packet.header().first_byte(),
            unprotected_first_byte,
            LONG_PRESERVED_MASK,
            unprotected_packet_number,
            protected_packet.protected_remainder().len(),
        )?;
        Ok(Self {
            protected_packet,
            unprotected_first_byte,
            packet_number: QuicTruncatedPacketNumber::new(
                unprotected_packet_number,
                QuicPacketNumberLen::from_first_byte(unprotected_first_byte),
            ),
        })
    }

    /// Returns the accepted protected long packet.
    pub const fn protected_packet(self) -> QuicProtectedLongPacket<'packet> {
        self.protected_packet
    }

    /// Returns the caller-supplied unprotected first byte.
    pub const fn unprotected_first_byte(self) -> u8 {
        self.unprotected_first_byte
    }

    /// Returns the exact caller-supplied truncated packet number.
    pub const fn packet_number(self) -> QuicTruncatedPacketNumber<'unprotected> {
        self.packet_number
    }

    /// Returns the raw unprotected long-header reserved bits without validating them.
    pub const fn raw_reserved_bits(self) -> u8 {
        (self.unprotected_first_byte >> 2) & 0x03
    }
}

/// A checked caller-unprotected overlay of an accepted QUIC short header.
///
/// This is caller-unprotected structure, not authentication or semantic validation. The supplied
/// packet-number bytes may be external unmasking output in separate storage and need not alias
/// the protected packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicUnprotectedShortHeader<'packet, 'unprotected> {
    protected_packet: QuicShortHeader<'packet>,
    unprotected_first_byte: u8,
    packet_number: QuicTruncatedPacketNumber<'unprotected>,
}

impl<'packet, 'unprotected> QuicUnprotectedShortHeader<'packet, 'unprotected> {
    /// Associates externally unmasked short-header material with an accepted protected packet.
    ///
    /// This validates preserved first-byte bits, supplied packet-number width, and physical
    /// packet-number capacity in that order. It performs no cryptographic operation.
    pub fn new(
        protected_packet: QuicShortHeader<'packet>,
        unprotected_first_byte: u8,
        unprotected_packet_number: &'unprotected [u8],
    ) -> Result<Self, QuicUnprotectedHeaderError> {
        validate(
            protected_packet.first_byte(),
            unprotected_first_byte,
            SHORT_PRESERVED_MASK,
            unprotected_packet_number,
            protected_packet.protected_remainder().len(),
        )?;
        Ok(Self {
            protected_packet,
            unprotected_first_byte,
            packet_number: QuicTruncatedPacketNumber::new(
                unprotected_packet_number,
                QuicPacketNumberLen::from_first_byte(unprotected_first_byte),
            ),
        })
    }

    /// Returns the accepted protected short packet.
    pub const fn protected_packet(self) -> QuicShortHeader<'packet> {
        self.protected_packet
    }

    /// Returns the caller-supplied unprotected first byte.
    pub const fn unprotected_first_byte(self) -> u8 {
        self.unprotected_first_byte
    }

    /// Returns the exact caller-supplied truncated packet number.
    pub const fn packet_number(self) -> QuicTruncatedPacketNumber<'unprotected> {
        self.packet_number
    }

    /// Returns the raw unprotected short-header reserved bits without validating them.
    pub const fn raw_reserved_bits(self) -> u8 {
        (self.unprotected_first_byte >> 3) & 0x03
    }

    /// Returns the raw unprotected short-header spin bit without validating it.
    pub const fn spin_bit(self) -> bool {
        self.unprotected_first_byte & 0x20 != 0
    }

    /// Returns the raw unprotected short-header key phase bit without validating it.
    pub const fn key_phase(self) -> bool {
        self.unprotected_first_byte & 0x04 != 0
    }
}

fn validate(
    protected_first_byte: u8,
    unprotected_first_byte: u8,
    preserved_mask: u8,
    unprotected_packet_number: &[u8],
    protected_remainder_len: usize,
) -> Result<(), QuicUnprotectedHeaderError> {
    if protected_first_byte & preserved_mask != unprotected_first_byte & preserved_mask {
        return Err(QuicUnprotectedHeaderError::PreservedBitsMismatch {
            protected_first_byte,
            unprotected_first_byte,
            preserved_mask,
        });
    }

    let expected = QuicPacketNumberLen::from_first_byte(unprotected_first_byte).byte_len();
    let supplied = unprotected_packet_number.len();
    if supplied != expected {
        return Err(QuicUnprotectedHeaderError::PacketNumberLengthMismatch { expected, supplied });
    }

    if protected_remainder_len < expected {
        return Err(QuicUnprotectedHeaderError::ProtectedRemainderTooShort {
            required: expected,
            available: protected_remainder_len,
        });
    }
    Ok(())
}
