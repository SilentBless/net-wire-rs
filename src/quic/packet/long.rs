//! Version-aware bounded views of protected QUIC long packets.

use super::super::{
    QuicConnectionIdField, QuicLongHeader, QuicLongPacketType, QuicPacketParseError, QuicVarInt,
    QuicVarIntParseError, QuicVersion,
};

/// A borrowed QUIC v1 or v2 protected Initial, 0-RTT, or Handshake packet.
///
/// This view bounds the packet using its unprotected length field but deliberately leaves packet
/// number length, protected payload, and all cryptographic interpretation opaque.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicProtectedLongPacket<'a> {
    bytes: &'a [u8],
    header: QuicLongHeader<'a>,
    packet_type: QuicLongPacketType,
    token_length: Option<QuicVarInt<'a>>,
    token: Option<&'a [u8]>,
    length: QuicVarInt<'a>,
    packet_number_offset: usize,
    protected_remainder: &'a [u8],
}

impl<'a> QuicProtectedLongPacket<'a> {
    /// Assembles a protected long-packet view from builder-validated wire components.
    pub(crate) const fn from_validated(
        bytes: &'a [u8],
        header: QuicLongHeader<'a>,
        packet_type: QuicLongPacketType,
        token_fields: Option<(QuicVarInt<'a>, &'a [u8])>,
        length: QuicVarInt<'a>,
        packet_number_offset: usize,
        protected_remainder: &'a [u8],
    ) -> Self {
        let (token_length, token) = match token_fields {
            Some((token_length, token)) => (Some(token_length), Some(token)),
            None => (None, None),
        };
        Self {
            bytes,
            header,
            packet_type,
            token_length,
            token,
            length,
            packet_number_offset,
            protected_remainder,
        }
    }

    /// Parses one exact protected Initial, 0-RTT, or Handshake packet and returns its suffix.
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), QuicPacketParseError> {
        let header = QuicLongHeader::parse(bytes)?;
        let version = header.version();
        if version != QuicVersion::V1 && version != QuicVersion::V2 {
            return Err(QuicPacketParseError::UnsupportedVersion { version });
        }
        if !header.has_fixed_bit() {
            return Err(QuicPacketParseError::FixedBitNotSet {
                first_byte: header.first_byte(),
            });
        }
        validate_connection_id(
            QuicConnectionIdField::Destination,
            header.destination_connection_id().len(),
        )?;
        validate_connection_id(
            QuicConnectionIdField::Source,
            header.source_connection_id().len(),
        )?;

        let packet_type = match header.long_packet_type() {
            Some(packet_type) => packet_type,
            None => return Err(QuicPacketParseError::UnsupportedVersion { version }),
        };
        if packet_type == QuicLongPacketType::Retry {
            return Err(QuicPacketParseError::NotLengthDelimited { packet_type });
        }

        let header_end = header.as_bytes().len();
        let (token_length, token, length_offset) = if packet_type == QuicLongPacketType::Initial {
            let token_length = parse_varint_at(bytes, header_end)?;
            let token_start = checked_end(header_end, token_length.byte_len())?;
            let token_end = checked_end(token_start, to_usize(token_length.value())?)?;
            require(bytes, token_end)?;
            (
                Some(token_length),
                Some(&bytes[token_start..token_end]),
                token_end,
            )
        } else {
            (None, None, header_end)
        };

        let length = parse_varint_at(bytes, length_offset)?;
        if length.value() < 2 {
            return Err(QuicPacketParseError::ProtectedRemainderTooShort {
                minimum: 2,
                actual: length.value(),
            });
        }
        let packet_number_offset = checked_end(length_offset, length.byte_len())?;
        let packet_end = checked_end(packet_number_offset, to_usize(length.value())?)?;
        require(bytes, packet_end)?;

        Ok((
            Self {
                bytes: &bytes[..packet_end],
                header,
                packet_type,
                token_length,
                token,
                length,
                packet_number_offset,
                protected_remainder: &bytes[packet_number_offset..packet_end],
            },
            &bytes[packet_end..],
        ))
    }

    /// Returns the accepted invariant long-header prefix.
    pub const fn header(self) -> QuicLongHeader<'a> {
        self.header
    }

    /// Returns the supported QUIC version.
    pub const fn version(self) -> QuicVersion {
        self.header.version()
    }

    /// Returns the semantic Initial, 0-RTT, or Handshake type.
    pub const fn packet_type(self) -> QuicLongPacketType {
        self.packet_type
    }

    /// Returns the exact Initial token-length representation, if this is an Initial packet.
    pub const fn token_length(self) -> Option<QuicVarInt<'a>> {
        self.token_length
    }

    /// Returns the exact Initial token, including an empty token, if this is an Initial packet.
    pub const fn token(self) -> Option<&'a [u8]> {
        self.token
    }

    /// Returns the exact protected packet-length representation.
    pub const fn length(self) -> QuicVarInt<'a> {
        self.length
    }

    /// Returns the absolute offset of the protected packet number from packet start.
    pub const fn packet_number_offset(self) -> usize {
        self.packet_number_offset
    }

    /// Returns the exact bounded packet-number-and-protected-payload region.
    pub const fn protected_remainder(self) -> &'a [u8] {
        self.protected_remainder
    }

    /// Returns the exact complete length-delimited packet bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

fn validate_connection_id(
    field: QuicConnectionIdField,
    length: usize,
) -> Result<(), QuicPacketParseError> {
    if length > 20 {
        return Err(QuicPacketParseError::ConnectionIdTooLong { field, length });
    }
    Ok(())
}

fn parse_varint_at<'a>(
    bytes: &'a [u8],
    offset: usize,
) -> Result<QuicVarInt<'a>, QuicPacketParseError> {
    match QuicVarInt::parse(&bytes[offset..]) {
        Ok(value) => Ok(value),
        Err(QuicVarIntParseError::Incomplete {
            required,
            available: _,
        }) => Err(QuicPacketParseError::Incomplete {
            required: checked_end(offset, required)?,
            available: bytes.len(),
        }),
    }
}

fn to_usize(value: u64) -> Result<usize, QuicPacketParseError> {
    usize::try_from(value).map_err(|_| QuicPacketParseError::LengthNotRepresentable { value })
}

fn checked_end(offset: usize, length: usize) -> Result<usize, QuicPacketParseError> {
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
