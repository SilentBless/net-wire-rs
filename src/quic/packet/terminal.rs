//! Borrowed terminal QUIC Version Negotiation and Retry packet views.

use core::iter::FusedIterator;

use super::super::{
    QuicConnectionIdField, QuicLongHeader, QuicLongPacketType, QuicPacketParseError, QuicVersion,
};

const RETRY_INTEGRITY_TAG_LEN: usize = 16;

/// A borrowed QUIC Version Negotiation packet occupying its complete supplied datagram slice.
///
/// This view preserves the arbitrary lower seven bits of the first byte, connection-ID lengths
/// permitted by the invariant header, and every four-byte advertised version without applying
/// endpoint version-selection policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicVersionNegotiationPacket<'a> {
    bytes: &'a [u8],
    header: QuicLongHeader<'a>,
    versions: &'a [u8],
}

impl<'a> QuicVersionNegotiationPacket<'a> {
    /// Assembles a Version Negotiation view from builder-validated wire components.
    pub(crate) const fn from_validated(
        bytes: &'a [u8],
        header: QuicLongHeader<'a>,
        versions: &'a [u8],
    ) -> Self {
        Self {
            bytes,
            header,
            versions,
        }
    }

    /// Parses a complete Version Negotiation terminal packet.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QuicPacketParseError> {
        let header = QuicLongHeader::parse(bytes)?;
        if header.version() != QuicVersion::NEGOTIATION {
            return Err(QuicPacketParseError::WrongVersion {
                version: header.version(),
            });
        }

        let versions = header.version_specific();
        if versions.is_empty() {
            return Err(QuicPacketParseError::EmptyVersionList);
        }
        if !versions.len().is_multiple_of(4) {
            return Err(QuicPacketParseError::MisalignedVersionList {
                length: versions.len(),
            });
        }

        Ok(Self {
            bytes,
            header,
            versions,
        })
    }

    /// Returns the accepted invariant long-header prefix.
    pub const fn header(self) -> QuicLongHeader<'a> {
        self.header
    }

    /// Returns the exact raw four-byte version-list bytes.
    pub const fn version_list_bytes(self) -> &'a [u8] {
        self.versions
    }

    /// Returns an exact-size iterator over advertised versions in wire order.
    pub const fn versions(self) -> QuicVersionIter<'a> {
        QuicVersionIter {
            bytes: self.versions,
        }
    }

    /// Returns the complete supplied terminal packet bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

/// An allocation-free iterator over the exact raw versions in a Version Negotiation packet.
#[derive(Clone, Debug)]
pub struct QuicVersionIter<'a> {
    bytes: &'a [u8],
}

impl Iterator for QuicVersionIter<'_> {
    type Item = QuicVersion;

    fn next(&mut self) -> Option<Self::Item> {
        let (version, remainder) = self.bytes.split_first_chunk::<4>()?;
        self.bytes = remainder;
        Some(QuicVersion::new(u32::from_be_bytes(*version)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let length = self.len();
        (length, Some(length))
    }
}

impl ExactSizeIterator for QuicVersionIter<'_> {
    fn len(&self) -> usize {
        self.bytes.len() / 4
    }
}

impl FusedIterator for QuicVersionIter<'_> {}

/// A borrowed QUIC v1 or v2 Retry packet occupying its complete supplied datagram slice.
///
/// Retry token bytes and the final Retry Integrity Tag remain opaque. This view does not verify
/// the integrity tag or interpret the token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicRetryPacket<'a> {
    bytes: &'a [u8],
    header: QuicLongHeader<'a>,
    packet_type: QuicLongPacketType,
    token: &'a [u8],
    integrity_tag: &'a [u8],
}

impl<'a> QuicRetryPacket<'a> {
    /// Assembles a Retry view from builder-validated wire components.
    pub(crate) const fn from_validated(
        bytes: &'a [u8],
        header: QuicLongHeader<'a>,
        packet_type: QuicLongPacketType,
        token: &'a [u8],
        integrity_tag: &'a [u8],
    ) -> Self {
        Self {
            bytes,
            header,
            packet_type,
            token,
            integrity_tag,
        }
    }

    /// Parses a complete QUIC v1 or v2 Retry terminal packet.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QuicPacketParseError> {
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

        let packet_type = header
            .long_packet_type()
            .ok_or(QuicPacketParseError::UnsupportedVersion { version })?;
        if packet_type != QuicLongPacketType::Retry {
            return Err(QuicPacketParseError::NotRetry { packet_type });
        }

        let header_end = header.as_bytes().len();
        let required = header_end.checked_add(RETRY_INTEGRITY_TAG_LEN).ok_or(
            QuicPacketParseError::LengthOverflow {
                offset: header_end,
                length: RETRY_INTEGRITY_TAG_LEN,
            },
        )?;
        if bytes.len() < required {
            return Err(QuicPacketParseError::Incomplete {
                required,
                available: bytes.len(),
            });
        }
        if bytes.len() == required {
            return Err(QuicPacketParseError::EmptyRetryToken);
        }

        let tag_start = bytes.len() - RETRY_INTEGRITY_TAG_LEN;
        Ok(Self {
            bytes,
            header,
            packet_type,
            token: &bytes[header_end..tag_start],
            integrity_tag: &bytes[tag_start..],
        })
    }

    /// Returns the accepted invariant long-header prefix.
    pub const fn header(self) -> QuicLongHeader<'a> {
        self.header
    }

    /// Returns the supported QUIC version.
    pub const fn version(self) -> QuicVersion {
        self.header.version()
    }

    /// Returns the Retry semantic packet type.
    pub const fn packet_type(self) -> QuicLongPacketType {
        self.packet_type
    }

    /// Returns the exact opaque Retry Token bytes.
    pub const fn token(self) -> &'a [u8] {
        self.token
    }

    /// Returns the exact final 16-byte opaque Retry Integrity Tag.
    pub const fn integrity_tag(self) -> &'a [u8] {
        self.integrity_tag
    }

    /// Returns the complete supplied terminal packet bytes.
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
