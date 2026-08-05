//! Terminal QUIC packet builders.

use super::super::{
    QuicConnectionId, QuicConnectionIdField, QuicLongHeader, QuicLongPacketType,
    QuicPacketBuildError, QuicRetryPacket, QuicVersion, QuicVersionNegotiationPacket,
};

const RETRY_INTEGRITY_TAG_LEN: usize = 16;

/// Builds a terminal QUIC Version Negotiation packet in caller-owned storage.
pub struct QuicVersionNegotiationPacketBuilder<'buffer, 'input> {
    destination: &'buffer mut [u8],
    unused_bits: u8,
    destination_connection_id: QuicConnectionId<'input>,
    source_connection_id: QuicConnectionId<'input>,
    versions: &'input [QuicVersion],
}

impl<'buffer, 'input> QuicVersionNegotiationPacketBuilder<'buffer, 'input> {
    /// Creates a builder for a Version Negotiation packet with the supplied wire components.
    pub fn new(
        destination: &'buffer mut [u8],
        unused_bits: u8,
        destination_connection_id: QuicConnectionId<'input>,
        source_connection_id: QuicConnectionId<'input>,
        versions: &'input [QuicVersion],
    ) -> Self {
        Self {
            destination,
            unused_bits,
            destination_connection_id,
            source_connection_id,
            versions,
        }
    }

    /// Validates all inputs and capacity before writing a complete Version Negotiation packet.
    pub fn build(self) -> Result<QuicVersionNegotiationPacket<'buffer>, QuicPacketBuildError> {
        if self.unused_bits > 0x7f {
            return Err(QuicPacketBuildError::UnusedBitsOutOfRange {
                maximum: 0x7f,
                actual: self.unused_bits,
            });
        }
        validate_connection_id(
            QuicConnectionIdField::Destination,
            self.destination_connection_id.len(),
            255,
        )?;
        validate_connection_id(
            QuicConnectionIdField::Source,
            self.source_connection_id.len(),
            255,
        )?;
        if self.versions.is_empty() {
            return Err(QuicPacketBuildError::EmptyVersionList);
        }

        let version_bytes =
            self.versions
                .len()
                .checked_mul(4)
                .ok_or(QuicPacketBuildError::LengthOverflow {
                    component: "version list",
                    offset: self.versions.len(),
                    length: 4,
                })?;
        let destination_start = 6;
        let destination_end = checked_add(
            destination_start,
            self.destination_connection_id.len(),
            "destination connection ID",
        )?;
        let source_length_offset = destination_end;
        let source_start = checked_add(source_length_offset, 1, "source connection ID length")?;
        let source_end = checked_add(
            source_start,
            self.source_connection_id.len(),
            "source connection ID",
        )?;
        let required = checked_add(source_end, version_bytes, "version list")?;
        if self.destination.len() < required {
            return Err(QuicPacketBuildError::BufferTooShort {
                required,
                available: self.destination.len(),
            });
        }

        let destination = self.destination;
        destination[0] = 0x80 | self.unused_bits;
        destination[1..5].copy_from_slice(&QuicVersion::NEGOTIATION.raw().to_be_bytes());
        destination[5] = self.destination_connection_id.len() as u8;
        destination[destination_start..destination_end]
            .copy_from_slice(self.destination_connection_id.as_bytes());
        destination[source_length_offset] = self.source_connection_id.len() as u8;
        destination[source_start..source_end].copy_from_slice(self.source_connection_id.as_bytes());
        for (slot, version) in destination[source_end..required]
            .chunks_exact_mut(4)
            .zip(self.versions)
        {
            slot.copy_from_slice(&version.raw().to_be_bytes());
        }

        let bytes = &destination[..required];
        let header = QuicLongHeader::from_validated(
            &bytes[..source_end],
            bytes[0],
            QuicVersion::NEGOTIATION,
            QuicConnectionId::new(&bytes[destination_start..destination_end]),
            QuicConnectionId::new(&bytes[source_start..source_end]),
            &bytes[source_end..],
        );
        Ok(QuicVersionNegotiationPacket::from_validated(
            bytes,
            header,
            &bytes[source_end..],
        ))
    }
}

/// Builds a terminal QUIC v1 or v2 Retry packet in caller-owned storage.
pub struct QuicRetryPacketBuilder<'buffer, 'input> {
    destination: &'buffer mut [u8],
    version: QuicVersion,
    unused_bits: u8,
    destination_connection_id: QuicConnectionId<'input>,
    source_connection_id: QuicConnectionId<'input>,
    token: &'input [u8],
    integrity_tag: &'input [u8; RETRY_INTEGRITY_TAG_LEN],
}

impl<'buffer, 'input> QuicRetryPacketBuilder<'buffer, 'input> {
    /// Creates a builder for a Retry packet with supplied opaque token and integrity-tag bytes.
    pub fn new(
        destination: &'buffer mut [u8],
        version: QuicVersion,
        unused_bits: u8,
        destination_connection_id: QuicConnectionId<'input>,
        source_connection_id: QuicConnectionId<'input>,
        token: &'input [u8],
        integrity_tag: &'input [u8; RETRY_INTEGRITY_TAG_LEN],
    ) -> Self {
        Self {
            destination,
            version,
            unused_bits,
            destination_connection_id,
            source_connection_id,
            token,
            integrity_tag,
        }
    }

    /// Validates all inputs and capacity before writing a complete Retry packet.
    pub fn build(self) -> Result<QuicRetryPacket<'buffer>, QuicPacketBuildError> {
        let raw_type = match QuicLongPacketType::Retry.raw_type(self.version) {
            Some(raw_type) => raw_type,
            None => {
                return Err(QuicPacketBuildError::UnsupportedVersion {
                    version: self.version,
                });
            }
        };
        if self.unused_bits > 0x0f {
            return Err(QuicPacketBuildError::UnusedBitsOutOfRange {
                maximum: 0x0f,
                actual: self.unused_bits,
            });
        }
        validate_connection_id(
            QuicConnectionIdField::Destination,
            self.destination_connection_id.len(),
            20,
        )?;
        validate_connection_id(
            QuicConnectionIdField::Source,
            self.source_connection_id.len(),
            20,
        )?;
        if self.token.is_empty() {
            return Err(QuicPacketBuildError::EmptyRetryToken);
        }

        let destination_start = 6;
        let destination_end = checked_add(
            destination_start,
            self.destination_connection_id.len(),
            "destination connection ID",
        )?;
        let source_length_offset = destination_end;
        let source_start = checked_add(source_length_offset, 1, "source connection ID length")?;
        let source_end = checked_add(
            source_start,
            self.source_connection_id.len(),
            "source connection ID",
        )?;
        let token_end = checked_add(source_end, self.token.len(), "Retry Token")?;
        let required = checked_add(token_end, RETRY_INTEGRITY_TAG_LEN, "Retry Integrity Tag")?;
        if self.destination.len() < required {
            return Err(QuicPacketBuildError::BufferTooShort {
                required,
                available: self.destination.len(),
            });
        }

        let destination = self.destination;
        destination[0] = 0xc0 | (raw_type << 4) | self.unused_bits;
        destination[1..5].copy_from_slice(&self.version.raw().to_be_bytes());
        destination[5] = self.destination_connection_id.len() as u8;
        destination[destination_start..destination_end]
            .copy_from_slice(self.destination_connection_id.as_bytes());
        destination[source_length_offset] = self.source_connection_id.len() as u8;
        destination[source_start..source_end].copy_from_slice(self.source_connection_id.as_bytes());
        destination[source_end..token_end].copy_from_slice(self.token);
        destination[token_end..required].copy_from_slice(self.integrity_tag);

        let bytes = &destination[..required];
        let header = QuicLongHeader::from_validated(
            &bytes[..source_end],
            bytes[0],
            self.version,
            QuicConnectionId::new(&bytes[destination_start..destination_end]),
            QuicConnectionId::new(&bytes[source_start..source_end]),
            &bytes[source_end..],
        );
        Ok(QuicRetryPacket::from_validated(
            bytes,
            header,
            QuicLongPacketType::Retry,
            &bytes[source_end..token_end],
            &bytes[token_end..],
        ))
    }
}

fn validate_connection_id(
    field: QuicConnectionIdField,
    actual: usize,
    maximum: usize,
) -> Result<(), QuicPacketBuildError> {
    if actual > maximum {
        return Err(QuicPacketBuildError::ConnectionIdTooLong {
            field,
            maximum,
            actual,
        });
    }
    Ok(())
}

fn checked_add(
    offset: usize,
    length: usize,
    component: &'static str,
) -> Result<usize, QuicPacketBuildError> {
    offset
        .checked_add(length)
        .ok_or(QuicPacketBuildError::LengthOverflow {
            component,
            offset,
            length,
        })
}
