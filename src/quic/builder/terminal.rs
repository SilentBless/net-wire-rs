//! Terminal QUIC packet builders.

use super::super::packet::header::{
    QuicConnectionId, QuicConnectionIdField, QuicLongHeader, QuicLongPacketType, QuicVersion,
};
use super::super::packet::layout::{
    QuicLongHeaderLayoutBuilder, QuicLongHeaderLayoutWriteError, prefix_len,
};
use super::super::packet::terminal::{QuicRetryPacket, QuicVersionNegotiationPacket};
use super::{QuicPacketBuildError, built_prefix_error};

const RETRY_INTEGRITY_TAG_LEN: usize = 16;

fn representation_error(error: QuicLongHeaderLayoutWriteError) -> QuicPacketBuildError {
    match error {
        QuicLongHeaderLayoutWriteError::FieldFirstByte(error)
        | QuicLongHeaderLayoutWriteError::FieldVersion(error)
        | QuicLongHeaderLayoutWriteError::FieldDestinationConnectionIdLength(error)
        | QuicLongHeaderLayoutWriteError::FieldSourceConnectionIdLength(error) => match error {},
        QuicLongHeaderLayoutWriteError::InvalidPlanLength { .. }
        | QuicLongHeaderLayoutWriteError::MissingContext { .. }
        | QuicLongHeaderLayoutWriteError::InvalidCodecWidth { .. }
        | QuicLongHeaderLayoutWriteError::InvalidRangeSource { .. }
        | QuicLongHeaderLayoutWriteError::ConflictingRangeSources { .. }
        | QuicLongHeaderLayoutWriteError::InvalidPrefixPlanLength { .. }
        | QuicLongHeaderLayoutWriteError::InvalidLayoutExtent { .. }
        | QuicLongHeaderLayoutWriteError::OutputTooShort { .. }
        | QuicLongHeaderLayoutWriteError::MissingField { .. } => {
            QuicPacketBuildError::InvalidRepresentation
        }
    }
}

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
        let source_end = prefix_len(
            self.destination_connection_id.len(),
            self.source_connection_id.len(),
        )
        .ok_or(QuicPacketBuildError::LengthOverflow {
            component: "invariant long-header prefix",
            offset: 7 + self.destination_connection_id.len(),
            length: self.source_connection_id.len(),
        })?;
        let required = checked_add(source_end, version_bytes, "version list")?;
        if self.destination.len() < required {
            return Err(QuicPacketBuildError::BufferTooShort {
                required,
                available: self.destination.len(),
            });
        }

        let destination = self.destination;
        {
            let (_, suffix) = QuicLongHeaderLayoutBuilder::new()
                .first_byte(0x80 | self.unused_bits)
                .version(QuicVersion::NEGOTIATION)
                .destination_connection_id(self.destination_connection_id.as_bytes())
                .source_connection_id(self.source_connection_id.as_bytes())
                .build_into(destination)
                .map_err(representation_error)?;
            for (slot, version) in suffix[..version_bytes]
                .chunks_exact_mut(4)
                .zip(self.versions)
            {
                slot.copy_from_slice(&version.raw().to_be_bytes());
            }
        }

        let bytes = &destination[..required];
        let header = QuicLongHeader::parse(bytes).map_err(built_prefix_error)?;
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

        let source_end = prefix_len(
            self.destination_connection_id.len(),
            self.source_connection_id.len(),
        )
        .ok_or(QuicPacketBuildError::LengthOverflow {
            component: "invariant long-header prefix",
            offset: 7 + self.destination_connection_id.len(),
            length: self.source_connection_id.len(),
        })?;
        let token_end = checked_add(source_end, self.token.len(), "Retry Token")?;
        let required = checked_add(token_end, RETRY_INTEGRITY_TAG_LEN, "Retry Integrity Tag")?;
        if self.destination.len() < required {
            return Err(QuicPacketBuildError::BufferTooShort {
                required,
                available: self.destination.len(),
            });
        }

        let destination = self.destination;
        {
            let (_, suffix) = QuicLongHeaderLayoutBuilder::new()
                .first_byte(0xc0 | (raw_type << 4) | self.unused_bits)
                .version(self.version)
                .destination_connection_id(self.destination_connection_id.as_bytes())
                .source_connection_id(self.source_connection_id.as_bytes())
                .build_into(destination)
                .map_err(representation_error)?;
            suffix[..self.token.len()].copy_from_slice(self.token);
            suffix[self.token.len()..self.token.len() + RETRY_INTEGRITY_TAG_LEN]
                .copy_from_slice(self.integrity_tag);
        }

        let bytes = &destination[..required];
        let header = QuicLongHeader::parse(bytes).map_err(built_prefix_error)?;
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
