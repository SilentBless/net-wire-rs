//! Protected QUIC v1 and v2 length-delimited long-packet builders.

use super::super::packet::header::{
    QuicConnectionId, QuicConnectionIdField, QuicLongHeader, QuicLongPacketType, QuicVersion,
};
use super::super::packet::layout::{
    QuicLongHeaderLayoutBuilder, QuicLongHeaderLayoutWriteError, prefix_len,
};
use super::super::packet::long::QuicProtectedLongPacket;
use super::super::varint::{QuicVarInt, QuicVarIntBuildError, QuicVarIntLen};
use super::{QuicPacketBuildError, QuicPacketBuildField, built_prefix_error};

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

/// Builds a protected QUIC v1 or v2 Initial packet in caller-owned storage.
pub struct QuicInitialPacketBuilder<'buffer, 'input> {
    destination: &'buffer mut [u8],
    version: QuicVersion,
    protected_low_bits: u8,
    destination_connection_id: QuicConnectionId<'input>,
    source_connection_id: QuicConnectionId<'input>,
    token: &'input [u8],
    protected_remainder: &'input [u8],
    token_length_len: Option<QuicVarIntLen>,
    length_len: Option<QuicVarIntLen>,
}

impl<'buffer, 'input> QuicInitialPacketBuilder<'buffer, 'input> {
    /// Creates a builder with exact opaque Initial token and protected-remainder bytes.
    pub fn new(
        destination: &'buffer mut [u8],
        version: QuicVersion,
        protected_low_bits: u8,
        destination_connection_id: QuicConnectionId<'input>,
        source_connection_id: QuicConnectionId<'input>,
        token: &'input [u8],
        protected_remainder: &'input [u8],
    ) -> Self {
        Self {
            destination,
            version,
            protected_low_bits,
            destination_connection_id,
            source_connection_id,
            token,
            protected_remainder,
            token_length_len: None,
            length_len: None,
        }
    }

    /// Requests an explicit legal encoded width for the Initial token-length field.
    pub fn with_token_length_len(mut self, length: QuicVarIntLen) -> Self {
        self.token_length_len = Some(length);
        self
    }

    /// Requests an explicit legal encoded width for the protected packet-length field.
    pub fn with_length_len(mut self, length: QuicVarIntLen) -> Self {
        self.length_len = Some(length);
        self
    }

    /// Validates all inputs and capacity before writing a complete protected Initial packet.
    pub fn build(self) -> Result<QuicProtectedLongPacket<'buffer>, QuicPacketBuildError> {
        build_long(BuildInput {
            destination: self.destination,
            version: self.version,
            protected_low_bits: self.protected_low_bits,
            destination_connection_id: self.destination_connection_id,
            source_connection_id: self.source_connection_id,
            packet_type: QuicLongPacketType::Initial,
            token: Some(self.token),
            token_length_len: self.token_length_len,
            length_len: self.length_len,
            protected_remainder: self.protected_remainder,
        })
    }
}

/// Builds a protected QUIC v1 or v2 0-RTT packet in caller-owned storage.
pub struct QuicZeroRttPacketBuilder<'buffer, 'input> {
    destination: &'buffer mut [u8],
    version: QuicVersion,
    protected_low_bits: u8,
    destination_connection_id: QuicConnectionId<'input>,
    source_connection_id: QuicConnectionId<'input>,
    protected_remainder: &'input [u8],
    length_len: Option<QuicVarIntLen>,
}

impl<'buffer, 'input> QuicZeroRttPacketBuilder<'buffer, 'input> {
    /// Creates a builder with exact opaque protected-remainder bytes.
    pub fn new(
        destination: &'buffer mut [u8],
        version: QuicVersion,
        protected_low_bits: u8,
        destination_connection_id: QuicConnectionId<'input>,
        source_connection_id: QuicConnectionId<'input>,
        protected_remainder: &'input [u8],
    ) -> Self {
        Self {
            destination,
            version,
            protected_low_bits,
            destination_connection_id,
            source_connection_id,
            protected_remainder,
            length_len: None,
        }
    }

    /// Requests an explicit legal encoded width for the protected packet-length field.
    pub fn with_length_len(mut self, length: QuicVarIntLen) -> Self {
        self.length_len = Some(length);
        self
    }

    /// Validates all inputs and capacity before writing a complete protected 0-RTT packet.
    pub fn build(self) -> Result<QuicProtectedLongPacket<'buffer>, QuicPacketBuildError> {
        build_long(BuildInput {
            destination: self.destination,
            version: self.version,
            protected_low_bits: self.protected_low_bits,
            destination_connection_id: self.destination_connection_id,
            source_connection_id: self.source_connection_id,
            packet_type: QuicLongPacketType::ZeroRtt,
            token: None,
            token_length_len: None,
            length_len: self.length_len,
            protected_remainder: self.protected_remainder,
        })
    }
}

/// Builds a protected QUIC v1 or v2 Handshake packet in caller-owned storage.
pub struct QuicHandshakePacketBuilder<'buffer, 'input> {
    destination: &'buffer mut [u8],
    version: QuicVersion,
    protected_low_bits: u8,
    destination_connection_id: QuicConnectionId<'input>,
    source_connection_id: QuicConnectionId<'input>,
    protected_remainder: &'input [u8],
    length_len: Option<QuicVarIntLen>,
}

impl<'buffer, 'input> QuicHandshakePacketBuilder<'buffer, 'input> {
    /// Creates a builder with exact opaque protected-remainder bytes.
    pub fn new(
        destination: &'buffer mut [u8],
        version: QuicVersion,
        protected_low_bits: u8,
        destination_connection_id: QuicConnectionId<'input>,
        source_connection_id: QuicConnectionId<'input>,
        protected_remainder: &'input [u8],
    ) -> Self {
        Self {
            destination,
            version,
            protected_low_bits,
            destination_connection_id,
            source_connection_id,
            protected_remainder,
            length_len: None,
        }
    }

    /// Requests an explicit legal encoded width for the protected packet-length field.
    pub fn with_length_len(mut self, length: QuicVarIntLen) -> Self {
        self.length_len = Some(length);
        self
    }

    /// Validates all inputs and capacity before writing a complete protected Handshake packet.
    pub fn build(self) -> Result<QuicProtectedLongPacket<'buffer>, QuicPacketBuildError> {
        build_long(BuildInput {
            destination: self.destination,
            version: self.version,
            protected_low_bits: self.protected_low_bits,
            destination_connection_id: self.destination_connection_id,
            source_connection_id: self.source_connection_id,
            packet_type: QuicLongPacketType::Handshake,
            token: None,
            token_length_len: None,
            length_len: self.length_len,
            protected_remainder: self.protected_remainder,
        })
    }
}

struct BuildInput<'buffer, 'input> {
    destination: &'buffer mut [u8],
    version: QuicVersion,
    protected_low_bits: u8,
    destination_connection_id: QuicConnectionId<'input>,
    source_connection_id: QuicConnectionId<'input>,
    packet_type: QuicLongPacketType,
    token: Option<&'input [u8]>,
    token_length_len: Option<QuicVarIntLen>,
    length_len: Option<QuicVarIntLen>,
    protected_remainder: &'input [u8],
}

fn build_long<'buffer>(
    input: BuildInput<'buffer, '_>,
) -> Result<QuicProtectedLongPacket<'buffer>, QuicPacketBuildError> {
    let raw_type = input.packet_type.raw_type(input.version).ok_or(
        QuicPacketBuildError::UnsupportedVersion {
            version: input.version,
        },
    )?;
    if input.protected_low_bits > 0x0f {
        return Err(QuicPacketBuildError::ProtectedLowBitsOutOfRange {
            maximum: 0x0f,
            actual: input.protected_low_bits,
        });
    }
    validate_connection_id(
        QuicConnectionIdField::Destination,
        input.destination_connection_id.len(),
    )?;
    validate_connection_id(
        QuicConnectionIdField::Source,
        input.source_connection_id.len(),
    )?;
    if input.protected_remainder.len() < 2 {
        return Err(QuicPacketBuildError::ProtectedRemainderTooShort {
            minimum: 2,
            actual: input.protected_remainder.len(),
        });
    }

    let protected_length = u64::try_from(input.protected_remainder.len()).map_err(|_| {
        QuicPacketBuildError::VarInt {
            field: QuicPacketBuildField::ProtectedLength,
            error: QuicVarIntBuildError::ValueTooLarge { value: u64::MAX },
        }
    })?;
    let length_len = validate_varint(
        QuicPacketBuildField::ProtectedLength,
        protected_length,
        input.length_len,
    )?;
    let token_length = input.token.map(|token| token.len());
    let token_length_value = match token_length {
        Some(length) => u64::try_from(length).map_err(|_| QuicPacketBuildError::VarInt {
            field: QuicPacketBuildField::TokenLength,
            error: QuicVarIntBuildError::ValueTooLarge { value: u64::MAX },
        })?,
        None => 0,
    };
    let token_length_len = match token_length {
        Some(_) => Some(validate_varint(
            QuicPacketBuildField::TokenLength,
            token_length_value,
            input.token_length_len,
        )?),
        None => None,
    };

    let source_end = prefix_len(
        input.destination_connection_id.len(),
        input.source_connection_id.len(),
    )
    .ok_or(QuicPacketBuildError::LengthOverflow {
        component: "invariant long-header prefix",
        offset: 7 + input.destination_connection_id.len(),
        length: input.source_connection_id.len(),
    })?;
    let token_length_offset = source_end;
    let token_start = match (input.token, token_length_len) {
        (Some(_), Some(length)) => {
            checked_add(token_length_offset, length.byte_len(), "token length")?
        }
        (None, None) => source_end,
        _ => {
            return Err(QuicPacketBuildError::LengthOverflow {
                component: "token fields",
                offset: source_end,
                length: 0,
            });
        }
    };
    let token_end = match input.token {
        Some(token) => checked_add(token_start, token.len(), "Initial token")?,
        None => token_start,
    };
    let length_offset = token_end;
    let packet_number_offset =
        checked_add(length_offset, length_len.byte_len(), "protected length")?;
    let required = checked_add(
        packet_number_offset,
        input.protected_remainder.len(),
        "protected remainder",
    )?;
    if input.destination.len() < required {
        return Err(QuicPacketBuildError::BufferTooShort {
            required,
            available: input.destination.len(),
        });
    }

    let destination = input.destination;
    {
        let (_, suffix) = QuicLongHeaderLayoutBuilder::new()
            .first_byte(0xc0 | (raw_type << 4) | input.protected_low_bits)
            .version(input.version)
            .destination_connection_id(input.destination_connection_id.as_bytes())
            .source_connection_id(input.source_connection_id.as_bytes())
            .build_into(destination)
            .map_err(representation_error)?;
        if let (Some(token), Some(token_length_len)) = (input.token, token_length_len) {
            write_varint(
                &mut suffix[..token_start - source_end],
                token_length_value,
                token_length_len,
            );
            suffix[token_start - source_end..token_end - source_end].copy_from_slice(token);
        }
        write_varint(
            &mut suffix[length_offset - source_end..packet_number_offset - source_end],
            protected_length,
            length_len,
        );
        suffix[packet_number_offset - source_end..required - source_end]
            .copy_from_slice(input.protected_remainder);
    }

    let bytes = &destination[..required];
    let header = QuicLongHeader::parse(bytes).map_err(built_prefix_error)?;
    let token_length = token_length_len.map(|length| {
        QuicVarInt::from_validated(
            &bytes[token_length_offset..token_start],
            token_length_value,
            length,
        )
    });
    let token_fields =
        token_length.map(|token_length| (token_length, &bytes[token_start..token_end]));
    let length = QuicVarInt::from_validated(
        &bytes[length_offset..packet_number_offset],
        protected_length,
        length_len,
    );
    Ok(QuicProtectedLongPacket::from_validated(
        bytes,
        header,
        input.packet_type,
        token_fields,
        length,
        packet_number_offset,
        &bytes[packet_number_offset..required],
    ))
}

fn validate_connection_id(
    field: QuicConnectionIdField,
    actual: usize,
) -> Result<(), QuicPacketBuildError> {
    if actual > 20 {
        return Err(QuicPacketBuildError::ConnectionIdTooLong {
            field,
            maximum: 20,
            actual,
        });
    }
    Ok(())
}

fn validate_varint(
    field: QuicPacketBuildField,
    value: u64,
    requested: Option<QuicVarIntLen>,
) -> Result<QuicVarIntLen, QuicPacketBuildError> {
    if value > QuicVarIntLen::Eight.max_value() {
        return Err(QuicPacketBuildError::VarInt {
            field,
            error: QuicVarIntBuildError::ValueTooLarge { value },
        });
    }
    let length = requested.unwrap_or_else(|| canonical_len(value));
    if value > length.max_value() {
        return Err(QuicPacketBuildError::VarInt {
            field,
            error: QuicVarIntBuildError::WidthTooSmall { length, value },
        });
    }
    Ok(length)
}

const fn canonical_len(value: u64) -> QuicVarIntLen {
    if value <= QuicVarIntLen::One.max_value() {
        QuicVarIntLen::One
    } else if value <= QuicVarIntLen::Two.max_value() {
        QuicVarIntLen::Two
    } else if value <= QuicVarIntLen::Four.max_value() {
        QuicVarIntLen::Four
    } else {
        QuicVarIntLen::Eight
    }
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

fn write_varint(destination: &mut [u8], value: u64, length: QuicVarIntLen) {
    let value_bytes = value.to_be_bytes();
    let length_bytes = length.byte_len();
    destination.copy_from_slice(&value_bytes[value_bytes.len() - length_bytes..]);
    destination[0] |= match length {
        QuicVarIntLen::One => 0,
        QuicVarIntLen::Two => 0x40,
        QuicVarIntLen::Four => 0x80,
        QuicVarIntLen::Eight => 0xc0,
    };
}
