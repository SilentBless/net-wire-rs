//! QUIC variable-integer and packet-view errors.

use core::fmt;

/// Identifies a QUIC variable-length integer field during packet construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicPacketBuildField {
    /// The Initial packet token-length field.
    TokenLength,
    /// The protected packet-length field.
    ProtectedLength,
}

/// Failure to build a QUIC packet in caller-owned storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicPacketBuildError {
    /// The supplied unused-bit value exceeds the packet form's maximum.
    UnusedBitsOutOfRange {
        /// Greatest permitted unused-bit value.
        maximum: u8,
        /// Supplied unused-bit value.
        actual: u8,
    },
    /// The supplied protected-low-bit value exceeds the maximum permitted value.
    ProtectedLowBitsOutOfRange {
        /// Greatest permitted protected-low-bit value.
        maximum: u8,
        /// Supplied protected-low-bit value.
        actual: u8,
    },
    /// Packet construction supports only QUIC v1 and v2.
    UnsupportedVersion {
        /// Supplied raw version.
        version: super::QuicVersion,
    },
    /// A connection ID cannot be represented by this packet form.
    ConnectionIdTooLong {
        /// Connection-ID field that is too long.
        field: super::QuicConnectionIdField,
        /// Greatest permitted byte length.
        maximum: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// A Version Negotiation packet requires at least one advertised version.
    EmptyVersionList,
    /// A Retry packet requires at least one token byte.
    EmptyRetryToken,
    /// A protected packet remainder is too short to contain a packet number and payload.
    ProtectedRemainderTooShort {
        /// Minimum protected remainder byte length.
        minimum: usize,
        /// Supplied protected remainder byte length.
        actual: usize,
    },
    /// A packet variable-length field cannot represent its requested value or width.
    VarInt {
        /// Field that could not be encoded.
        field: QuicPacketBuildField,
        /// Exact variable-integer construction failure.
        error: QuicVarIntBuildError,
    },
    /// Packet-size arithmetic cannot represent an intermediate total.
    LengthOverflow {
        /// Named packet-size component being added.
        component: &'static str,
        /// Accumulated byte length before adding the component.
        offset: usize,
        /// Component byte length.
        length: usize,
    },
    /// The caller buffer cannot contain the complete packet.
    BufferTooShort {
        /// Complete packet byte length required.
        required: usize,
        /// Bytes available in the caller buffer.
        available: usize,
    },
}

impl fmt::Display for QuicPacketBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnusedBitsOutOfRange { maximum, actual } => write!(
                f,
                "QUIC unused bits value {actual:#04x} exceeds maximum {maximum:#04x}"
            ),
            Self::ProtectedLowBitsOutOfRange { maximum, actual } => write!(
                f,
                "QUIC protected low bits value {actual:#04x} exceeds maximum {maximum:#04x}"
            ),
            Self::UnsupportedVersion { version } => write!(
                f,
                "QUIC packet construction does not support version {:#010x}",
                version.raw()
            ),
            Self::ConnectionIdTooLong {
                field,
                maximum,
                actual,
            } => write!(
                f,
                "QUIC {field:?} connection ID length {actual} exceeds maximum {maximum}"
            ),
            Self::EmptyVersionList => write!(
                f,
                "QUIC Version Negotiation construction requires a nonempty version list"
            ),
            Self::EmptyRetryToken => {
                write!(f, "QUIC Retry construction requires a nonempty Retry Token")
            }
            Self::ProtectedRemainderTooShort { minimum, actual } => write!(
                f,
                "QUIC protected packet remainder is too short: need at least {minimum} bytes, have {actual}"
            ),
            Self::VarInt { field, error } => {
                write!(f, "QUIC {field:?} field cannot be encoded: {error}")
            }
            Self::LengthOverflow {
                component,
                offset,
                length,
            } => write!(
                f,
                "QUIC packet size overflows while adding {component}: offset {offset} plus length {length}"
            ),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "QUIC packet destination is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Failure to parse a QUIC variable-length integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicVarIntParseError {
    /// The input does not contain the complete encoded integer.
    Incomplete {
        /// Bytes required by the encoded width.
        required: usize,
        /// Bytes available in the input.
        available: usize,
    },
}

impl fmt::Display for QuicVarIntParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete {
                required,
                available,
            } => write!(
                f,
                "QUIC variable-length integer input is incomplete: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Identifies a semantic field in a QUIC frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuicFrameField {
    /// The CRYPTO frame's offset field.
    CryptoOffset,
    /// The CRYPTO frame's data-length field.
    CryptoLength,
    /// The CRYPTO frame's opaque data bytes.
    CryptoData,
    /// The frame's token-length field.
    TokenLength,
    /// The frame's opaque token bytes.
    Token,
    /// The frame's stream-ID field.
    StreamId,
    /// The STREAM frame's offset field.
    StreamOffset,
    /// The STREAM frame's data-length field.
    StreamLength,
    /// The STREAM frame's opaque data bytes.
    StreamData,
    /// The frame's maximum-data field.
    MaximumData,
    /// The frame's maximum-stream-data field.
    MaximumStreamData,
    /// The frame's maximum-streams field.
    MaximumStreams,
    /// The frame's application-error-code field.
    ApplicationErrorCode,
    /// The CONNECTION_CLOSE frame's error-code field.
    ConnectionCloseErrorCode,
    /// The transport CONNECTION_CLOSE frame's triggering-frame-type field.
    TriggeringFrameType,
    /// The CONNECTION_CLOSE frame's reason-phrase-length field.
    ReasonPhraseLength,
    /// The CONNECTION_CLOSE frame's opaque reason-phrase bytes.
    ReasonPhrase,
    /// The frame's final-size field.
    FinalSize,
    /// The frame's opaque path-validation data.
    PathData,
    /// The frame's connection-ID sequence-number field.
    SequenceNumber,
    /// The frame's retire-prior-to field.
    RetirePriorTo,
    /// The frame's connection-ID-length field.
    ConnectionIdLength,
    /// The frame's opaque connection-ID bytes.
    ConnectionId,
    /// The frame's stateless-reset-token bytes.
    StatelessResetToken,
    /// The ACK frame's largest-acknowledged field.
    LargestAcknowledged,
    /// The ACK frame's acknowledgment-delay field.
    AckDelay,
    /// The ACK frame's additional-range count field.
    AckRangeCount,
    /// The ACK frame's first acknowledgment-range field.
    FirstAckRange,
    /// An ACK frame's additional-range gap field.
    AckGap,
    /// An ACK frame's additional-range length field.
    AckRangeLength,
    /// The ACK_ECN frame's ECT(0) count field.
    Ect0Count,
    /// The ACK_ECN frame's ECT(1) count field.
    Ect1Count,
    /// The ACK_ECN frame's ECN-CE count field.
    EcnCeCount,
}

/// Failure to parse a QUIC plaintext frame sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicFrameParseError {
    /// The supplied plaintext frame sequence contains no frames.
    EmptySequence,
    /// The frame-type variable integer is incomplete at the indicated sequence offset.
    FrameType {
        /// Absolute byte offset of the frame type from the sequence start.
        offset: usize,
        /// Exact variable-integer parsing failure.
        error: QuicVarIntParseError,
    },
    /// A semantic frame field variable integer is incomplete at the indicated sequence offset.
    Field {
        /// Semantic field whose variable integer could not be parsed.
        field: QuicFrameField,
        /// Absolute byte offset of the field from the sequence start.
        offset: usize,
        /// Exact variable-integer parsing failure.
        error: QuicVarIntParseError,
    },
    /// A semantic frame field exceeds its RFC-defined maximum value.
    FieldValueOutOfRange {
        /// Semantic field whose decoded value exceeds its maximum.
        field: QuicFrameField,
        /// Absolute byte offset of the field from the sequence start.
        offset: usize,
        /// Decoded field value.
        value: u64,
        /// Greatest permitted field value.
        maximum: u64,
    },
    /// A semantic frame field exceeds the decoded value of another field.
    FieldValueExceedsField {
        /// Semantic field whose decoded value is too large.
        field: QuicFrameField,
        /// Absolute byte offset of the field from the sequence start.
        offset: usize,
        /// Decoded field value.
        value: u64,
        /// Semantic field supplying the maximum value.
        maximum_field: QuicFrameField,
        /// Decoded maximum-field value.
        maximum: u64,
    },
    /// A decoded frame byte range exceeds its RFC-defined maximum end offset.
    FieldRangeOutOfRange {
        /// Semantic field encoding the decoded range start.
        field: QuicFrameField,
        /// Absolute byte offset of the encoded range-start field from the sequence start.
        offset: usize,
        /// Decoded range start.
        start: u64,
        /// Decoded range length.
        length: u64,
        /// Greatest permitted decoded range end.
        maximum: u64,
    },
    /// A decoded bounded-byte field length cannot be represented as `usize` on this target.
    LengthNotRepresentable {
        /// Semantic field whose length cannot be represented.
        field: QuicFrameField,
        /// Absolute byte offset of the encoded length from the sequence start.
        offset: usize,
        /// Decoded wire length.
        value: u64,
    },
    /// An implicit bounded-byte field length cannot be represented as `u64`.
    ImplicitLengthNotRepresentable {
        /// Semantic field whose implicit length cannot be represented.
        field: QuicFrameField,
        /// Absolute byte offset of the bounded byte field from the sequence start.
        offset: usize,
        /// Native byte length derived from the supplied slice.
        length: usize,
    },
    /// Computing the end of a bounded-byte field overflows `usize`.
    LengthOverflow {
        /// Semantic bounded-byte field whose end cannot be represented.
        field: QuicFrameField,
        /// Absolute byte offset of the bounded byte field from the sequence start.
        offset: usize,
        /// Representable bounded byte-field length.
        length: usize,
    },
    /// A bounded-byte field is incomplete.
    IncompleteBytes {
        /// Semantic bounded-byte field that is incomplete.
        field: QuicFrameField,
        /// Absolute byte offset of the bounded byte field from the sequence start.
        offset: usize,
        /// Bytes required by the bounded byte field.
        required: usize,
        /// Bytes available for the bounded byte field.
        available: usize,
    },
    /// A semantically required nonempty field is empty.
    EmptyField {
        /// Semantic field that must not be empty.
        field: QuicFrameField,
        /// Absolute byte offset of the field from the sequence start.
        offset: usize,
    },
    /// Computing an ACK range packet number would be negative.
    AckRangeUnderflow {
        /// ACK field whose encoded value caused the underflow.
        field: QuicFrameField,
        /// Absolute byte offset of the encoded field from the sequence start.
        offset: usize,
        /// Packet number before subtracting this field.
        base: u64,
        /// Decoded field value being subtracted.
        value: u64,
        /// Additional fixed adjustment applied after `value`.
        adjustment: u64,
    },
    /// The frame type has no safe boundary without implementing its type-specific layout.
    UnsupportedFrameType {
        /// Decoded raw frame-type value.
        value: u64,
        /// Exact encoded frame-type width.
        length: super::QuicVarIntLen,
        /// Absolute byte offset of the frame type from the sequence start.
        offset: usize,
    },
}

impl fmt::Display for QuicFrameParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySequence => write!(f, "QUIC plaintext frame sequence is empty"),
            Self::FrameType { offset, error } => write!(
                f,
                "QUIC frame type at offset {offset} cannot be parsed: {error}"
            ),
            Self::Field {
                field,
                offset,
                error,
            } => write!(
                f,
                "QUIC frame {field:?} field at offset {offset} cannot be parsed: {error}"
            ),
            Self::FieldValueOutOfRange {
                field,
                offset,
                value,
                maximum,
            } => write!(
                f,
                "QUIC frame {field:?} field at offset {offset} has value {value}, exceeding maximum {maximum}"
            ),
            Self::FieldValueExceedsField {
                field,
                offset,
                value,
                maximum_field,
                maximum,
            } => write!(
                f,
                "QUIC frame {field:?} field at offset {offset} has value {value}, exceeding {maximum_field:?} value {maximum}"
            ),
            Self::FieldRangeOutOfRange {
                field,
                offset,
                start,
                length,
                maximum,
            } => write!(
                f,
                "QUIC frame {field:?} range at offset {offset} has start {start} plus length {length}, exceeding maximum end {maximum}"
            ),
            Self::LengthNotRepresentable {
                field,
                offset,
                value,
            } => write!(
                f,
                "QUIC frame {field:?} length at offset {offset} has unrepresentable value {value}"
            ),
            Self::ImplicitLengthNotRepresentable {
                field,
                offset,
                length,
            } => write!(
                f,
                "QUIC frame {field:?} implicit length at offset {offset} cannot represent native length {length} as u64"
            ),
            Self::LengthOverflow {
                field,
                offset,
                length,
            } => write!(
                f,
                "QUIC frame {field:?} bounded field at offset {offset} overflows with length {length}"
            ),
            Self::IncompleteBytes {
                field,
                offset,
                required,
                available,
            } => write!(
                f,
                "QUIC frame {field:?} bytes at offset {offset} are incomplete: need {required} bytes, have {available}"
            ),
            Self::EmptyField { field, offset } => write!(
                f,
                "QUIC frame {field:?} field at offset {offset} must be nonempty"
            ),
            Self::AckRangeUnderflow {
                field,
                offset,
                base,
                value,
                adjustment,
            } => write!(
                f,
                "QUIC ACK {field:?} field at offset {offset} underflows: {base} minus {value} minus {adjustment}"
            ),
            Self::UnsupportedFrameType {
                value,
                length,
                offset,
            } => write!(
                f,
                "QUIC frame type {value} at offset {offset} with encoded width {} is unsupported",
                length.byte_len()
            ),
        }
    }
}

/// Failure to build a QUIC variable-length integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicVarIntBuildError {
    /// The value exceeds QUIC's 62-bit maximum.
    ValueTooLarge {
        /// Supplied value.
        value: u64,
    },
    /// The requested encoded width cannot represent the value.
    WidthTooSmall {
        /// Requested encoded width.
        length: super::QuicVarIntLen,
        /// Supplied value.
        value: u64,
    },
    /// The caller buffer cannot contain the requested encoding.
    BufferTooShort {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
}

impl fmt::Display for QuicVarIntBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueTooLarge { value } => write!(
                f,
                "QUIC variable-length integer value {value} exceeds the 62-bit maximum"
            ),
            Self::WidthTooSmall { length, value } => write!(
                f,
                "QUIC variable-length integer width {} cannot represent {value}",
                length.byte_len()
            ),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "QUIC variable-length integer buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Failure to associate caller-unprotected bytes with a protected QUIC packet view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicUnprotectedHeaderError {
    /// Header-protection-preserved first-byte bits differ from the protected packet.
    PreservedBitsMismatch {
        /// The first byte from the accepted protected packet.
        protected_first_byte: u8,
        /// The caller-supplied unprotected first byte.
        unprotected_first_byte: u8,
        /// Mask identifying bits that header protection must preserve.
        preserved_mask: u8,
    },
    /// The supplied truncated packet-number byte count disagrees with the unprotected first byte.
    PacketNumberLengthMismatch {
        /// Packet-number byte count required by the unprotected first byte.
        expected: usize,
        /// Caller-supplied packet-number byte count.
        supplied: usize,
    },
    /// The protected packet remainder cannot physically contain the indicated packet number.
    ProtectedRemainderTooShort {
        /// Packet-number byte count required by the unprotected first byte.
        required: usize,
        /// Bytes physically available in the protected packet remainder.
        available: usize,
    },
}

impl fmt::Display for QuicUnprotectedHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreservedBitsMismatch {
                protected_first_byte,
                unprotected_first_byte,
                preserved_mask,
            } => write!(
                f,
                "QUIC protected first byte {protected_first_byte:#04x} and unprotected first byte {unprotected_first_byte:#04x} differ under preserved-bit mask {preserved_mask:#04x}"
            ),
            Self::PacketNumberLengthMismatch { expected, supplied } => write!(
                f,
                "QUIC unprotected packet-number width mismatch: need {expected} bytes, have {supplied}"
            ),
            Self::ProtectedRemainderTooShort {
                required,
                available,
            } => write!(
                f,
                "QUIC protected packet remainder is too short for its unprotected packet number: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Failure to parse a QUIC packet-header view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicPacketParseError {
    /// A supplied UDP datagram contains no packet bytes.
    EmptyDatagram,
    /// A short-header packet cannot be delimited without caller-supplied destination ID context.
    ShortHeaderContextRequired,
    /// The first byte has the opposite QUIC header form from the requested view.
    WrongHeaderForm {
        /// Whether the requested view requires the long-header form bit to be set.
        expected_long: bool,
        /// The observed first byte.
        first_byte: u8,
    },
    /// The input does not contain all bytes structurally required by the view.
    Incomplete {
        /// Absolute byte count required from the start of the supplied input.
        required: usize,
        /// Bytes available in the supplied input.
        available: usize,
    },
    /// A caller-supplied length cannot be represented when locating a field.
    LengthOverflow {
        /// Offset before adding the supplied length.
        offset: usize,
        /// Length that could not be added to the offset.
        length: usize,
    },
    /// A version-specific packet view does not define semantics for this QUIC version.
    UnsupportedVersion {
        /// The raw unsupported version.
        version: super::QuicVersion,
    },
    /// A terminal packet was parsed by a view requiring a different exact version.
    WrongVersion {
        /// The observed raw version.
        version: super::QuicVersion,
    },
    /// A Version Negotiation packet has no advertised versions after its invariant prefix.
    EmptyVersionList,
    /// A Version Negotiation version list does not contain a whole number of four-byte versions.
    MisalignedVersionList {
        /// The observed version-list byte length.
        length: usize,
    },
    /// A supported-version terminal packet is not a Retry packet.
    NotRetry {
        /// The observed semantic packet type.
        packet_type: super::QuicLongPacketType,
    },
    /// A Retry packet has an integrity tag but no Retry Token bytes.
    EmptyRetryToken,
    /// A supported-version long header has its required fixed bit cleared.
    FixedBitNotSet {
        /// The observed first byte.
        first_byte: u8,
    },
    /// A supported-version connection ID exceeds its 20-byte limit.
    ConnectionIdTooLong {
        /// The overlong connection-ID field.
        field: super::QuicConnectionIdField,
        /// The observed byte length.
        length: usize,
    },
    /// The packet type is terminal rather than length-delimited.
    NotLengthDelimited {
        /// The terminal semantic packet type.
        packet_type: super::QuicLongPacketType,
    },
    /// A decoded length cannot be represented as `usize` on this target.
    LengthNotRepresentable {
        /// The decoded wire value.
        value: u64,
    },
    /// A protected packet length is too short to contain a packet number and payload.
    ProtectedRemainderTooShort {
        /// Minimum protected remainder byte length.
        minimum: u64,
        /// Decoded protected remainder byte length.
        actual: u64,
    },
}

impl fmt::Display for QuicPacketParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDatagram => write!(f, "QUIC UDP datagram is empty"),
            Self::ShortHeaderContextRequired => write!(
                f,
                "QUIC short-header packet requires destination connection-ID length context"
            ),
            Self::WrongHeaderForm {
                expected_long,
                first_byte,
            } => {
                let expected = if *expected_long { "long" } else { "short" };
                write!(
                    f,
                    "QUIC {expected} header view received first byte {first_byte:#04x} with the wrong header form"
                )
            }
            Self::Incomplete {
                required,
                available,
            } => write!(
                f,
                "QUIC packet input is incomplete: need {required} bytes, have {available}"
            ),
            Self::LengthOverflow { offset, length } => write!(
                f,
                "QUIC packet field end cannot be represented: offset {offset} plus length {length} overflows usize"
            ),
            Self::UnsupportedVersion { version } => write!(
                f,
                "QUIC version-specific long-packet semantics are unsupported for version {:#010x}",
                version.raw()
            ),
            Self::WrongVersion { version } => write!(
                f,
                "QUIC terminal packet view requires a different version than {:#010x}",
                version.raw()
            ),
            Self::EmptyVersionList => write!(
                f,
                "QUIC Version Negotiation packet has an empty version list"
            ),
            Self::MisalignedVersionList { length } => write!(
                f,
                "QUIC Version Negotiation version list has invalid byte length {length}; expected a nonzero multiple of 4"
            ),
            Self::NotRetry { packet_type } => {
                write!(f, "QUIC terminal packet is {packet_type:?}, not Retry")
            }
            Self::EmptyRetryToken => write!(f, "QUIC Retry packet has an empty Retry Token"),
            Self::FixedBitNotSet { first_byte } => write!(
                f,
                "QUIC supported-version long packet has fixed bit clear in first byte {first_byte:#04x}"
            ),
            Self::ConnectionIdTooLong { field, length } => write!(
                f,
                "QUIC {field:?} connection ID has invalid length {length}; supported versions permit at most 20 bytes"
            ),
            Self::NotLengthDelimited { packet_type } => write!(
                f,
                "QUIC {packet_type:?} packet is terminal and not length-delimited"
            ),
            Self::LengthNotRepresentable { value } => write!(
                f,
                "QUIC wire length {value} cannot be represented as usize on this target"
            ),
            Self::ProtectedRemainderTooShort { minimum, actual } => write!(
                f,
                "QUIC protected packet length is too short: need at least {minimum} bytes, have {actual}"
            ),
        }
    }
}
