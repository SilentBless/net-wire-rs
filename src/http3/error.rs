//! HTTP/3 frame parsing and construction errors.

use core::fmt;

use crate::{
    qpack::QpackFieldSectionDecodeError,
    quic::{QuicVarIntBuildError, QuicVarIntParseError},
};

/// Failure to parse a structurally bounded HTTP/3 frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3FrameParseError {
    /// The frame type variable-length integer is incomplete.
    TypeVarInt(QuicVarIntParseError),
    /// The payload length variable-length integer is incomplete.
    LengthVarInt(QuicVarIntParseError),
    /// The encoded payload length cannot be represented as `usize`.
    PayloadLengthNotRepresentable {
        /// Encoded payload length.
        value: u64,
    },
    /// Adding the encoded header and payload lengths overflows `usize`.
    FrameLengthOverflow {
        /// Encoded type length in bytes.
        type_length: usize,
        /// Encoded payload-length length in bytes.
        length_length: usize,
        /// Decoded payload length in bytes.
        payload_length: usize,
    },
    /// The declared payload exceeds the caller-provided maximum.
    PayloadTooLarge {
        /// Caller-provided maximum payload length.
        maximum: usize,
        /// Declared payload length.
        actual: usize,
    },
    /// The complete frame is not available.
    IncompletePayload {
        /// Bytes required for the complete frame.
        required: usize,
        /// Bytes available in the input.
        available: usize,
    },
}

impl fmt::Display for Http3FrameParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeVarInt(error) => {
                write!(f, "HTTP/3 frame type variable-length integer: {error}")
            }
            Self::LengthVarInt(error) => {
                write!(
                    f,
                    "HTTP/3 frame payload length variable-length integer: {error}"
                )
            }
            Self::PayloadLengthNotRepresentable { value } => write!(
                f,
                "HTTP/3 frame payload length {value} cannot be represented as usize"
            ),
            Self::FrameLengthOverflow {
                type_length,
                length_length,
                payload_length,
            } => write!(
                f,
                "HTTP/3 frame length overflows: type {type_length} bytes, length {length_length} bytes, payload {payload_length} bytes"
            ),
            Self::PayloadTooLarge { maximum, actual } => write!(
                f,
                "HTTP/3 frame payload is too large: maximum {maximum}, got {actual}"
            ),
            Self::IncompletePayload {
                required,
                available,
            } => write!(
                f,
                "HTTP/3 frame payload is incomplete: need {required} bytes, have {available}"
            ),
        }
    }
}

impl core::error::Error for Http3FrameParseError {}

/// Identifies an HTTP/3 frame payload field whose variable-length integer is malformed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3FramePayloadField {
    /// A Push ID field.
    PushId,
    /// The role-neutral identifier carried by a GOAWAY frame.
    GoawayIdentifier,
    /// A SETTINGS parameter identifier.
    SettingIdentifier,
    /// A SETTINGS parameter value.
    SettingValue,
}

impl fmt::Display for Http3FramePayloadField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PushId => f.write_str("Push ID"),
            Self::GoawayIdentifier => f.write_str("GOAWAY identifier"),
            Self::SettingIdentifier => f.write_str("SETTINGS identifier"),
            Self::SettingValue => f.write_str("SETTINGS value"),
        }
    }
}

/// Failure to parse the intrinsic payload layout of a standard HTTP/3 frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3FramePayloadParseError {
    /// Parsing the raw HTTP/3 frame envelope failed.
    Frame(Http3FrameParseError),
    /// The raw frame type does not match the typed view.
    WrongFrameType {
        /// Frame type required by the typed view.
        expected: super::Http3FrameType,
        /// Frame type carried by the raw frame.
        actual: super::Http3FrameType,
    },
    /// A payload variable-length integer is malformed.
    PayloadVarInt {
        /// Field whose variable-length integer could not be parsed.
        field: Http3FramePayloadField,
        /// Byte offset within the frame payload.
        offset: usize,
        /// Underlying QUIC variable-length integer failure.
        error: QuicVarIntParseError,
    },
    /// An exact-layout payload has bytes after its required field.
    TrailingPayload {
        /// Bytes consumed by the required payload fields.
        consumed: usize,
        /// Total payload length in bytes.
        actual: usize,
    },
}

impl fmt::Display for Http3FramePayloadParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "HTTP/3 frame: {error}"),
            Self::WrongFrameType { expected, actual } => write!(
                f,
                "wrong HTTP/3 frame type: expected {}, got {}",
                expected.value(),
                actual.value()
            ),
            Self::PayloadVarInt {
                field,
                offset,
                error,
            } => write!(
                f,
                "HTTP/3 {field} variable-length integer at payload offset {offset}: {error}"
            ),
            Self::TrailingPayload { consumed, actual } => write!(
                f,
                "HTTP/3 frame payload has trailing bytes: consumed {consumed}, got {actual}"
            ),
        }
    }
}

impl core::error::Error for Http3FramePayloadParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::WrongFrameType { .. }
            | Self::PayloadVarInt { .. }
            | Self::TrailingPayload { .. } => None,
        }
    }
}

/// Failure to strictly validate HTTP/3 SETTINGS semantics.
///
/// Offsets are byte offsets of setting identifiers from the start of the SETTINGS payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3SettingsSemanticError {
    /// A SETTINGS identifier repeats an earlier identifier.
    DuplicateSetting {
        /// Repeated raw setting identifier.
        id: super::Http3SettingId,
        /// Byte offset of this setting identifier within the SETTINGS payload.
        offset: usize,
    },
    /// A SETTINGS identifier is reserved for HTTP/2.
    ProhibitedSetting {
        /// Reserved raw setting identifier.
        id: super::Http3SettingId,
        /// Byte offset of this setting identifier within the SETTINGS payload.
        offset: usize,
    },
}

impl fmt::Display for Http3SettingsSemanticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateSetting { id, offset } => write!(
                f,
                "HTTP/3 SETTINGS identifier {} at payload offset {offset} duplicates an earlier identifier",
                id.value()
            ),
            Self::ProhibitedSetting { id, offset } => write!(
                f,
                "HTTP/3 SETTINGS identifier {} at payload offset {offset} is reserved for HTTP/2",
                id.value()
            ),
        }
    }
}

impl core::error::Error for Http3SettingsSemanticError {}

/// Failure to sequence a received frame on an HTTP/3 control stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3ControlStreamError {
    /// The first control-stream frame was not SETTINGS.
    MissingSettings {
        /// Actual first frame type.
        actual: super::Http3FrameType,
    },
    /// A frame is forbidden in its current control-stream position or endpoint role.
    UnexpectedFrame {
        /// Forbidden frame type.
        frame_type: super::Http3FrameType,
    },
    /// A known control-stream frame has a malformed intrinsic payload.
    FramePayload {
        /// Type of the frame with the malformed payload.
        frame_type: super::Http3FrameType,
        /// Intrinsic payload parsing failure.
        error: Http3FramePayloadParseError,
    },
    /// SETTINGS failed strict semantic validation.
    Settings(Http3SettingsSemanticError),
    /// A client received GOAWAY with a non-client-bidirectional stream identifier.
    InvalidGoawayStreamId {
        /// Invalid GOAWAY identifier.
        identifier: u64,
    },
    /// A later GOAWAY identifier increased.
    IncreasedGoawayIdentifier {
        /// Previously accepted GOAWAY identifier.
        previous: u64,
        /// Later, invalid larger GOAWAY identifier.
        current: u64,
    },
    /// A later MAX_PUSH_ID decreased.
    ReducedMaximumPushId {
        /// Previously accepted maximum Push ID.
        previous: super::Http3PushId,
        /// Later, invalid smaller maximum Push ID.
        current: super::Http3PushId,
    },
}

impl Http3ControlStreamError {
    /// Returns the HTTP/3 application error code required by this failure.
    pub const fn error_code(self) -> super::Http3ErrorCode {
        match self {
            Self::MissingSettings { .. } => super::Http3ErrorCode::MISSING_SETTINGS,
            Self::UnexpectedFrame { .. } => super::Http3ErrorCode::FRAME_UNEXPECTED,
            Self::FramePayload { .. } => super::Http3ErrorCode::FRAME_ERROR,
            Self::Settings(_) => super::Http3ErrorCode::SETTINGS_ERROR,
            Self::InvalidGoawayStreamId { .. }
            | Self::IncreasedGoawayIdentifier { .. }
            | Self::ReducedMaximumPushId { .. } => super::Http3ErrorCode::ID_ERROR,
        }
    }
}

impl fmt::Display for Http3ControlStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSettings { actual } => write!(
                f,
                "HTTP/3 control stream starts with frame type {} instead of SETTINGS",
                actual.value()
            ),
            Self::UnexpectedFrame { frame_type } => write!(
                f,
                "HTTP/3 frame type {} is unexpected on the control stream",
                frame_type.value()
            ),
            Self::FramePayload { frame_type, error } => write!(
                f,
                "HTTP/3 control-stream frame type {} payload: {error}",
                frame_type.value()
            ),
            Self::Settings(error) => write!(f, "HTTP/3 control-stream SETTINGS: {error}"),
            Self::InvalidGoawayStreamId { identifier } => write!(
                f,
                "HTTP/3 GOAWAY identifier {identifier} is not a client-initiated bidirectional stream ID"
            ),
            Self::IncreasedGoawayIdentifier { previous, current } => write!(
                f,
                "HTTP/3 GOAWAY identifier increased from {previous} to {current}"
            ),
            Self::ReducedMaximumPushId { previous, current } => write!(
                f,
                "HTTP/3 MAX_PUSH_ID decreased from {} to {}",
                previous.value(),
                current.value()
            ),
        }
    }
}

impl core::error::Error for Http3ControlStreamError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::FramePayload { error, .. } => Some(error),
            Self::Settings(error) => Some(error),
            Self::MissingSettings { .. }
            | Self::UnexpectedFrame { .. }
            | Self::InvalidGoawayStreamId { .. }
            | Self::IncreasedGoawayIdentifier { .. }
            | Self::ReducedMaximumPushId { .. } => None,
        }
    }
}

/// Failure to sequence a received frame on an HTTP/3 message stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3MessageStreamError {
    /// A frame is forbidden in the current message position or stream kind.
    UnexpectedFrame {
        /// Forbidden frame type.
        frame_type: super::Http3FrameType,
        /// Message position at which the frame was received.
        position: super::Http3MessagePosition,
    },
    /// An allowed known frame has a malformed intrinsic payload.
    FramePayload {
        /// Type of the frame with the malformed payload.
        frame_type: super::Http3FrameType,
        /// Intrinsic payload parsing failure.
        error: Http3FramePayloadParseError,
    },
    /// A QPACK-decoded header section is invalid for the current message position.
    InvalidHeaderSection {
        /// Incoming message stream kind.
        stream_kind: super::Http3MessageStreamKind,
        /// Message position at which HEADERS was received.
        position: super::Http3MessagePosition,
        /// QPACK-decoded header-section role supplied by the caller.
        section_kind: super::Http3HeaderSectionKind,
    },
    /// The stream ended before its initial or final response header section was accepted.
    IncompleteMessage {
        /// Incoming message stream kind.
        stream_kind: super::Http3MessageStreamKind,
        /// Message position at stream end.
        position: super::Http3MessagePosition,
    },
}

impl Http3MessageStreamError {
    /// Returns the HTTP/3 application error code required by this failure.
    pub const fn error_code(self) -> super::Http3ErrorCode {
        match self {
            Self::UnexpectedFrame { .. } => super::Http3ErrorCode::FRAME_UNEXPECTED,
            Self::FramePayload { .. } => super::Http3ErrorCode::FRAME_ERROR,
            Self::InvalidHeaderSection { .. } => super::Http3ErrorCode::MESSAGE_ERROR,
            Self::IncompleteMessage {
                stream_kind: super::Http3MessageStreamKind::Request,
                ..
            } => super::Http3ErrorCode::REQUEST_INCOMPLETE,
            Self::IncompleteMessage {
                stream_kind:
                    super::Http3MessageStreamKind::Response | super::Http3MessageStreamKind::Push,
                ..
            } => super::Http3ErrorCode::MESSAGE_ERROR,
        }
    }
}

impl fmt::Display for Http3MessageStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedFrame {
                frame_type,
                position,
            } => write!(
                f,
                "HTTP/3 frame type {} is unexpected at message position {position:?}",
                frame_type.value()
            ),
            Self::FramePayload { frame_type, error } => write!(
                f,
                "HTTP/3 message frame type {} payload: {error}",
                frame_type.value()
            ),
            Self::InvalidHeaderSection {
                stream_kind,
                position,
                section_kind,
            } => write!(
                f,
                "HTTP/3 {section_kind:?} header section is invalid for {stream_kind:?} at message position {position:?}"
            ),
            Self::IncompleteMessage {
                stream_kind,
                position,
            } => write!(
                f,
                "HTTP/3 {stream_kind:?} message is incomplete at message position {position:?}"
            ),
        }
    }
}

impl core::error::Error for Http3MessageStreamError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::FramePayload { error, .. } => Some(error),
            Self::UnexpectedFrame { .. }
            | Self::InvalidHeaderSection { .. }
            | Self::IncompleteMessage { .. } => None,
        }
    }
}

/// Failure to build an HTTP/3 frame in caller-provided storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3FrameBuildError {
    /// The frame type cannot be encoded as a QUIC variable-length integer.
    TypeVarInt(QuicVarIntBuildError),
    /// The payload length cannot be encoded as a QUIC variable-length integer.
    LengthVarInt(QuicVarIntBuildError),
    /// The payload length cannot be represented as `u64`.
    PayloadLengthNotRepresentable {
        /// Supplied payload length.
        length: usize,
    },
    /// Adding the encoded header and payload lengths overflows `usize`.
    FrameLengthOverflow {
        /// Encoded type length in bytes.
        type_length: usize,
        /// Encoded payload-length length in bytes.
        length_length: usize,
        /// Supplied payload length in bytes.
        payload_length: usize,
    },
    /// The caller buffer cannot contain the complete frame.
    BufferTooShort {
        /// Bytes required for the complete frame.
        required: usize,
        /// Bytes available in the destination.
        available: usize,
    },
}

impl fmt::Display for Http3FrameBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeVarInt(error) => {
                write!(f, "HTTP/3 frame type variable-length integer: {error}")
            }
            Self::LengthVarInt(error) => {
                write!(
                    f,
                    "HTTP/3 frame payload length variable-length integer: {error}"
                )
            }
            Self::PayloadLengthNotRepresentable { length } => write!(
                f,
                "HTTP/3 frame payload length {length} cannot be represented as u64"
            ),
            Self::FrameLengthOverflow {
                type_length,
                length_length,
                payload_length,
            } => write!(
                f,
                "HTTP/3 frame length overflows: type {type_length} bytes, length {length_length} bytes, payload {payload_length} bytes"
            ),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "HTTP/3 frame destination is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

impl core::error::Error for Http3FrameBuildError {}

/// Failure to build an HTTP/3 frame whose payload contains structured fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3FramePayloadBuildError {
    /// Building the raw HTTP/3 frame envelope failed.
    Frame(Http3FrameBuildError),
    /// A payload field cannot be canonically encoded as a QUIC variable-length integer.
    PayloadVarInt {
        /// Field whose value could not be encoded.
        field: Http3FramePayloadField,
        /// Underlying QUIC variable-length integer failure.
        error: QuicVarIntBuildError,
    },
    /// Adding payload components overflowed `usize`.
    PayloadLengthOverflow {
        /// Index of the settings entry being accumulated, if applicable.
        index: Option<usize>,
        /// Accumulated payload length before the addition.
        current: usize,
        /// Component length being added.
        addition: usize,
    },
    /// The caller-provided SETTINGS workspace is too short.
    SettingsScratchTooShort {
        /// Bytes required for the canonical SETTINGS payload.
        required: usize,
        /// Bytes available in the caller workspace.
        available: usize,
    },
    /// The outgoing SETTINGS list contains the same identifier more than once.
    DuplicateSetting {
        /// Repeated raw setting identifier.
        id: super::Http3SettingId,
    },
    /// The outgoing SETTINGS list contains an HTTP/2-only reserved identifier.
    ProhibitedSetting {
        /// Reserved raw setting identifier.
        id: super::Http3SettingId,
    },
}

impl fmt::Display for Http3FramePayloadBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "HTTP/3 frame: {error}"),
            Self::PayloadVarInt { field, error } => {
                write!(f, "HTTP/3 {field} variable-length integer: {error}")
            }
            Self::PayloadLengthOverflow {
                index,
                current,
                addition,
            } => match index {
                Some(index) => write!(
                    f,
                    "HTTP/3 SETTINGS payload length overflows at entry {index}: {current} plus {addition} bytes"
                ),
                None => write!(
                    f,
                    "HTTP/3 frame payload length overflows: {current} plus {addition} bytes"
                ),
            },
            Self::SettingsScratchTooShort {
                required,
                available,
            } => write!(
                f,
                "HTTP/3 SETTINGS workspace is too short: need {required} bytes, have {available}"
            ),
            Self::DuplicateSetting { id } => {
                write!(
                    f,
                    "HTTP/3 SETTINGS contains duplicate identifier {}",
                    id.value()
                )
            }
            Self::ProhibitedSetting { id } => write!(
                f,
                "HTTP/3 SETTINGS identifier {} is reserved for HTTP/2",
                id.value()
            ),
        }
    }
}

impl core::error::Error for Http3FramePayloadBuildError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::PayloadVarInt { .. }
            | Self::PayloadLengthOverflow { .. }
            | Self::SettingsScratchTooShort { .. }
            | Self::DuplicateSetting { .. }
            | Self::ProhibitedSetting { .. } => None,
        }
    }
}

/// Identifies a variable-length integer field in an HTTP/3 unidirectional stream header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3UniStreamField {
    /// The unidirectional stream type.
    StreamType,
    /// The Push ID following a push stream type.
    PushId,
}

impl fmt::Display for Http3UniStreamField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StreamType => f.write_str("stream type"),
            Self::PushId => f.write_str("Push ID"),
        }
    }
}

/// Failure to parse an HTTP/3 unidirectional stream header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3UniStreamParseError {
    /// A required header variable-length integer is incomplete.
    VarInt {
        /// Field whose variable-length integer could not be parsed.
        field: Http3UniStreamField,
        /// Byte offset from the beginning of the stream header.
        offset: usize,
        /// Underlying QUIC variable-length integer failure.
        error: QuicVarIntParseError,
    },
}

impl fmt::Display for Http3UniStreamParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VarInt {
                field,
                offset,
                error,
            } => write!(
                f,
                "HTTP/3 unidirectional stream {field} variable-length integer at offset {offset}: {error}"
            ),
        }
    }
}

impl core::error::Error for Http3UniStreamParseError {}

/// Failure to build an HTTP/3 unidirectional stream header in caller-provided storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3UniStreamBuildError {
    /// A header variable-length integer cannot be canonically encoded.
    VarInt {
        /// Field whose value could not be encoded.
        field: Http3UniStreamField,
        /// Underlying QUIC variable-length integer failure.
        error: QuicVarIntBuildError,
    },
    /// Adding encoded header field lengths overflowed `usize`.
    LengthOverflow {
        /// First encoded field length in bytes.
        first: usize,
        /// Second encoded field length in bytes.
        second: usize,
    },
    /// The caller buffer cannot contain the complete header.
    BufferTooShort {
        /// Bytes required for the complete header.
        required: usize,
        /// Bytes available in the destination.
        available: usize,
    },
    /// A known stream type was incorrectly supplied as `Unknown`.
    KnownTypeMarkedUnknown {
        /// Known raw stream type value supplied as `Unknown`.
        stream_type: super::Http3StreamType,
    },
}

impl fmt::Display for Http3UniStreamBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VarInt { field, error } => {
                write!(
                    f,
                    "HTTP/3 unidirectional stream {field} variable-length integer: {error}"
                )
            }
            Self::LengthOverflow { first, second } => write!(
                f,
                "HTTP/3 unidirectional stream header length overflows: {first} plus {second} bytes"
            ),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "HTTP/3 unidirectional stream destination is too short: need {required} bytes, have {available}"
            ),
            Self::KnownTypeMarkedUnknown { stream_type } => write!(
                f,
                "HTTP/3 known unidirectional stream type {} cannot be marked unknown",
                stream_type.value()
            ),
        }
    }
}

impl core::error::Error for Http3UniStreamBuildError {}

/// Failure while registering or closing a peer HTTP/3 unidirectional stream.
///
/// [`Self::InvalidPeerUnidirectionalStream`] is a local integration error. The remaining
/// variants are peer-caused HTTP/3 connection errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3PeerUniStreamError {
    /// The supplied stream ID is not a valid peer-initiated unidirectional QUIC stream ID.
    InvalidPeerUnidirectionalStream {
        /// Invalid raw QUIC stream identifier.
        stream_id: super::Http3StreamId,
    },
    /// The peer opened a second stream for a required unique critical-stream kind.
    DuplicateCriticalStream {
        /// Duplicated critical-stream kind.
        kind: super::Http3CriticalUniStreamKind,
        /// Previously registered peer stream identifier.
        existing: super::Http3StreamId,
        /// Newly received duplicate peer stream identifier.
        received: super::Http3StreamId,
    },
    /// A client opened a server-only push stream.
    ClientInitiatedPushStream {
        /// Client-initiated QUIC stream identifier.
        stream_id: super::Http3StreamId,
        /// Push ID carried by the invalid stream header.
        push_id: super::Http3PushId,
    },
    /// A peer closed or reset a registered critical stream.
    ClosedCriticalStream {
        /// Closed critical-stream kind.
        kind: super::Http3CriticalUniStreamKind,
        /// Closed peer stream identifier.
        stream_id: super::Http3StreamId,
    },
}

impl Http3PeerUniStreamError {
    /// Returns the HTTP/3 application error code for a peer-caused failure.
    pub const fn error_code(self) -> Option<super::Http3ErrorCode> {
        match self {
            Self::InvalidPeerUnidirectionalStream { .. } => None,
            Self::DuplicateCriticalStream { .. } | Self::ClientInitiatedPushStream { .. } => {
                Some(super::Http3ErrorCode::STREAM_CREATION_ERROR)
            }
            Self::ClosedCriticalStream { .. } => {
                Some(super::Http3ErrorCode::CLOSED_CRITICAL_STREAM)
            }
        }
    }
}

impl fmt::Display for Http3PeerUniStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPeerUnidirectionalStream { stream_id } => write!(
                f,
                "stream ID {} is not a peer-initiated unidirectional QUIC stream",
                stream_id.value()
            ),
            Self::DuplicateCriticalStream {
                kind,
                existing,
                received,
            } => write!(
                f,
                "HTTP/3 {kind:?} critical stream {} duplicates stream {}",
                received.value(),
                existing.value()
            ),
            Self::ClientInitiatedPushStream { stream_id, push_id } => write!(
                f,
                "client-initiated HTTP/3 push stream {} carries Push ID {}",
                stream_id.value(),
                push_id.value()
            ),
            Self::ClosedCriticalStream { kind, stream_id } => write!(
                f,
                "HTTP/3 {kind:?} critical stream {} was closed",
                stream_id.value()
            ),
        }
    }
}

impl core::error::Error for Http3PeerUniStreamError {}

/// Failure while decoding a QPACK field section carried by an HTTP/3 frame.
///
/// [`Self::DecompressionFailed`] is a peer-caused HTTP/3 connection error.
/// [`Self::OutputProvisioning`] reports insufficient caller output storage and is local, so it
/// must not be sent as an HTTP/3 peer error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3QpackFieldSectionError {
    /// The peer's field section failed QPACK decompression.
    DecompressionFailed(QpackFieldSectionDecodeError),
    /// Caller-provided decoded-field output was insufficient.
    OutputProvisioning(QpackFieldSectionDecodeError),
}

impl Http3QpackFieldSectionError {
    /// Returns the HTTP/3 connection error code when this failure is peer-caused.
    pub const fn error_code(self) -> Option<super::Http3ErrorCode> {
        match self {
            Self::DecompressionFailed(_) => Some(super::Http3ErrorCode::QPACK_DECOMPRESSION_FAILED),
            Self::OutputProvisioning(_) => None,
        }
    }
}

impl From<QpackFieldSectionDecodeError> for Http3QpackFieldSectionError {
    fn from(error: QpackFieldSectionDecodeError) -> Self {
        match error.is_decompression_failed() {
            true => Self::DecompressionFailed(error),
            false => Self::OutputProvisioning(error),
        }
    }
}

impl fmt::Display for Http3QpackFieldSectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecompressionFailed(error) => {
                write!(f, "HTTP/3 QPACK decompression failed: {error}")
            }
            Self::OutputProvisioning(error) => {
                write!(
                    f,
                    "HTTP/3 QPACK output provisioning failed locally: {error}"
                )
            }
        }
    }
}

impl core::error::Error for Http3QpackFieldSectionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::DecompressionFailed(error) | Self::OutputProvisioning(error) => Some(error),
        }
    }
}

/// Failure to semantically validate a decoded HTTP/3 field section.
///
/// `field_index` values identify decoded fields in wire order. They are not byte offsets because
/// QPACK decoding does not retain a field's encoded wire offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3HeaderSectionError {
    /// Adding a decoded field's RFC 9114 size contribution overflowed `u64`.
    FieldSectionSizeOverflow {
        /// Index of the field whose contribution overflowed.
        field_index: usize,
    },
    /// A regular field name is empty or not an HTTP token.
    InvalidFieldName {
        /// Index of the invalid field.
        field_index: usize,
    },
    /// A regular field name contains an uppercase ASCII byte.
    UppercaseFieldName {
        /// Index of the invalid field.
        field_index: usize,
    },
    /// A field value contains invalid HTTP field-content or leading/trailing whitespace.
    InvalidFieldValue {
        /// Index of the invalid field.
        field_index: usize,
    },
    /// A pseudo-field follows a regular field.
    PseudoFieldAfterRegular {
        /// Index of the misplaced pseudo-field.
        field_index: usize,
    },
    /// A trailer section contains a pseudo-field.
    PseudoFieldInTrailers {
        /// Index of the forbidden pseudo-field.
        field_index: usize,
    },
    /// A pseudo-field is unknown or forbidden for this section context.
    InvalidPseudoField {
        /// Index of the invalid pseudo-field.
        field_index: usize,
    },
    /// A pseudo-field repeats an earlier pseudo-field.
    DuplicatePseudoField {
        /// Index of the repeated pseudo-field.
        field_index: usize,
    },
    /// A required pseudo-field is absent.
    MissingPseudoField {
        /// Name of the missing pseudo-field.
        name: &'static [u8],
    },
    /// A connection-specific field is forbidden in HTTP/3.
    ConnectionSpecificField {
        /// Index of the forbidden field.
        field_index: usize,
    },
    /// A `te` field is forbidden here or does not contain only `trailers` values.
    InvalidTe {
        /// Index of the invalid field.
        field_index: usize,
    },
    /// A `host` field repeats an earlier Host field.
    DuplicateHost {
        /// Index of the repeated Host field.
        field_index: usize,
    },
    /// A request has neither a nonempty `:authority` nor a nonempty Host field.
    MissingAuthorityOrHost,
    /// A `:authority` value is invalid for the request form.
    InvalidAuthority {
        /// Index of the invalid `:authority` field.
        field_index: usize,
    },
    /// A Host field is empty.
    InvalidHost {
        /// Index of the invalid Host field.
        field_index: usize,
    },
    /// `:authority` and Host are both present but differ.
    AuthorityHostMismatch {
        /// Index of the `:authority` field.
        authority_field_index: usize,
        /// Index of the Host field.
        host_field_index: usize,
    },
    /// The `:method` pseudo-field is empty or not an HTTP token.
    InvalidMethod {
        /// Index of the invalid `:method` field.
        field_index: usize,
    },
    /// The `:scheme` pseudo-field is empty or malformed.
    InvalidScheme {
        /// Index of the invalid `:scheme` field.
        field_index: usize,
    },
    /// The `:path` pseudo-field is empty or invalid for an HTTP scheme.
    InvalidPath {
        /// Index of the invalid `:path` field.
        field_index: usize,
    },
    /// The `:protocol` pseudo-field is disabled, malformed, or not paired with CONNECT.
    InvalidProtocol {
        /// Index of the invalid `:protocol` field.
        field_index: usize,
    },
    /// An ordinary CONNECT request contains `:scheme` or `:path`.
    InvalidConnectPseudoFields {
        /// Index of the first forbidden pseudo-field.
        field_index: usize,
    },
    /// The `:status` pseudo-field is malformed, forbidden, or outside the accepted range.
    InvalidStatus {
        /// Index of the invalid `:status` field.
        field_index: usize,
    },
}

impl Http3HeaderSectionError {
    /// Returns the HTTP/3 application error code required by every semantic field-section error.
    pub const fn error_code(self) -> super::Http3ErrorCode {
        super::Http3ErrorCode::MESSAGE_ERROR
    }
}

impl fmt::Display for Http3HeaderSectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldSectionSizeOverflow { field_index } => write!(
                f,
                "HTTP/3 field {field_index} makes the field-section size overflow"
            ),
            Self::InvalidFieldName { field_index } => {
                write!(f, "HTTP/3 field {field_index} has an invalid name")
            }
            Self::UppercaseFieldName { field_index } => {
                write!(f, "HTTP/3 field {field_index} has an uppercase name")
            }
            Self::InvalidFieldValue { field_index } => {
                write!(f, "HTTP/3 field {field_index} has an invalid value")
            }
            Self::PseudoFieldAfterRegular { field_index } => write!(
                f,
                "HTTP/3 pseudo-field {field_index} follows a regular field"
            ),
            Self::PseudoFieldInTrailers { field_index } => {
                write!(f, "HTTP/3 trailer pseudo-field {field_index} is forbidden")
            }
            Self::InvalidPseudoField { field_index } => write!(
                f,
                "HTTP/3 pseudo-field {field_index} is invalid for this context"
            ),
            Self::DuplicatePseudoField { field_index } => write!(
                f,
                "HTTP/3 pseudo-field {field_index} duplicates an earlier pseudo-field"
            ),
            Self::MissingPseudoField { name } => write!(
                f,
                "HTTP/3 field section is missing required pseudo-field {name:?}"
            ),
            Self::ConnectionSpecificField { field_index } => {
                write!(f, "HTTP/3 field {field_index} is connection-specific")
            }
            Self::InvalidTe { field_index } => {
                write!(f, "HTTP/3 TE field {field_index} is invalid")
            }
            Self::DuplicateHost { field_index } => write!(
                f,
                "HTTP/3 Host field {field_index} duplicates an earlier Host field"
            ),
            Self::MissingAuthorityOrHost => {
                f.write_str("HTTP/3 request is missing :authority and Host")
            }
            Self::InvalidAuthority { field_index } => {
                write!(f, "HTTP/3 :authority field {field_index} is invalid")
            }
            Self::InvalidHost { field_index } => {
                write!(f, "HTTP/3 Host field {field_index} is invalid")
            }
            Self::AuthorityHostMismatch {
                authority_field_index,
                host_field_index,
            } => write!(
                f,
                "HTTP/3 :authority field {authority_field_index} and Host field {host_field_index} differ"
            ),
            Self::InvalidMethod { field_index } => {
                write!(f, "HTTP/3 :method field {field_index} is invalid")
            }
            Self::InvalidScheme { field_index } => {
                write!(f, "HTTP/3 :scheme field {field_index} is invalid")
            }
            Self::InvalidPath { field_index } => {
                write!(f, "HTTP/3 :path field {field_index} is invalid")
            }
            Self::InvalidProtocol { field_index } => {
                write!(f, "HTTP/3 :protocol field {field_index} is invalid")
            }
            Self::InvalidConnectPseudoFields { field_index } => write!(
                f,
                "HTTP/3 ordinary CONNECT pseudo-field {field_index} is forbidden"
            ),
            Self::InvalidStatus { field_index } => {
                write!(f, "HTTP/3 :status field {field_index} is invalid")
            }
        }
    }
}

impl core::error::Error for Http3HeaderSectionError {}

/// Failure while accounting for HTTP message content and Content-Length.
///
/// Local operation sequencing and tunnel handoff failures have no HTTP/3 peer error code. The
/// remaining variants describe peer message-content violations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3MessageContentError {
    /// A Content-Length list member is empty or not an ASCII decimal number.
    InvalidContentLength {
        /// Decoded field index in wire order.
        field_index: usize,
        /// Comma-separated member index within the field value.
        member_index: usize,
    },
    /// A Content-Length list member overflows `u64`.
    ContentLengthOverflow {
        /// Decoded field index in wire order.
        field_index: usize,
        /// Comma-separated member index within the field value.
        member_index: usize,
    },
    /// A Content-Length list member differs from the earlier normalized value.
    ConflictingContentLength {
        /// Decoded field index in wire order.
        field_index: usize,
        /// Comma-separated member index within the field value.
        member_index: usize,
        /// Earlier normalized Content-Length.
        expected: u64,
        /// Conflicting normalized Content-Length.
        actual: u64,
    },
    /// A trailer field section contains Content-Length.
    ContentLengthInTrailers {
        /// Decoded trailer field index in wire order.
        field_index: usize,
    },
    /// Content-Length is forbidden for this message form.
    ProhibitedContentLength {
        /// Decoded field index in wire order.
        field_index: usize,
    },
    /// A validated header section was supplied at the wrong content-accounting operation.
    UnexpectedHeaderSection {
        /// Operation expected by content accounting.
        expected: super::Http3MessageContentOperation,
        /// Validated role carried by the supplied section.
        actual: super::Http3HeaderSectionKind,
    },
    /// A local content-accounting operation cannot proceed in the current message phase.
    OperationNotReady {
        /// Operation that cannot proceed.
        operation: super::Http3MessageContentOperation,
    },
    /// DATA is forbidden because this message form has no HTTP content.
    ContentNotAllowed {
        /// Forbidden DATA payload length.
        data_length: usize,
    },
    /// A DATA payload length cannot be represented as `u64`.
    DataLengthNotRepresentable {
        /// DATA payload length.
        length: usize,
    },
    /// Adding a DATA payload length overflows cumulative received length.
    ReceivedLengthOverflow {
        /// Cumulative length before the DATA frame.
        received_length: u64,
        /// DATA payload length after conversion to `u64`.
        frame_length: u64,
    },
    /// Received HTTP content does not equal the declared Content-Length.
    ContentLengthMismatch {
        /// Declared normalized Content-Length.
        declared: u64,
        /// Received HTTP content length.
        received: u64,
    },
    /// A caller supplied an HTTP-content operation after CONNECT tunnel handoff.
    NotHttpMessageContent,
    /// The message ended before required initial or final headers were accepted.
    IncompleteMessage,
}

impl Http3MessageContentError {
    /// Returns the HTTP/3 peer error code when this failure is peer-caused.
    pub const fn error_code(self) -> Option<super::Http3ErrorCode> {
        match self {
            Self::UnexpectedHeaderSection { .. }
            | Self::OperationNotReady { .. }
            | Self::NotHttpMessageContent => None,
            Self::InvalidContentLength { .. }
            | Self::ContentLengthOverflow { .. }
            | Self::ConflictingContentLength { .. }
            | Self::ContentLengthInTrailers { .. }
            | Self::ProhibitedContentLength { .. }
            | Self::ContentNotAllowed { .. }
            | Self::DataLengthNotRepresentable { .. }
            | Self::ReceivedLengthOverflow { .. }
            | Self::ContentLengthMismatch { .. }
            | Self::IncompleteMessage => Some(super::Http3ErrorCode::MESSAGE_ERROR),
        }
    }
}

impl fmt::Display for Http3MessageContentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContentLength {
                field_index,
                member_index,
            } => write!(
                f,
                "HTTP/3 Content-Length field {field_index} member {member_index} is invalid"
            ),
            Self::ContentLengthOverflow {
                field_index,
                member_index,
            } => write!(
                f,
                "HTTP/3 Content-Length field {field_index} member {member_index} overflows"
            ),
            Self::ConflictingContentLength {
                field_index,
                member_index,
                expected,
                actual,
            } => write!(
                f,
                "HTTP/3 Content-Length field {field_index} member {member_index} is {actual}, expected {expected}"
            ),
            Self::ContentLengthInTrailers { field_index } => {
                write!(
                    f,
                    "HTTP/3 trailer field {field_index} contains Content-Length"
                )
            }
            Self::ProhibitedContentLength { field_index } => {
                write!(
                    f,
                    "HTTP/3 field {field_index} has prohibited Content-Length"
                )
            }
            Self::UnexpectedHeaderSection { expected, actual } => write!(
                f,
                "HTTP/3 {actual:?} header section is unexpected while accepting {expected:?}"
            ),
            Self::OperationNotReady { operation } => {
                write!(
                    f,
                    "HTTP/3 {operation:?} operation is not ready in the current message phase"
                )
            }
            Self::ContentNotAllowed { data_length } => {
                write!(
                    f,
                    "HTTP/3 DATA payload of {data_length} bytes is not allowed"
                )
            }
            Self::DataLengthNotRepresentable { length } => {
                write!(
                    f,
                    "HTTP/3 DATA payload length {length} cannot be represented as u64"
                )
            }
            Self::ReceivedLengthOverflow {
                received_length,
                frame_length,
            } => write!(
                f,
                "HTTP/3 received content length overflows: {received_length} plus {frame_length}"
            ),
            Self::ContentLengthMismatch { declared, received } => write!(
                f,
                "HTTP/3 Content-Length mismatch: declared {declared}, received {received}"
            ),
            Self::NotHttpMessageContent => {
                f.write_str("HTTP/3 operation belongs to CONNECT tunnel handling, not HTTP content")
            }
            Self::IncompleteMessage => f.write_str("HTTP/3 message content headers are incomplete"),
        }
    }
}

impl core::error::Error for Http3MessageContentError {}
