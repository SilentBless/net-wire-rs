//! Typed borrowed HTTP/3 frame payload views, builders, and diagnostics.

use core::fmt;

use crate::quic::varint::{
    QuicVarInt, QuicVarIntBuildError, QuicVarIntBuilder, QuicVarIntLen, QuicVarIntParseError,
};

use super::{
    Http3Frame, Http3FrameBuildError, Http3FrameBuilder, Http3FrameEnvelopePlan,
    Http3FrameParseError,
};
use crate::http3::codepoints::Http3FrameType;
use crate::http3::ids::Http3PushId;

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
        expected: Http3FrameType,
        /// Frame type carried by the raw frame.
        actual: Http3FrameType,
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
        /// Accumulated payload length before the addition.
        current: usize,
        /// Component length being added.
        addition: usize,
    },
}

impl fmt::Display for Http3FramePayloadBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "HTTP/3 frame: {error}"),
            Self::PayloadVarInt { field, error } => {
                write!(f, "HTTP/3 {field} variable-length integer: {error}")
            }
            Self::PayloadLengthOverflow { current, addition } => write!(
                f,
                "HTTP/3 frame payload length overflows: {current} plus {addition} bytes"
            ),
        }
    }
}

impl core::error::Error for Http3FramePayloadBuildError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::PayloadVarInt { .. } | Self::PayloadLengthOverflow { .. } => None,
        }
    }
}

pub(in crate::http3) struct EncodedVarInt {
    bytes: [u8; 8],
    len: QuicVarIntLen,
}

impl EncodedVarInt {
    pub(in crate::http3) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len.byte_len()]
    }

    pub(in crate::http3) const fn byte_len(&self) -> usize {
        self.len.byte_len()
    }
}

pub(in crate::http3) fn encode_varint(value: u64) -> Result<EncodedVarInt, QuicVarIntBuildError> {
    let mut bytes = [0; 8];
    let varint = QuicVarIntBuilder::new(&mut bytes, value).build()?;
    let len = varint.encoded_len();
    Ok(EncodedVarInt { bytes, len })
}

fn envelope(
    frame_type: Http3FrameType,
    payload_length: usize,
    destination: &mut [u8],
) -> Result<Http3FrameEnvelopePlan, Http3FramePayloadBuildError> {
    Http3FrameEnvelopePlan::new(frame_type, payload_length, destination.len())
        .map_err(Http3FramePayloadBuildError::Frame)
}

pub(in crate::http3) fn add_payload(current: usize, addition: usize) -> Option<usize> {
    current.checked_add(addition)
}

/// A validated borrowed HTTP/3 DATA frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3Data<'a> {
    frame: Http3Frame<'a>,
}

impl<'a> Http3Data<'a> {
    /// Assembles a DATA view from a builder-validated frame.
    pub(in crate::http3) const fn from_validated(frame: Http3Frame<'a>) -> Self {
        Self { frame }
    }

    /// Parses the first complete DATA frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FramePayloadParseError> {
        Self::from_frame(
            Http3Frame::parse(bytes, maximum_payload)
                .map_err(Http3FramePayloadParseError::Frame)?,
        )
    }

    /// Validates a raw DATA frame's intrinsic layout.
    pub fn from_frame(frame: Http3Frame<'a>) -> Result<Self, Http3FramePayloadParseError> {
        validate_type(frame, Http3FrameType::DATA)?;
        Ok(Self { frame })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http3Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the complete opaque DATA payload.
    pub fn data(&self) -> &'a [u8] {
        self.frame.payload()
    }
}

/// A validated borrowed HTTP/3 HEADERS frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3Headers<'a> {
    frame: Http3Frame<'a>,
}

impl<'a> Http3Headers<'a> {
    /// Assembles a HEADERS view from a builder-validated frame.
    pub(in crate::http3) const fn from_validated(frame: Http3Frame<'a>) -> Self {
        Self { frame }
    }

    /// Parses the first complete HEADERS frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FramePayloadParseError> {
        Self::from_frame(
            Http3Frame::parse(bytes, maximum_payload)
                .map_err(Http3FramePayloadParseError::Frame)?,
        )
    }

    /// Validates a raw HEADERS frame's intrinsic layout without decoding QPACK.
    pub fn from_frame(frame: Http3Frame<'a>) -> Result<Self, Http3FramePayloadParseError> {
        validate_type(frame, Http3FrameType::HEADERS)?;
        Ok(Self { frame })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http3Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the complete opaque QPACK-encoded field section.
    pub fn encoded_field_section(&self) -> &'a [u8] {
        self.frame.payload()
    }
}

/// A validated borrowed HTTP/3 CANCEL_PUSH frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3CancelPush<'a> {
    frame: Http3Frame<'a>,
    push_id: QuicVarInt<'a>,
}

impl<'a> Http3CancelPush<'a> {
    /// Assembles a CANCEL_PUSH view from builder-validated components.
    pub(in crate::http3) fn from_validated(
        frame: Http3Frame<'a>,
        push_id: Http3PushId,
        push_id_length: QuicVarIntLen,
    ) -> Self {
        let push_id = QuicVarInt::from_validated(
            &frame.payload()[..push_id_length.byte_len()],
            push_id.value(),
            push_id_length,
        );
        Self { frame, push_id }
    }

    /// Parses the first complete CANCEL_PUSH frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FramePayloadParseError> {
        Self::from_frame(
            Http3Frame::parse(bytes, maximum_payload)
                .map_err(Http3FramePayloadParseError::Frame)?,
        )
    }

    /// Validates a raw CANCEL_PUSH frame's intrinsic layout.
    pub fn from_frame(frame: Http3Frame<'a>) -> Result<Self, Http3FramePayloadParseError> {
        validate_type(frame, Http3FrameType::CANCEL_PUSH)?;
        let push_id = parse_exact_varint(frame.payload(), Http3FramePayloadField::PushId)?;
        Ok(Self { frame, push_id })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http3Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the raw-preserving Push ID.
    pub const fn push_id(&self) -> Http3PushId {
        Http3PushId::new(self.push_id.value())
    }

    /// Returns the exact Push ID variable-length integer.
    pub const fn push_id_varint(&self) -> QuicVarInt<'a> {
        self.push_id
    }
}

/// A validated borrowed HTTP/3 PUSH_PROMISE frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3PushPromise<'a> {
    frame: Http3Frame<'a>,
    push_id: QuicVarInt<'a>,
}

impl<'a> Http3PushPromise<'a> {
    /// Assembles a PUSH_PROMISE view from builder-validated components.
    pub(in crate::http3) fn from_validated(
        frame: Http3Frame<'a>,
        push_id: Http3PushId,
        push_id_length: QuicVarIntLen,
    ) -> Self {
        let push_id = QuicVarInt::from_validated(
            &frame.payload()[..push_id_length.byte_len()],
            push_id.value(),
            push_id_length,
        );
        Self { frame, push_id }
    }

    /// Parses the first complete PUSH_PROMISE frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FramePayloadParseError> {
        Self::from_frame(
            Http3Frame::parse(bytes, maximum_payload)
                .map_err(Http3FramePayloadParseError::Frame)?,
        )
    }

    /// Validates a raw PUSH_PROMISE frame's initial Push ID without decoding QPACK.
    pub fn from_frame(frame: Http3Frame<'a>) -> Result<Self, Http3FramePayloadParseError> {
        validate_type(frame, Http3FrameType::PUSH_PROMISE)?;
        let push_id = parse_payload_varint(frame.payload(), Http3FramePayloadField::PushId, 0)?;
        Ok(Self { frame, push_id })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http3Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the raw-preserving Push ID.
    pub const fn push_id(&self) -> Http3PushId {
        Http3PushId::new(self.push_id.value())
    }

    /// Returns the exact Push ID variable-length integer.
    pub const fn push_id_varint(&self) -> QuicVarInt<'a> {
        self.push_id
    }

    /// Returns the remaining opaque QPACK-encoded field section.
    pub fn encoded_field_section(&self) -> &'a [u8] {
        &self.frame.payload()[self.push_id.byte_len()..]
    }
}

/// A validated borrowed HTTP/3 GOAWAY frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3Goaway<'a> {
    frame: Http3Frame<'a>,
    identifier: QuicVarInt<'a>,
}

impl<'a> Http3Goaway<'a> {
    /// Assembles a GOAWAY view from builder-validated components.
    pub(in crate::http3) fn from_validated(
        frame: Http3Frame<'a>,
        identifier: u64,
        identifier_length: QuicVarIntLen,
    ) -> Self {
        let identifier = QuicVarInt::from_validated(
            &frame.payload()[..identifier_length.byte_len()],
            identifier,
            identifier_length,
        );
        Self { frame, identifier }
    }

    /// Parses the first complete GOAWAY frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FramePayloadParseError> {
        Self::from_frame(
            Http3Frame::parse(bytes, maximum_payload)
                .map_err(Http3FramePayloadParseError::Frame)?,
        )
    }

    /// Validates a raw GOAWAY frame's intrinsic layout without assigning identifier role.
    pub fn from_frame(frame: Http3Frame<'a>) -> Result<Self, Http3FramePayloadParseError> {
        validate_type(frame, Http3FrameType::GOAWAY)?;
        let identifier =
            parse_exact_varint(frame.payload(), Http3FramePayloadField::GoawayIdentifier)?;
        Ok(Self { frame, identifier })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http3Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the role-neutral GOAWAY identifier value.
    pub const fn identifier(&self) -> u64 {
        self.identifier.value()
    }

    /// Returns the exact role-neutral GOAWAY identifier variable-length integer.
    pub const fn identifier_varint(&self) -> QuicVarInt<'a> {
        self.identifier
    }
}

/// A validated borrowed HTTP/3 MAX_PUSH_ID frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3MaxPushId<'a> {
    frame: Http3Frame<'a>,
    push_id: QuicVarInt<'a>,
}

impl<'a> Http3MaxPushId<'a> {
    /// Assembles a MAX_PUSH_ID view from builder-validated components.
    pub(in crate::http3) fn from_validated(
        frame: Http3Frame<'a>,
        push_id: Http3PushId,
        push_id_length: QuicVarIntLen,
    ) -> Self {
        let push_id = QuicVarInt::from_validated(
            &frame.payload()[..push_id_length.byte_len()],
            push_id.value(),
            push_id_length,
        );
        Self { frame, push_id }
    }

    /// Parses the first complete MAX_PUSH_ID frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FramePayloadParseError> {
        Self::from_frame(
            Http3Frame::parse(bytes, maximum_payload)
                .map_err(Http3FramePayloadParseError::Frame)?,
        )
    }

    /// Validates a raw MAX_PUSH_ID frame's intrinsic layout.
    pub fn from_frame(frame: Http3Frame<'a>) -> Result<Self, Http3FramePayloadParseError> {
        validate_type(frame, Http3FrameType::MAX_PUSH_ID)?;
        let push_id = parse_exact_varint(frame.payload(), Http3FramePayloadField::PushId)?;
        Ok(Self { frame, push_id })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http3Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns the raw-preserving Push ID.
    pub const fn push_id(&self) -> Http3PushId {
        Http3PushId::new(self.push_id.value())
    }

    /// Returns the exact Push ID variable-length integer.
    pub const fn push_id_varint(&self) -> QuicVarInt<'a> {
        self.push_id
    }
}

pub(in crate::http3) fn validate_type(
    frame: Http3Frame<'_>,
    expected: Http3FrameType,
) -> Result<(), Http3FramePayloadParseError> {
    let actual = frame.frame_type();
    if actual != expected {
        return Err(Http3FramePayloadParseError::WrongFrameType { expected, actual });
    }
    Ok(())
}

pub(in crate::http3) fn parse_payload_varint<'a>(
    bytes: &'a [u8],
    field: Http3FramePayloadField,
    offset: usize,
) -> Result<QuicVarInt<'a>, Http3FramePayloadParseError> {
    QuicVarInt::parse(bytes).map_err(|error| Http3FramePayloadParseError::PayloadVarInt {
        field,
        offset,
        error,
    })
}

fn parse_exact_varint<'a>(
    payload: &'a [u8],
    field: Http3FramePayloadField,
) -> Result<QuicVarInt<'a>, Http3FramePayloadParseError> {
    let varint = parse_payload_varint(payload, field, 0)?;
    if varint.byte_len() != payload.len() {
        return Err(Http3FramePayloadParseError::TrailingPayload {
            consumed: varint.byte_len(),
            actual: payload.len(),
        });
    }
    Ok(varint)
}

/// Builds a typed HTTP/3 DATA frame in caller-owned storage.
pub struct Http3DataBuilder<'output, 'payload> {
    destination: &'output mut [u8],
    data: &'payload [u8],
}

impl<'output, 'payload> Http3DataBuilder<'output, 'payload> {
    /// Creates a DATA builder for opaque payload bytes.
    pub fn new(destination: &'output mut [u8], data: &'payload [u8]) -> Self {
        Self { destination, data }
    }

    /// Canonically encodes and atomically writes the DATA frame.
    pub fn build(self) -> Result<Http3Data<'output>, Http3FrameBuildError> {
        let frame =
            Http3FrameBuilder::new(self.destination, Http3FrameType::DATA, self.data).build()?;
        Ok(Http3Data::from_validated(frame))
    }
}

/// Builds a typed HTTP/3 HEADERS frame in caller-owned storage.
pub struct Http3HeadersBuilder<'output, 'section> {
    destination: &'output mut [u8],
    encoded_field_section: &'section [u8],
}

impl<'output, 'section> Http3HeadersBuilder<'output, 'section> {
    /// Creates a HEADERS builder for an opaque QPACK-encoded field section.
    pub fn new(destination: &'output mut [u8], encoded_field_section: &'section [u8]) -> Self {
        Self {
            destination,
            encoded_field_section,
        }
    }

    /// Canonically encodes and atomically writes the HEADERS frame.
    pub fn build(self) -> Result<Http3Headers<'output>, Http3FrameBuildError> {
        let frame = Http3FrameBuilder::new(
            self.destination,
            Http3FrameType::HEADERS,
            self.encoded_field_section,
        )
        .build()?;
        Ok(Http3Headers::from_validated(frame))
    }
}

/// Builds a typed HTTP/3 CANCEL_PUSH frame in caller-owned storage.
pub struct Http3CancelPushBuilder<'output> {
    destination: &'output mut [u8],
    push_id: Http3PushId,
}

impl<'output> Http3CancelPushBuilder<'output> {
    /// Creates a CANCEL_PUSH builder for a raw Push ID.
    pub fn new(destination: &'output mut [u8], push_id: Http3PushId) -> Self {
        Self {
            destination,
            push_id,
        }
    }

    /// Canonically encodes and atomically writes the CANCEL_PUSH frame.
    pub fn build(self) -> Result<Http3CancelPush<'output>, Http3FramePayloadBuildError> {
        let push_id = encode_varint(self.push_id.value()).map_err(|error| {
            Http3FramePayloadBuildError::PayloadVarInt {
                field: Http3FramePayloadField::PushId,
                error,
            }
        })?;
        let plan = envelope(
            Http3FrameType::CANCEL_PUSH,
            push_id.byte_len(),
            self.destination,
        )?;
        let header_length = plan.header_length();
        let required = plan.required();
        let bytes = &mut self.destination[..required];
        plan.write_header(bytes);
        bytes[header_length..].copy_from_slice(push_id.bytes());
        let frame = plan.finish(bytes);
        Ok(Http3CancelPush::from_validated(
            frame,
            self.push_id,
            push_id.len,
        ))
    }
}

/// Builds a typed HTTP/3 PUSH_PROMISE frame in caller-owned storage.
pub struct Http3PushPromiseBuilder<'output, 'section> {
    destination: &'output mut [u8],
    push_id: Http3PushId,
    encoded_field_section: &'section [u8],
}

impl<'output, 'section> Http3PushPromiseBuilder<'output, 'section> {
    /// Creates a PUSH_PROMISE builder for a raw Push ID and opaque QPACK field section.
    pub fn new(
        destination: &'output mut [u8],
        push_id: Http3PushId,
        encoded_field_section: &'section [u8],
    ) -> Self {
        Self {
            destination,
            push_id,
            encoded_field_section,
        }
    }

    /// Canonically encodes and atomically writes the PUSH_PROMISE frame.
    pub fn build(self) -> Result<Http3PushPromise<'output>, Http3FramePayloadBuildError> {
        let push_id = encode_varint(self.push_id.value()).map_err(|error| {
            Http3FramePayloadBuildError::PayloadVarInt {
                field: Http3FramePayloadField::PushId,
                error,
            }
        })?;
        let payload_length = add_payload(push_id.byte_len(), self.encoded_field_section.len())
            .ok_or(Http3FramePayloadBuildError::PayloadLengthOverflow {
                current: push_id.byte_len(),
                addition: self.encoded_field_section.len(),
            })?;
        let plan = envelope(
            Http3FrameType::PUSH_PROMISE,
            payload_length,
            self.destination,
        )?;
        let header_length = plan.header_length();
        let required = plan.required();
        let bytes = &mut self.destination[..required];
        plan.write_header(bytes);
        let payload = &mut bytes[header_length..];
        let push_id_length = push_id.byte_len();
        payload[..push_id_length].copy_from_slice(push_id.bytes());
        payload[push_id_length..].copy_from_slice(self.encoded_field_section);
        let frame = plan.finish(bytes);
        Ok(Http3PushPromise::from_validated(
            frame,
            self.push_id,
            push_id.len,
        ))
    }
}

/// Builds a typed HTTP/3 GOAWAY frame in caller-owned storage.
pub struct Http3GoawayBuilder<'output> {
    destination: &'output mut [u8],
    identifier: u64,
}

impl<'output> Http3GoawayBuilder<'output> {
    /// Creates a role-neutral GOAWAY builder.
    pub fn new(destination: &'output mut [u8], identifier: u64) -> Self {
        Self {
            destination,
            identifier,
        }
    }

    /// Canonically encodes and atomically writes the GOAWAY frame.
    pub fn build(self) -> Result<Http3Goaway<'output>, Http3FramePayloadBuildError> {
        let identifier = encode_varint(self.identifier).map_err(|error| {
            Http3FramePayloadBuildError::PayloadVarInt {
                field: Http3FramePayloadField::GoawayIdentifier,
                error,
            }
        })?;
        let plan = envelope(
            Http3FrameType::GOAWAY,
            identifier.byte_len(),
            self.destination,
        )?;
        let header_length = plan.header_length();
        let required = plan.required();
        let bytes = &mut self.destination[..required];
        plan.write_header(bytes);
        bytes[header_length..].copy_from_slice(identifier.bytes());
        let frame = plan.finish(bytes);
        Ok(Http3Goaway::from_validated(
            frame,
            self.identifier,
            identifier.len,
        ))
    }
}

/// Builds a typed HTTP/3 MAX_PUSH_ID frame in caller-owned storage.
pub struct Http3MaxPushIdBuilder<'output> {
    destination: &'output mut [u8],
    push_id: Http3PushId,
}

impl<'output> Http3MaxPushIdBuilder<'output> {
    /// Creates a MAX_PUSH_ID builder for a raw Push ID.
    pub fn new(destination: &'output mut [u8], push_id: Http3PushId) -> Self {
        Self {
            destination,
            push_id,
        }
    }

    /// Canonically encodes and atomically writes the MAX_PUSH_ID frame.
    pub fn build(self) -> Result<Http3MaxPushId<'output>, Http3FramePayloadBuildError> {
        let push_id = encode_varint(self.push_id.value()).map_err(|error| {
            Http3FramePayloadBuildError::PayloadVarInt {
                field: Http3FramePayloadField::PushId,
                error,
            }
        })?;
        let plan = envelope(
            Http3FrameType::MAX_PUSH_ID,
            push_id.byte_len(),
            self.destination,
        )?;
        let header_length = plan.header_length();
        let required = plan.required();
        let bytes = &mut self.destination[..required];
        plan.write_header(bytes);
        bytes[header_length..].copy_from_slice(push_id.bytes());
        let frame = plan.finish(bytes);
        Ok(Http3MaxPushId::from_validated(
            frame,
            self.push_id,
            push_id.len,
        ))
    }
}
