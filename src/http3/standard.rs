//! Typed borrowed views of standard HTTP/3 frame layouts.

use core::iter::FusedIterator;

use crate::quic::{QuicVarInt, QuicVarIntLen};

use super::{
    Http3Frame, Http3FramePayloadField, Http3FramePayloadParseError, Http3FrameType, Http3PushId,
    Http3SettingId,
};

/// A validated borrowed HTTP/3 DATA frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3Data<'a> {
    frame: Http3Frame<'a>,
}

impl<'a> Http3Data<'a> {
    /// Assembles a DATA view from a builder-validated frame.
    pub(super) const fn from_validated(frame: Http3Frame<'a>) -> Self {
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
    pub(super) const fn from_validated(frame: Http3Frame<'a>) -> Self {
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
    pub(super) fn from_validated(
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

/// A raw-preserving HTTP/3 SETTINGS parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3Setting<'a> {
    bytes: &'a [u8],
    id: QuicVarInt<'a>,
    value: QuicVarInt<'a>,
}

impl<'a> Http3Setting<'a> {
    /// Returns the exact encoded setting bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the raw-preserving setting identifier.
    pub const fn id(&self) -> Http3SettingId {
        Http3SettingId::new(self.id.value())
    }

    /// Returns the exact setting identifier variable-length integer.
    pub const fn id_varint(&self) -> QuicVarInt<'a> {
        self.id
    }

    /// Returns the decoded setting value.
    pub const fn value(&self) -> u64 {
        self.value.value()
    }

    /// Returns the exact setting value variable-length integer.
    pub const fn value_varint(&self) -> QuicVarInt<'a> {
        self.value
    }
}

/// A validated borrowed HTTP/3 SETTINGS frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3Settings<'a> {
    frame: Http3Frame<'a>,
}

impl<'a> Http3Settings<'a> {
    /// Assembles a SETTINGS view from a builder-validated frame.
    pub(super) const fn from_validated(frame: Http3Frame<'a>) -> Self {
        Self { frame }
    }

    /// Parses the first complete SETTINGS frame, enforcing the caller-provided payload maximum.
    pub fn parse(
        bytes: &'a [u8],
        maximum_payload: usize,
    ) -> Result<Self, Http3FramePayloadParseError> {
        Self::from_frame(
            Http3Frame::parse(bytes, maximum_payload)
                .map_err(Http3FramePayloadParseError::Frame)?,
        )
    }

    /// Validates every SETTINGS identifier and value in wire order.
    pub fn from_frame(frame: Http3Frame<'a>) -> Result<Self, Http3FramePayloadParseError> {
        validate_type(frame, Http3FrameType::SETTINGS)?;
        validate_settings(frame.payload())?;
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

    /// Iterates validated SETTINGS parameters in wire order without combining duplicates.
    pub fn settings(&self) -> Http3SettingsIter<'a> {
        Http3SettingsIter {
            bytes: self.frame.payload(),
        }
    }

    /// Strictly validates SETTINGS semantics and returns effective known peer settings.
    ///
    /// Unknown extension settings are ignored in the returned snapshot. This rejects duplicate
    /// identifiers even though HTTP/3 permits receivers to choose that policy.
    pub fn validate_semantics(
        self,
    ) -> Result<super::Http3PeerSettings, super::Http3SettingsSemanticError> {
        super::settings::validate(self)
    }
}

/// Iterator over eagerly validated HTTP/3 SETTINGS parameters.
#[derive(Clone, Debug)]
pub struct Http3SettingsIter<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for Http3SettingsIter<'a> {
    type Item = Http3Setting<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (setting, remaining) = parse_setting(self.bytes)?;
        self.bytes = remaining;
        Some(setting)
    }
}

impl FusedIterator for Http3SettingsIter<'_> {}

/// A validated borrowed HTTP/3 PUSH_PROMISE frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3PushPromise<'a> {
    frame: Http3Frame<'a>,
    push_id: QuicVarInt<'a>,
}

impl<'a> Http3PushPromise<'a> {
    /// Assembles a PUSH_PROMISE view from builder-validated components.
    pub(super) fn from_validated(
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
    pub(super) fn from_validated(
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
    pub(super) fn from_validated(
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

fn validate_type(
    frame: Http3Frame<'_>,
    expected: Http3FrameType,
) -> Result<(), Http3FramePayloadParseError> {
    let actual = frame.frame_type();
    if actual != expected {
        return Err(Http3FramePayloadParseError::WrongFrameType { expected, actual });
    }
    Ok(())
}

fn parse_payload_varint<'a>(
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

fn validate_settings(payload: &[u8]) -> Result<(), Http3FramePayloadParseError> {
    let mut remaining = payload;
    while !remaining.is_empty() {
        let identifier_offset = payload.len() - remaining.len();
        let identifier = parse_payload_varint(
            remaining,
            Http3FramePayloadField::SettingIdentifier,
            identifier_offset,
        )?;
        remaining = &remaining[identifier.byte_len()..];

        let value_offset = payload.len() - remaining.len();
        let value = parse_payload_varint(
            remaining,
            Http3FramePayloadField::SettingValue,
            value_offset,
        )?;
        remaining = &remaining[value.byte_len()..];
    }
    Ok(())
}

fn parse_setting<'a>(bytes: &'a [u8]) -> Option<(Http3Setting<'a>, &'a [u8])> {
    let id = QuicVarInt::parse(bytes).ok()?;
    let after_id = &bytes[id.byte_len()..];
    let value = QuicVarInt::parse(after_id).ok()?;
    let remaining = &after_id[value.byte_len()..];
    let setting = Http3Setting {
        bytes: &bytes[..bytes.len() - remaining.len()],
        id,
        value,
    };
    Some((setting, remaining))
}
