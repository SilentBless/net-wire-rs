//! Typed, atomic construction of standard HTTP/3 frames.

use crate::quic::{QuicVarIntBuilder, QuicVarIntLen};

use super::builder::Http3FrameEnvelopePlan;
use super::settings::prohibited_setting;
use super::{
    Http3CancelPush, Http3Data, Http3FrameBuildError, Http3FrameBuilder,
    Http3FramePayloadBuildError, Http3FramePayloadField, Http3FrameType, Http3Goaway, Http3Headers,
    Http3MaxPushId, Http3PushId, Http3PushPromise, Http3SettingId, Http3Settings,
};

/// A raw-preserving outbound HTTP/3 SETTINGS identifier and value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http3SettingValue {
    id: Http3SettingId,
    value: u64,
}

impl Http3SettingValue {
    /// Creates an outbound SETTINGS entry without restricting extension identifiers.
    pub const fn new(id: Http3SettingId, value: u64) -> Self {
        Self { id, value }
    }

    /// Returns the raw SETTINGS identifier.
    pub const fn id(self) -> Http3SettingId {
        self.id
    }

    /// Returns the decoded SETTINGS value.
    pub const fn value(self) -> u64 {
        self.value
    }
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
        let push_id = encode_varint(self.push_id.value(), Http3FramePayloadField::PushId)?;
        let plan = envelope(
            Http3FrameType::CANCEL_PUSH,
            push_id.len.byte_len(),
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
        let push_id = encode_varint(self.push_id.value(), Http3FramePayloadField::PushId)?;
        let payload_length = add_payload(
            push_id.len.byte_len(),
            self.encoded_field_section.len(),
            None,
        )?;
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
        let push_id_length = push_id.len.byte_len();
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
        let identifier = encode_varint(self.identifier, Http3FramePayloadField::GoawayIdentifier)?;
        let plan = envelope(
            Http3FrameType::GOAWAY,
            identifier.len.byte_len(),
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
        let push_id = encode_varint(self.push_id.value(), Http3FramePayloadField::PushId)?;
        let plan = envelope(
            Http3FrameType::MAX_PUSH_ID,
            push_id.len.byte_len(),
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

/// Builds a typed HTTP/3 SETTINGS frame in caller-owned storage.
pub struct Http3SettingsBuilder<'output, 'scratch, 'settings> {
    destination: &'output mut [u8],
    payload_scratch: &'scratch mut [u8],
    settings: &'settings [Http3SettingValue],
}

impl<'output, 'scratch, 'settings> Http3SettingsBuilder<'output, 'scratch, 'settings> {
    /// Creates a SETTINGS builder using caller-owned payload workspace.
    ///
    /// Workspace contents are unspecified after an error that occurs after its capacity has been
    /// validated. Destination bytes remain unchanged on every error.
    pub fn new(
        destination: &'output mut [u8],
        payload_scratch: &'scratch mut [u8],
        settings: &'settings [Http3SettingValue],
    ) -> Self {
        Self {
            destination,
            payload_scratch,
            settings,
        }
    }

    /// Canonically encodes semantically valid SETTINGS and atomically writes their frame.
    pub fn build(self) -> Result<Http3Settings<'output>, Http3FramePayloadBuildError> {
        let payload_length = validate_settings(self.settings)?;
        if self.payload_scratch.len() < payload_length {
            return Err(Http3FramePayloadBuildError::SettingsScratchTooShort {
                required: payload_length,
                available: self.payload_scratch.len(),
            });
        }

        let mut offset = 0;
        for setting in self.settings {
            let id = encode_varint(
                setting.id.value(),
                Http3FramePayloadField::SettingIdentifier,
            )?;
            let value = encode_varint(setting.value, Http3FramePayloadField::SettingValue)?;
            let id_end = offset + id.len.byte_len();
            self.payload_scratch[offset..id_end].copy_from_slice(id.bytes());
            let value_end = id_end + value.len.byte_len();
            self.payload_scratch[id_end..value_end].copy_from_slice(value.bytes());
            offset = value_end;
        }

        let frame = Http3FrameBuilder::new(
            self.destination,
            Http3FrameType::SETTINGS,
            &self.payload_scratch[..payload_length],
        )
        .build()
        .map_err(Http3FramePayloadBuildError::Frame)?;
        Ok(Http3Settings::from_validated(frame))
    }
}

struct EncodedVarInt {
    bytes: [u8; 8],
    len: QuicVarIntLen,
}

impl EncodedVarInt {
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len.byte_len()]
    }
}

fn encode_varint(
    value: u64,
    field: Http3FramePayloadField,
) -> Result<EncodedVarInt, Http3FramePayloadBuildError> {
    let mut bytes = [0; 8];
    let varint = QuicVarIntBuilder::new(&mut bytes, value)
        .build()
        .map_err(|error| Http3FramePayloadBuildError::PayloadVarInt { field, error })?;
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

fn add_payload(
    current: usize,
    addition: usize,
    index: Option<usize>,
) -> Result<usize, Http3FramePayloadBuildError> {
    current
        .checked_add(addition)
        .ok_or(Http3FramePayloadBuildError::PayloadLengthOverflow {
            index,
            current,
            addition,
        })
}

fn validate_settings(settings: &[Http3SettingValue]) -> Result<usize, Http3FramePayloadBuildError> {
    let mut payload_length = 0;
    for (index, setting) in settings.iter().copied().enumerate() {
        if prohibited_setting(setting.id) {
            return Err(Http3FramePayloadBuildError::ProhibitedSetting { id: setting.id });
        }
        for previous in &settings[..index] {
            if previous.id == setting.id {
                return Err(Http3FramePayloadBuildError::DuplicateSetting { id: setting.id });
            }
        }
        let id = encode_varint(
            setting.id.value(),
            Http3FramePayloadField::SettingIdentifier,
        )?;
        let value = encode_varint(setting.value, Http3FramePayloadField::SettingValue)?;
        payload_length = add_payload(payload_length, id.len.byte_len(), Some(index))?;
        payload_length = add_payload(payload_length, value.len.byte_len(), Some(index))?;
    }
    Ok(payload_length)
}
