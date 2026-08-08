//! HTTP/3 SETTINGS wire views, construction, and semantic interpretation.

use core::fmt;
use core::iter::FusedIterator;

use crate::quic::{QuicVarInt, QuicVarIntBuildError};

use super::codepoints::{Http3FrameType, Http3SettingId};
use super::frame::{
    Http3Frame, Http3FrameBuildError, Http3FrameBuilder, Http3FramePayloadField,
    Http3FramePayloadParseError, encode_varint, parse_payload_varint, validate_type,
};

/// Failure to build an outbound HTTP/3 SETTINGS frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3SettingsBuildError {
    /// Building the raw HTTP/3 frame envelope failed.
    Frame(Http3FrameBuildError),
    /// A SETTINGS field cannot be canonically encoded as a QUIC variable-length integer.
    SettingVarInt {
        /// Field whose value could not be encoded.
        field: Http3FramePayloadField,
        /// Underlying QUIC variable-length integer failure.
        error: QuicVarIntBuildError,
    },
    /// Adding a SETTINGS entry component overflowed `usize`.
    PayloadLengthOverflow {
        /// Index of the SETTINGS entry being accumulated.
        index: usize,
        /// Accumulated payload length before the addition.
        current: usize,
        /// Component length being added.
        addition: usize,
    },
    /// The caller-provided SETTINGS workspace is too short.
    ScratchTooShort {
        /// Bytes required for the canonical SETTINGS payload.
        required: usize,
        /// Bytes available in the caller workspace.
        available: usize,
    },
    /// The outgoing SETTINGS list contains the same identifier more than once.
    DuplicateSetting {
        /// Repeated raw setting identifier.
        id: Http3SettingId,
    },
    /// The outgoing SETTINGS list contains an HTTP/2-only reserved identifier.
    ProhibitedSetting {
        /// Reserved raw setting identifier.
        id: Http3SettingId,
    },
}

impl fmt::Display for Http3SettingsBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "HTTP/3 frame: {error}"),
            Self::SettingVarInt { field, error } => {
                write!(f, "HTTP/3 {field} variable-length integer: {error}")
            }
            Self::PayloadLengthOverflow {
                index,
                current,
                addition,
            } => write!(
                f,
                "HTTP/3 SETTINGS payload length overflows at entry {index}: {current} plus {addition} bytes"
            ),
            Self::ScratchTooShort {
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

impl core::error::Error for Http3SettingsBuildError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::SettingVarInt { .. }
            | Self::PayloadLengthOverflow { .. }
            | Self::ScratchTooShort { .. }
            | Self::DuplicateSetting { .. }
            | Self::ProhibitedSetting { .. } => None,
        }
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
    const fn from_validated(frame: Http3Frame<'a>) -> Self {
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
    pub fn validate_semantics(self) -> Result<Http3PeerSettings, Http3SettingsSemanticError> {
        validate(self)
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
    pub fn build(self) -> Result<Http3Settings<'output>, Http3SettingsBuildError> {
        let payload_length = validate_outbound_settings(self.settings)?;
        if self.payload_scratch.len() < payload_length {
            return Err(Http3SettingsBuildError::ScratchTooShort {
                required: payload_length,
                available: self.payload_scratch.len(),
            });
        }

        let mut offset = 0;
        for setting in self.settings {
            let id = encode_varint(setting.id.value()).map_err(|error| {
                Http3SettingsBuildError::SettingVarInt {
                    field: Http3FramePayloadField::SettingIdentifier,
                    error,
                }
            })?;
            let value = encode_varint(setting.value).map_err(|error| {
                Http3SettingsBuildError::SettingVarInt {
                    field: Http3FramePayloadField::SettingValue,
                    error,
                }
            })?;
            let id_end = offset + id.byte_len();
            self.payload_scratch[offset..id_end].copy_from_slice(id.bytes());
            let value_end = id_end + value.byte_len();
            self.payload_scratch[id_end..value_end].copy_from_slice(value.bytes());
            offset = value_end;
        }

        let frame = Http3FrameBuilder::new(
            self.destination,
            Http3FrameType::SETTINGS,
            &self.payload_scratch[..payload_length],
        )
        .build()
        .map_err(Http3SettingsBuildError::Frame)?;
        Ok(Http3Settings::from_validated(frame))
    }
}

fn validate_outbound_settings(
    settings: &[Http3SettingValue],
) -> Result<usize, Http3SettingsBuildError> {
    let mut payload_length = 0;
    for (index, setting) in settings.iter().copied().enumerate() {
        if prohibited_setting(setting.id) {
            return Err(Http3SettingsBuildError::ProhibitedSetting { id: setting.id });
        }
        for previous in &settings[..index] {
            if previous.id == setting.id {
                return Err(Http3SettingsBuildError::DuplicateSetting { id: setting.id });
            }
        }
        let id = encode_varint(setting.id.value()).map_err(|error| {
            Http3SettingsBuildError::SettingVarInt {
                field: Http3FramePayloadField::SettingIdentifier,
                error,
            }
        })?;
        let value = encode_varint(setting.value).map_err(|error| {
            Http3SettingsBuildError::SettingVarInt {
                field: Http3FramePayloadField::SettingValue,
                error,
            }
        })?;
        payload_length = add_setting_payload(index, payload_length, id.byte_len())?;
        payload_length = add_setting_payload(index, payload_length, value.byte_len())?;
    }
    Ok(payload_length)
}

fn add_setting_payload(
    index: usize,
    current: usize,
    addition: usize,
) -> Result<usize, Http3SettingsBuildError> {
    current
        .checked_add(addition)
        .ok_or(Http3SettingsBuildError::PayloadLengthOverflow {
            index,
            current,
            addition,
        })
}

/// Failure to strictly validate HTTP/3 SETTINGS semantics.
///
/// Offsets are byte offsets of setting identifiers from the start of the SETTINGS payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3SettingsSemanticError {
    /// A SETTINGS identifier repeats an earlier identifier.
    DuplicateSetting {
        /// Repeated raw setting identifier.
        id: Http3SettingId,
        /// Byte offset of this setting identifier within the SETTINGS payload.
        offset: usize,
    },
    /// A SETTINGS identifier is reserved for HTTP/2.
    ProhibitedSetting {
        /// Reserved raw setting identifier.
        id: Http3SettingId,
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

/// Validates SETTINGS semantics and returns the effective known peer settings.
pub(super) fn validate(
    settings: Http3Settings<'_>,
) -> Result<Http3PeerSettings, Http3SettingsSemanticError> {
    let mut peer_settings = Http3PeerSettings::default();
    let mut offset = 0;

    for (index, setting) in settings.settings().enumerate() {
        let id = setting.id();
        if prohibited_setting(id) {
            return Err(Http3SettingsSemanticError::ProhibitedSetting { id, offset });
        }
        for previous in settings.settings().take(index) {
            if previous.id() == id {
                return Err(Http3SettingsSemanticError::DuplicateSetting { id, offset });
            }
        }

        match id {
            Http3SettingId::QPACK_MAX_TABLE_CAPACITY => {
                peer_settings.qpack_max_table_capacity = setting.value();
            }
            Http3SettingId::MAX_FIELD_SECTION_SIZE => {
                peer_settings.maximum_field_section_size = Some(setting.value());
            }
            Http3SettingId::QPACK_BLOCKED_STREAMS => {
                peer_settings.qpack_blocked_streams = setting.value();
            }
            _ => {}
        }

        // Settings are disjoint subslices of one validated payload, so this cannot overflow.
        if let Some(next_offset) = offset.checked_add(setting.as_bytes().len()) {
            offset = next_offset;
        }
    }

    Ok(peer_settings)
}

/// Returns whether an identifier is reserved for HTTP/2 and prohibited in HTTP/3 SETTINGS.
pub(super) const fn prohibited_setting(id: Http3SettingId) -> bool {
    matches!(id.value(), 0x00 | 0x02 | 0x03 | 0x04 | 0x05)
}

/// Effective known SETTINGS received from an HTTP/3 peer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Http3PeerSettings {
    qpack_max_table_capacity: u64,
    maximum_field_section_size: Option<u64>,
    qpack_blocked_streams: u64,
}

impl Http3PeerSettings {
    /// Returns SETTINGS_QPACK_MAX_TABLE_CAPACITY, defaulting to zero.
    pub const fn qpack_max_table_capacity(self) -> u64 {
        self.qpack_max_table_capacity
    }

    /// Returns SETTINGS_MAX_FIELD_SECTION_SIZE, or `None` for the unlimited default.
    pub const fn maximum_field_section_size(self) -> Option<u64> {
        self.maximum_field_section_size
    }

    /// Returns SETTINGS_QPACK_BLOCKED_STREAMS, defaulting to zero.
    pub const fn qpack_blocked_streams(self) -> u64 {
        self.qpack_blocked_streams
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setting_payload_length_overflow_preserves_entry_index() {
        assert_eq!(
            add_setting_payload(7, usize::MAX, 1),
            Err(Http3SettingsBuildError::PayloadLengthOverflow {
                index: 7,
                current: usize::MAX,
                addition: 1,
            })
        );
    }
}
