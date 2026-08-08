use super::error::Http2ParseError;
use super::frame::Http2Frame;
use super::layout::{validate_type, validate_zero_stream};
use super::types::{Http2FrameType, Http2SettingId};
use core::iter::FusedIterator;

/// A raw-preserving HTTP/2 SETTINGS parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Setting {
    id: Http2SettingId,
    value: u32,
}

impl Http2Setting {
    /// Creates a setting from a raw-preserving identifier and encoded value.
    pub const fn new(id: Http2SettingId, value: u32) -> Self {
        Self { id, value }
    }

    fn parse(bytes: &[u8]) -> Self {
        Self {
            id: Http2SettingId::new(u16::from_be_bytes([bytes[0], bytes[1]])),
            value: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
        }
    }

    pub(super) const fn has_valid_intrinsic_value(self) -> bool {
        match self.id {
            Http2SettingId::ENABLE_PUSH | Http2SettingId::ENABLE_CONNECT_PROTOCOL => {
                self.value <= 1
            }
            Http2SettingId::INITIAL_WINDOW_SIZE => self.value <= 0x7fff_ffff,
            Http2SettingId::MAX_FRAME_SIZE => self.value >= 0x4000 && self.value <= 0x00ff_ffff,
            _ => true,
        }
    }

    /// Returns the raw-preserving setting identifier.
    pub const fn id(self) -> Http2SettingId {
        self.id
    }

    /// Returns the raw encoded setting value.
    pub const fn value(self) -> u32 {
        self.value
    }
}

/// A validated borrowed HTTP/2 SETTINGS frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Settings<'a> {
    frame: Http2Frame<'a>,
}

impl<'a> Http2Settings<'a> {
    pub(super) fn from_validated(frame: Http2Frame<'a>) -> Self {
        Self { frame }
    }

    /// Parses the first complete SETTINGS frame, enforcing the caller-provided payload maximum.
    pub fn parse(bytes: &'a [u8], maximum_payload: usize) -> Result<Self, Http2ParseError> {
        Self::from_frame(Http2Frame::parse(bytes, maximum_payload)?)
    }

    /// Validates a raw SETTINGS frame's intrinsic layout.
    pub fn from_frame(frame: Http2Frame<'a>) -> Result<Self, Http2ParseError> {
        validate_type(frame, Http2FrameType::SETTINGS)?;
        validate_zero_stream(frame)?;
        let actual = frame.payload().len();
        if frame.flags() & 0x1 != 0 && actual != 0 {
            return Err(Http2ParseError::SettingsAckPayload { actual });
        }
        if !actual.is_multiple_of(6) {
            return Err(Http2ParseError::SettingsPayloadLength { actual });
        }
        for bytes in frame.payload().chunks_exact(6) {
            let setting = Http2Setting::parse(bytes);
            if !setting.has_valid_intrinsic_value() {
                return Err(Http2ParseError::InvalidSettingValue {
                    id: setting.id(),
                    value: setting.value(),
                });
            }
        }
        Ok(Self { frame })
    }

    /// Returns the validated raw frame.
    pub const fn frame(&self) -> Http2Frame<'a> {
        self.frame
    }

    /// Returns the exact represented frame bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.frame.as_bytes()
    }

    /// Returns whether the ACK flag is set.
    pub fn is_ack(&self) -> bool {
        self.frame.flags() & 0x1 != 0
    }

    /// Iterates SETTINGS parameters in wire order without combining duplicates.
    pub fn settings(&self) -> Http2SettingsIter<'a> {
        Http2SettingsIter {
            bytes: self.frame.payload(),
        }
    }
}

/// Iterator over validated HTTP/2 SETTINGS parameters.
#[derive(Clone, Debug)]
pub struct Http2SettingsIter<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for Http2SettingsIter<'a> {
    type Item = Http2Setting;

    fn next(&mut self) -> Option<Self::Item> {
        let (setting, remaining) = self.bytes.split_first_chunk::<6>()?;
        self.bytes = remaining;
        Some(Http2Setting::parse(setting))
    }
}

impl FusedIterator for Http2SettingsIter<'_> {}
