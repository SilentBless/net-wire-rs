//! HTTP/3 protocol codepoints.

/// An HTTP/3 frame type, preserving extension and unknown values.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Http3FrameType(u64);

impl Http3FrameType {
    /// DATA (`0x00`).
    pub const DATA: Self = Self(0x00);
    /// HEADERS (`0x01`).
    pub const HEADERS: Self = Self(0x01);
    /// CANCEL_PUSH (`0x03`).
    pub const CANCEL_PUSH: Self = Self(0x03);
    /// SETTINGS (`0x04`).
    pub const SETTINGS: Self = Self(0x04);
    /// PUSH_PROMISE (`0x05`).
    pub const PUSH_PROMISE: Self = Self(0x05);
    /// GOAWAY (`0x07`).
    pub const GOAWAY: Self = Self(0x07);
    /// MAX_PUSH_ID (`0x0d`).
    pub const MAX_PUSH_ID: Self = Self(0x0d);

    /// Creates a raw frame type without restricting extensions.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the encoded frame type value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// An HTTP/3 SETTINGS identifier, preserving extension and unknown values.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Http3SettingId(u64);

impl Http3SettingId {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (`0x01`).
    pub const QPACK_MAX_TABLE_CAPACITY: Self = Self(0x01);
    /// SETTINGS_MAX_FIELD_SECTION_SIZE (`0x06`).
    pub const MAX_FIELD_SECTION_SIZE: Self = Self(0x06);
    /// SETTINGS_QPACK_BLOCKED_STREAMS (`0x07`).
    pub const QPACK_BLOCKED_STREAMS: Self = Self(0x07);

    /// Creates a raw setting identifier without restricting extensions.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the encoded setting identifier value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// An HTTP/3 unidirectional stream type, preserving extension and unknown values.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Http3StreamType(u64);

impl Http3StreamType {
    /// Control stream (`0x00`).
    pub const CONTROL: Self = Self(0x00);
    /// Push stream (`0x01`).
    pub const PUSH: Self = Self(0x01);
    /// QPACK encoder stream (`0x02`).
    pub const QPACK_ENCODER: Self = Self(0x02);
    /// QPACK decoder stream (`0x03`).
    pub const QPACK_DECODER: Self = Self(0x03);

    /// Creates a raw stream type without restricting extensions.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the encoded stream type value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// An HTTP/3 application error code, preserving extension and unknown values.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Http3ErrorCode(u64);

impl Http3ErrorCode {
    /// H3_NO_ERROR (`0x0100`).
    pub const NO_ERROR: Self = Self(0x0100);
    /// H3_GENERAL_PROTOCOL_ERROR (`0x0101`).
    pub const GENERAL_PROTOCOL_ERROR: Self = Self(0x0101);
    /// H3_INTERNAL_ERROR (`0x0102`).
    pub const INTERNAL_ERROR: Self = Self(0x0102);
    /// H3_STREAM_CREATION_ERROR (`0x0103`).
    pub const STREAM_CREATION_ERROR: Self = Self(0x0103);
    /// H3_CLOSED_CRITICAL_STREAM (`0x0104`).
    pub const CLOSED_CRITICAL_STREAM: Self = Self(0x0104);
    /// H3_FRAME_UNEXPECTED (`0x0105`).
    pub const FRAME_UNEXPECTED: Self = Self(0x0105);
    /// H3_FRAME_ERROR (`0x0106`).
    pub const FRAME_ERROR: Self = Self(0x0106);
    /// H3_EXCESSIVE_LOAD (`0x0107`).
    pub const EXCESSIVE_LOAD: Self = Self(0x0107);
    /// H3_ID_ERROR (`0x0108`).
    pub const ID_ERROR: Self = Self(0x0108);
    /// H3_SETTINGS_ERROR (`0x0109`).
    pub const SETTINGS_ERROR: Self = Self(0x0109);
    /// H3_MISSING_SETTINGS (`0x010a`).
    pub const MISSING_SETTINGS: Self = Self(0x010a);
    /// H3_REQUEST_REJECTED (`0x010b`).
    pub const REQUEST_REJECTED: Self = Self(0x010b);
    /// H3_REQUEST_CANCELLED (`0x010c`).
    pub const REQUEST_CANCELLED: Self = Self(0x010c);
    /// H3_REQUEST_INCOMPLETE (`0x010d`).
    pub const REQUEST_INCOMPLETE: Self = Self(0x010d);
    /// H3_MESSAGE_ERROR (`0x010e`).
    pub const MESSAGE_ERROR: Self = Self(0x010e);
    /// H3_CONNECT_ERROR (`0x010f`).
    pub const CONNECT_ERROR: Self = Self(0x010f);
    /// H3_VERSION_FALLBACK (`0x0110`).
    pub const VERSION_FALLBACK: Self = Self(0x0110);
    /// QPACK_DECOMPRESSION_FAILED (`0x0200`).
    pub const QPACK_DECOMPRESSION_FAILED: Self = Self(0x0200);
    /// QPACK_ENCODER_STREAM_ERROR (`0x0201`).
    pub const QPACK_ENCODER_STREAM_ERROR: Self = Self(0x0201);
    /// QPACK_DECODER_STREAM_ERROR (`0x0202`).
    pub const QPACK_DECODER_STREAM_ERROR: Self = Self(0x0202);

    /// Creates a raw error code without restricting extensions.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the encoded error code value.
    pub const fn value(self) -> u64 {
        self.0
    }
}
