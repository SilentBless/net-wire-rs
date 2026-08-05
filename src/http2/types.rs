//! HTTP/2 scalar wire values.

use super::Http2StreamIdError;

/// An HTTP/2 frame type, preserving extension and unknown values.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Http2FrameType(u8);

impl Http2FrameType {
    /// DATA (`0x0`).
    pub const DATA: Self = Self(0x0);
    /// HEADERS (`0x1`).
    pub const HEADERS: Self = Self(0x1);
    /// PRIORITY (`0x2`).
    pub const PRIORITY: Self = Self(0x2);
    /// RST_STREAM (`0x3`).
    pub const RST_STREAM: Self = Self(0x3);
    /// SETTINGS (`0x4`).
    pub const SETTINGS: Self = Self(0x4);
    /// PUSH_PROMISE (`0x5`).
    pub const PUSH_PROMISE: Self = Self(0x5);
    /// PING (`0x6`).
    pub const PING: Self = Self(0x6);
    /// GOAWAY (`0x7`).
    pub const GOAWAY: Self = Self(0x7);
    /// WINDOW_UPDATE (`0x8`).
    pub const WINDOW_UPDATE: Self = Self(0x8);
    /// CONTINUATION (`0x9`).
    pub const CONTINUATION: Self = Self(0x9);

    /// Creates a raw frame type without restricting unknown extensions.
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns the encoded frame type.
    pub const fn raw(self) -> u8 {
        self.0
    }
}

/// An HTTP/2 stream identifier preserving its reserved high bit.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Http2StreamId(u32);

impl Http2StreamId {
    /// Creates an identifier from its raw encoded field, including the reserved bit.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Creates an outgoing identifier after rejecting a set reserved bit.
    pub const fn from_value(value: u32) -> Result<Self, Http2StreamIdError> {
        if value & 0x8000_0000 != 0 {
            Err(Http2StreamIdError::ReservedBitSet)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the raw encoded stream identifier, including its reserved bit.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the 31-bit stream identifier value.
    pub const fn value(self) -> u32 {
        self.0 & 0x7fff_ffff
    }

    /// Returns whether the raw encoded identifier has its reserved bit set.
    pub const fn has_reserved_bit(self) -> bool {
        self.0 & 0x8000_0000 != 0
    }
}

/// An HTTP/2 error code, preserving extension and unknown values.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Http2ErrorCode(u32);

impl Http2ErrorCode {
    /// NO_ERROR (`0x0`).
    pub const NO_ERROR: Self = Self(0x0);
    /// PROTOCOL_ERROR (`0x1`).
    pub const PROTOCOL_ERROR: Self = Self(0x1);
    /// INTERNAL_ERROR (`0x2`).
    pub const INTERNAL_ERROR: Self = Self(0x2);
    /// FLOW_CONTROL_ERROR (`0x3`).
    pub const FLOW_CONTROL_ERROR: Self = Self(0x3);
    /// SETTINGS_TIMEOUT (`0x4`).
    pub const SETTINGS_TIMEOUT: Self = Self(0x4);
    /// STREAM_CLOSED (`0x5`).
    pub const STREAM_CLOSED: Self = Self(0x5);
    /// FRAME_SIZE_ERROR (`0x6`).
    pub const FRAME_SIZE_ERROR: Self = Self(0x6);
    /// REFUSED_STREAM (`0x7`).
    pub const REFUSED_STREAM: Self = Self(0x7);
    /// CANCEL (`0x8`).
    pub const CANCEL: Self = Self(0x8);
    /// COMPRESSION_ERROR (`0x9`).
    pub const COMPRESSION_ERROR: Self = Self(0x9);
    /// CONNECT_ERROR (`0xa`).
    pub const CONNECT_ERROR: Self = Self(0xa);
    /// ENHANCE_YOUR_CALM (`0xb`).
    pub const ENHANCE_YOUR_CALM: Self = Self(0xb);
    /// INADEQUATE_SECURITY (`0xc`).
    pub const INADEQUATE_SECURITY: Self = Self(0xc);
    /// HTTP_1_1_REQUIRED (`0xd`).
    pub const HTTP_1_1_REQUIRED: Self = Self(0xd);

    /// Creates a raw error code without restricting extensions.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the encoded error code.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// An HTTP/2 SETTINGS parameter identifier, preserving extension and unknown values.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Http2SettingId(u16);

impl Http2SettingId {
    /// SETTINGS_HEADER_TABLE_SIZE (`0x1`).
    pub const HEADER_TABLE_SIZE: Self = Self(0x1);
    /// SETTINGS_ENABLE_PUSH (`0x2`).
    pub const ENABLE_PUSH: Self = Self(0x2);
    /// SETTINGS_MAX_CONCURRENT_STREAMS (`0x3`).
    pub const MAX_CONCURRENT_STREAMS: Self = Self(0x3);
    /// SETTINGS_INITIAL_WINDOW_SIZE (`0x4`).
    pub const INITIAL_WINDOW_SIZE: Self = Self(0x4);
    /// SETTINGS_MAX_FRAME_SIZE (`0x5`).
    pub const MAX_FRAME_SIZE: Self = Self(0x5);
    /// SETTINGS_MAX_HEADER_LIST_SIZE (`0x6`).
    pub const MAX_HEADER_LIST_SIZE: Self = Self(0x6);
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL (`0x8`).
    pub const ENABLE_CONNECT_PROTOCOL: Self = Self(0x8);

    /// Creates a raw setting identifier without restricting extensions.
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the encoded setting identifier.
    pub const fn raw(self) -> u16 {
        self.0
    }
}
