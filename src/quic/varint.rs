//! RFC 9000 section 16 variable-length integer parsing and construction.

mod codec;

use core::fmt;

use wire_repr::{EncodePlan, PrefixCodec};

const MAX_VALUE: u64 = (1 << 62) - 1;

pub(super) use codec::{QuicVarIntCodec, QuicVarIntCodecValue};

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

/// A QUIC variable-integer encoded width.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QuicVarIntLen {
    /// One encoded byte, carrying up to 6 value bits.
    One,
    /// Two encoded bytes, carrying up to 14 value bits.
    Two,
    /// Four encoded bytes, carrying up to 30 value bits.
    Four,
    /// Eight encoded bytes, carrying up to 62 value bits.
    Eight,
}

impl QuicVarIntLen {
    /// Returns the encoded width in bytes.
    pub const fn byte_len(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
        }
    }

    /// Returns the greatest value representable at this encoded width.
    pub const fn max_value(self) -> u64 {
        match self {
            Self::One => 63,
            Self::Two => 16_383,
            Self::Four => 1_073_741_823,
            Self::Eight => MAX_VALUE,
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
        length: QuicVarIntLen,
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

/// An exact borrowed RFC 9000 section 16 variable-integer representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicVarInt<'a> {
    bytes: &'a [u8],
    value: u64,
    length: QuicVarIntLen,
}

impl<'a> QuicVarInt<'a> {
    /// Assembles a variable-integer view from builder-validated wire components.
    pub(crate) const fn from_validated(bytes: &'a [u8], value: u64, length: QuicVarIntLen) -> Self {
        Self {
            bytes,
            value,
            length,
        }
    }

    /// Parses one variable-length integer and excludes all following input bytes.
    #[inline(always)]
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QuicVarIntParseError> {
        let extent = QuicVarIntCodec::validate_prefix(bytes)?;
        let required = extent.encoded_len().get();
        let exact = bytes
            .get(..required)
            .ok_or(QuicVarIntParseError::Incomplete {
                required,
                available: bytes.len(),
            })?;
        let decoded = QuicVarIntCodec::decode(exact);
        Ok(Self {
            bytes: exact,
            value: decoded.value(),
            length: decoded.length(),
        })
    }

    /// Returns the decoded integer value.
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Returns the exact encoded bytes, excluding any following input bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the encoded width.
    pub const fn encoded_len(self) -> QuicVarIntLen {
        self.length
    }

    /// Returns the encoded length in bytes.
    pub const fn byte_len(self) -> usize {
        self.length.byte_len()
    }

    /// Returns whether this uses the canonical shortest width for its value.
    pub const fn is_canonical(self) -> bool {
        self.length as u8 == codec::canonical_len(self.value) as u8
    }
}

/// Builds a QUIC variable-length integer in caller-owned storage.
pub struct QuicVarIntBuilder<'a> {
    destination: &'a mut [u8],
    value: u64,
    length: Option<QuicVarIntLen>,
}

impl<'a> QuicVarIntBuilder<'a> {
    /// Creates a builder that emits the value with its canonical shortest width.
    pub fn new(destination: &'a mut [u8], value: u64) -> Self {
        Self {
            destination,
            value,
            length: None,
        }
    }

    /// Requests an explicit legal encoded width, including a non-canonical width.
    pub fn with_len(mut self, length: QuicVarIntLen) -> Self {
        self.length = Some(length);
        self
    }

    /// Validates the value, requested width, and capacity before mutating the destination.
    #[inline(always)]
    pub fn build(self) -> Result<QuicVarInt<'a>, QuicVarIntBuildError> {
        let value = self.value;
        let plan = QuicVarIntCodec::plan(QuicVarIntCodecValue::encoding(value, self.length))?;
        let required = plan.encoded_len();
        if self.destination.len() < required {
            return Err(QuicVarIntBuildError::BufferTooShort {
                required,
                available: self.destination.len(),
            });
        }

        let exact = &mut self.destination[..required];
        plan.write_into(exact);
        Ok(QuicVarInt {
            bytes: exact,
            value,
            length: plan.length(),
        })
    }
}
