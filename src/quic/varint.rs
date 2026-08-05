//! RFC 9000 section 16 variable-length integer parsing and construction.

use super::{QuicVarIntBuildError, QuicVarIntParseError};

const MAX_VALUE: u64 = (1 << 62) - 1;

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

    const fn prefix(self) -> u8 {
        match self {
            Self::One => 0b00,
            Self::Two => 0b01,
            Self::Four => 0b10,
            Self::Eight => 0b11,
        }
    }

    const fn from_first_byte(first: u8) -> Self {
        match first >> 6 {
            0 => Self::One,
            1 => Self::Two,
            2 => Self::Four,
            _ => Self::Eight,
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
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QuicVarIntParseError> {
        let first = *bytes.first().ok_or(QuicVarIntParseError::Incomplete {
            required: 1,
            available: 0,
        })?;
        let length = QuicVarIntLen::from_first_byte(first);
        let required = length.byte_len();
        if bytes.len() < required {
            return Err(QuicVarIntParseError::Incomplete {
                required,
                available: bytes.len(),
            });
        }

        let exact = &bytes[..required];
        let mut value = u64::from(exact[0] & 0x3f);
        let mut index = 1;
        while index < required {
            value = (value << 8) | u64::from(exact[index]);
            index += 1;
        }
        Ok(Self {
            bytes: exact,
            value,
            length,
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
        self.length as u8 == canonical_len(self.value) as u8
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
    pub fn build(self) -> Result<QuicVarInt<'a>, QuicVarIntBuildError> {
        if self.value > MAX_VALUE {
            return Err(QuicVarIntBuildError::ValueTooLarge { value: self.value });
        }
        let length = self.length.unwrap_or(canonical_len(self.value));
        if self.value > length.max_value() {
            return Err(QuicVarIntBuildError::WidthTooSmall {
                length,
                value: self.value,
            });
        }
        let required = length.byte_len();
        if self.destination.len() < required {
            return Err(QuicVarIntBuildError::BufferTooShort {
                required,
                available: self.destination.len(),
            });
        }

        let exact = &mut self.destination[..required];
        let value_bytes = self.value.to_be_bytes();
        exact.copy_from_slice(&value_bytes[value_bytes.len() - required..]);
        exact[0] |= length.prefix() << 6;
        Ok(QuicVarInt {
            bytes: exact,
            value: self.value,
            length,
        })
    }
}

const fn canonical_len(value: u64) -> QuicVarIntLen {
    if value <= QuicVarIntLen::One.max_value() {
        QuicVarIntLen::One
    } else if value <= QuicVarIntLen::Two.max_value() {
        QuicVarIntLen::Two
    } else if value <= QuicVarIntLen::Four.max_value() {
        QuicVarIntLen::Four
    } else {
        QuicVarIntLen::Eight
    }
}
