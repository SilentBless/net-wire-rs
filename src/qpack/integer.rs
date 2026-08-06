//! RFC 9204 prefixed integer parsing and construction.

use core::fmt;

/// Greatest RFC 9204 prefixed integer this implementation accepts: the 62-bit ceiling.
pub const QPACK_INTEGER_MAX: u64 = (1u64 << 62) - 1;

/// A validated, exact borrowed QPACK prefixed integer representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackInteger<'a> {
    bytes: &'a [u8],
    prefix_bits: u8,
    value: u64,
    high_bits: u8,
}

impl<'a> QpackInteger<'a> {
    /// Parses one RFC 9204 section 4.1.1 integer and excludes following bytes.
    pub fn parse(bytes: &'a [u8], prefix_bits: u8) -> Result<Self, QpackIntegerParseError> {
        let prefix_mask = prefix_mask(prefix_bits)?;
        let first = *bytes.first().ok_or(QpackIntegerParseError::Incomplete {
            required: 1,
            available: 0,
        })?;
        let prefix_value = first & prefix_mask;
        let high_bits = first & !prefix_mask;
        if prefix_value < prefix_mask {
            return Ok(Self {
                bytes: &bytes[..1],
                prefix_bits,
                value: u64::from(prefix_value),
                high_bits,
            });
        }

        let mut value = u64::from(prefix_mask);
        let mut shift = 0u32;
        let mut index = 1usize;
        loop {
            let octet = *bytes.get(index).ok_or(QpackIntegerParseError::Incomplete {
                required: index
                    .checked_add(1)
                    .ok_or(QpackIntegerParseError::Overflow)?,
                available: bytes.len(),
            })?;
            if shift >= u64::BITS {
                return Err(QpackIntegerParseError::Overflow);
            }
            let contribution = u64::from(octet & 0x7f)
                .checked_mul(1u64 << shift)
                .ok_or(QpackIntegerParseError::Overflow)?;
            value = value
                .checked_add(contribution)
                .ok_or(QpackIntegerParseError::Overflow)?;
            index = index
                .checked_add(1)
                .ok_or(QpackIntegerParseError::Overflow)?;
            if octet & 0x80 == 0 {
                if value > QPACK_INTEGER_MAX {
                    return Err(QpackIntegerParseError::ValueTooLarge { value });
                }
                return Ok(Self {
                    bytes: &bytes[..index],
                    prefix_bits,
                    value,
                    high_bits,
                });
            }
            shift = shift
                .checked_add(7)
                .ok_or(QpackIntegerParseError::Overflow)?;
        }
    }

    /// Returns the decoded integer value.
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Returns the exact encoded representation, excluding following bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the number of controlled low bits in the first octet.
    pub const fn prefix_bits(self) -> u8 {
        self.prefix_bits
    }

    /// Returns the preserved uncontrolled high bits of the first octet.
    pub const fn high_bits(self) -> u8 {
        self.high_bits
    }
}

/// Failure to parse a QPACK prefixed integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackIntegerParseError {
    /// The prefix width is outside the inclusive range 1 through 8.
    InvalidPrefixBits {
        /// Supplied prefix width.
        prefix_bits: u8,
    },
    /// The input ended before the first octet or a terminating continuation octet.
    Incomplete {
        /// Required bytes to include the missing octet.
        required: usize,
        /// Available input bytes.
        available: usize,
    },
    /// The encoded number cannot be represented as a `u64`.
    Overflow,
    /// The decoded number exceeds QPACK's 62-bit required decoding limit.
    ValueTooLarge {
        /// Decoded value above [`QPACK_INTEGER_MAX`].
        value: u64,
    },
}

impl fmt::Display for QpackIntegerParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefixBits { prefix_bits } => write!(
                f,
                "QPACK integer prefix width must be 1 through 8, got {prefix_bits}"
            ),
            Self::Incomplete {
                required,
                available,
            } => write!(
                f,
                "QPACK integer input is incomplete: need {required} bytes, have {available}"
            ),
            Self::Overflow => f.write_str("QPACK integer exceeds u64"),
            Self::ValueTooLarge { value } => {
                write!(f, "QPACK integer exceeds the 62-bit limit: {value}")
            }
        }
    }
}

/// Builds a canonical RFC 9204 section 4.1.1 integer in caller-owned storage.
pub struct QpackIntegerBuilder<'a> {
    destination: &'a mut [u8],
    prefix_bits: u8,
    high_bits: u8,
    value: u64,
}

impl<'a> QpackIntegerBuilder<'a> {
    /// Creates a builder with the supplied prefix width, high bits, and value.
    pub fn new(destination: &'a mut [u8], prefix_bits: u8, high_bits: u8, value: u64) -> Self {
        Self {
            destination,
            prefix_bits,
            high_bits,
            value,
        }
    }

    /// Validates all inputs and capacity before writing a canonical representation.
    pub fn build(self) -> Result<QpackInteger<'a>, QpackIntegerBuildError> {
        let prefix_mask = prefix_mask(self.prefix_bits).map_err(|_| {
            QpackIntegerBuildError::InvalidPrefixBits {
                prefix_bits: self.prefix_bits,
            }
        })?;
        if self.high_bits & prefix_mask != 0 {
            return Err(QpackIntegerBuildError::HighBitsOverlap {
                high_bits: self.high_bits,
                prefix_bits: self.prefix_bits,
            });
        }
        if self.value > QPACK_INTEGER_MAX {
            return Err(QpackIntegerBuildError::ValueTooLarge { value: self.value });
        }
        let required = encoded_len(self.value, prefix_mask);
        if self.destination.len() < required {
            return Err(QpackIntegerBuildError::BufferTooShort {
                required,
                available: self.destination.len(),
            });
        }
        let bytes = &mut self.destination[..required];
        write_canonical_prevalidated(bytes, self.prefix_bits, self.high_bits, self.value);
        Ok(integer_from_prevalidated(
            bytes,
            self.prefix_bits,
            self.high_bits,
            self.value,
        ))
    }
}

/// Failure to build a QPACK prefixed integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackIntegerBuildError {
    /// The prefix width is outside the inclusive range 1 through 8.
    InvalidPrefixBits {
        /// Supplied prefix width.
        prefix_bits: u8,
    },
    /// Supplied high bits overlap the integer-controlled low prefix bits.
    HighBitsOverlap {
        /// Supplied high bits.
        high_bits: u8,
        /// Number of integer-controlled low bits.
        prefix_bits: u8,
    },
    /// The value exceeds QPACK's 62-bit required decoding limit.
    ValueTooLarge {
        /// Supplied value above [`QPACK_INTEGER_MAX`].
        value: u64,
    },
    /// The caller buffer cannot contain the complete integer representation.
    BufferTooShort {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
}

impl fmt::Display for QpackIntegerBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefixBits { prefix_bits } => write!(
                f,
                "QPACK integer prefix width must be 1 through 8, got {prefix_bits}"
            ),
            Self::HighBitsOverlap {
                high_bits,
                prefix_bits,
            } => write!(
                f,
                "QPACK integer high bits {high_bits:#04x} overlap the {prefix_bits}-bit prefix"
            ),
            Self::ValueTooLarge { value } => {
                write!(f, "QPACK integer exceeds the 62-bit limit: {value}")
            }
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK integer buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Returns the canonical encoded length after validating the prefix width and value.
pub(super) fn canonical_encoded_len(value: u64, prefix_bits: u8) -> usize {
    let prefix_mask = match prefix_bits {
        1..=7 => (1u8 << prefix_bits) - 1,
        8 => u8::MAX,
        _ => 0,
    };
    encoded_len(value, prefix_mask)
}

/// Writes a canonical integer after complete validation has established its exact size.
///
/// Callers must have validated the prefix width, high-bit separation, value ceiling,
/// exact canonical length, and destination capacity before invoking this handoff.
pub(super) fn write_canonical_prevalidated(
    bytes: &mut [u8],
    prefix_bits: u8,
    high_bits: u8,
    value: u64,
) {
    let prefix_mask = match prefix_bits {
        1..=7 => (1u8 << prefix_bits) - 1,
        8 => u8::MAX,
        _ => 0,
    };
    if value < u64::from(prefix_mask) {
        bytes[0] = high_bits | value as u8;
        return;
    }

    bytes[0] = high_bits | prefix_mask;
    let mut remaining = value - u64::from(prefix_mask);
    let mut index = 1usize;
    while remaining >= 0x80 {
        bytes[index] = (remaining as u8 & 0x7f) | 0x80;
        remaining >>= 7;
        index += 1;
    }
    bytes[index] = remaining as u8;
}

/// Creates an integer view over a canonical representation written by the prevalidated handoff.
pub(super) fn integer_from_prevalidated<'a>(
    bytes: &'a [u8],
    prefix_bits: u8,
    high_bits: u8,
    value: u64,
) -> QpackInteger<'a> {
    QpackInteger {
        bytes,
        prefix_bits,
        value,
        high_bits,
    }
}

fn prefix_mask(prefix_bits: u8) -> Result<u8, QpackIntegerParseError> {
    match prefix_bits {
        1..=7 => Ok((1u8 << prefix_bits) - 1),
        8 => Ok(u8::MAX),
        _ => Err(QpackIntegerParseError::InvalidPrefixBits { prefix_bits }),
    }
}

fn encoded_len(value: u64, prefix_mask: u8) -> usize {
    if value < u64::from(prefix_mask) {
        return 1;
    }
    let mut required = 2usize;
    let mut remaining = value - u64::from(prefix_mask);
    while remaining >= 0x80 {
        required += 1;
        remaining >>= 7;
    }
    required
}
