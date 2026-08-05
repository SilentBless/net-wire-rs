//! RFC 7541 variable-length integer parsing and construction.

use core::fmt;

/// A validated, exact borrowed HPACK integer representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpackInteger<'a> {
    bytes: &'a [u8],
    prefix_bits: u8,
    value: u64,
    high_bits: u8,
}

impl<'a> HpackInteger<'a> {
    /// Parses one RFC 7541 section 5.1 integer and excludes any following bytes.
    pub fn parse(bytes: &'a [u8], prefix_bits: u8) -> Result<Self, HpackIntegerParseError> {
        let prefix_mask = prefix_mask(prefix_bits)?;
        let first = *bytes.first().ok_or(HpackIntegerParseError::Incomplete {
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
            let octet = *bytes.get(index).ok_or(HpackIntegerParseError::Incomplete {
                required: index
                    .checked_add(1)
                    .ok_or(HpackIntegerParseError::Overflow)?,
                available: bytes.len(),
            })?;
            if shift >= u64::BITS {
                return Err(HpackIntegerParseError::Overflow);
            }
            let contribution = u64::from(octet & 0x7f)
                .checked_mul(1u64 << shift)
                .ok_or(HpackIntegerParseError::Overflow)?;
            value = value
                .checked_add(contribution)
                .ok_or(HpackIntegerParseError::Overflow)?;
            index = index
                .checked_add(1)
                .ok_or(HpackIntegerParseError::Overflow)?;
            if octet & 0x80 == 0 {
                return Ok(Self {
                    bytes: &bytes[..index],
                    prefix_bits,
                    value,
                    high_bits,
                });
            }
            shift = shift
                .checked_add(7)
                .ok_or(HpackIntegerParseError::Overflow)?;
        }
    }

    /// Returns the decoded integer value.
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Returns the exact encoded representation, excluding any following bytes.
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

pub(crate) fn canonical_encoded_len(value: u64, prefix_mask: u8) -> usize {
    encoded_len(value, prefix_mask)
}

pub(crate) fn canonical_integer<'a>(
    bytes: &'a [u8],
    prefix_bits: u8,
    high_bits: u8,
    value: u64,
) -> HpackInteger<'a> {
    HpackInteger {
        bytes,
        prefix_bits,
        value,
        high_bits,
    }
}

/// Failure to parse an HPACK integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackIntegerParseError {
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
}

impl fmt::Display for HpackIntegerParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefixBits { prefix_bits } => {
                write!(
                    f,
                    "HPACK integer prefix width must be 1 through 8, got {prefix_bits}"
                )
            }
            Self::Incomplete {
                required,
                available,
            } => write!(
                f,
                "HPACK integer input is incomplete: need {required} bytes, have {available}"
            ),
            Self::Overflow => f.write_str("HPACK integer exceeds u64"),
        }
    }
}

/// Builds a canonical RFC 7541 section 5.1 integer in caller-owned storage.
pub struct HpackIntegerBuilder<'a> {
    destination: &'a mut [u8],
    prefix_bits: u8,
    high_bits: u8,
    value: u64,
}

impl<'a> HpackIntegerBuilder<'a> {
    /// Creates a builder with the supplied prefix width, preserved high bits, and value.
    pub fn new(destination: &'a mut [u8], prefix_bits: u8, high_bits: u8, value: u64) -> Self {
        Self {
            destination,
            prefix_bits,
            high_bits,
            value,
        }
    }

    /// Validates all inputs and capacity before writing a canonical integer representation.
    pub fn build(self) -> Result<HpackInteger<'a>, HpackIntegerBuildError> {
        let prefix_mask = prefix_mask(self.prefix_bits).map_err(|_| {
            HpackIntegerBuildError::InvalidPrefixBits {
                prefix_bits: self.prefix_bits,
            }
        })?;
        if self.high_bits & prefix_mask != 0 {
            return Err(HpackIntegerBuildError::HighBitsOverlap {
                high_bits: self.high_bits,
                prefix_bits: self.prefix_bits,
            });
        }

        let required = encoded_len(self.value, prefix_mask);
        if self.destination.len() < required {
            return Err(HpackIntegerBuildError::BufferTooShort {
                required,
                available: self.destination.len(),
            });
        }

        Ok(write_canonical(
            &mut self.destination[..required],
            self.prefix_bits,
            prefix_mask,
            self.high_bits,
            self.value,
        ))
    }
}

/// Failure to build an HPACK integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackIntegerBuildError {
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
    /// The caller buffer cannot contain the complete integer representation.
    BufferTooShort {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
}

impl fmt::Display for HpackIntegerBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefixBits { prefix_bits } => {
                write!(
                    f,
                    "HPACK integer prefix width must be 1 through 8, got {prefix_bits}"
                )
            }
            Self::HighBitsOverlap {
                high_bits,
                prefix_bits,
            } => write!(
                f,
                "HPACK integer high bits {high_bits:#04x} overlap the {prefix_bits}-bit prefix"
            ),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "HPACK integer buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

fn write_canonical<'a>(
    bytes: &'a mut [u8],
    prefix_bits: u8,
    prefix_mask: u8,
    high_bits: u8,
    value: u64,
) -> HpackInteger<'a> {
    if value < u64::from(prefix_mask) {
        bytes[0] = high_bits | value as u8;
    } else {
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

    canonical_integer(bytes, prefix_bits, high_bits, value)
}

pub(crate) fn write_canonical_for_valid_prefix(
    bytes: &mut [u8],
    prefix_bits: u8,
    prefix_mask: u8,
    high_bits: u8,
    value: u64,
) {
    let required = canonical_encoded_len(value, prefix_mask);
    debug_assert_eq!(bytes.len(), required);
    let _ = write_canonical(bytes, prefix_bits, prefix_mask, high_bits, value);
}

fn prefix_mask(prefix_bits: u8) -> Result<u8, HpackIntegerParseError> {
    match prefix_bits {
        1..=7 => Ok((1u8 << prefix_bits) - 1),
        8 => Ok(u8::MAX),
        _ => Err(HpackIntegerParseError::InvalidPrefixBits { prefix_bits }),
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
