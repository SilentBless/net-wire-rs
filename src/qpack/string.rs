//! RFC 9204 section 4.1.2 N-bit-prefixed string literals.

use core::fmt;

use super::{
    QPACK_INTEGER_MAX, QpackInteger, QpackIntegerBuildError, QpackIntegerParseError,
    integer::{canonical_encoded_len, integer_from_prevalidated, write_canonical_prevalidated},
};

/// A validated borrowed QPACK string literal whose payload remains opaque.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackStringLiteral<'a> {
    bytes: &'a [u8],
    prefix_bits: u8,
    previous_high_bits: u8,
    huffman: bool,
    length: QpackInteger<'a>,
    encoded_payload: &'a [u8],
}

impl<'a> QpackStringLiteral<'a> {
    /// Parses one N-bit-prefixed QPACK string literal and excludes following bytes.
    pub fn parse(bytes: &'a [u8], prefix_bits: u8) -> Result<Self, QpackStringLiteralParseError> {
        let (integer_bits, huffman_mask) = string_bits(prefix_bits)?;
        let length = QpackInteger::parse(bytes, integer_bits)
            .map_err(QpackStringLiteralParseError::Length)?;
        let payload_len = usize::try_from(length.value()).map_err(|_| {
            QpackStringLiteralParseError::LengthTooLarge {
                value: length.value(),
            }
        })?;
        let end = length.as_bytes().len().checked_add(payload_len).ok_or(
            QpackStringLiteralParseError::LengthTooLarge {
                value: length.value(),
            },
        )?;
        if bytes.len() < end {
            return Err(QpackStringLiteralParseError::Incomplete {
                required: end,
                available: bytes.len(),
            });
        }
        let first = bytes[0];
        Ok(Self {
            bytes: &bytes[..end],
            prefix_bits,
            previous_high_bits: first & !controlled_mask(prefix_bits),
            huffman: first & huffman_mask != 0,
            length,
            encoded_payload: &bytes[length.as_bytes().len()..end],
        })
    }

    /// Returns the total RFC 9204 string prefix width N, including H.
    pub const fn prefix_bits(self) -> u8 {
        self.prefix_bits
    }

    /// Returns the previous representation's high bits, excluding the H flag.
    pub const fn previous_high_bits(self) -> u8 {
        self.previous_high_bits
    }

    /// Returns whether the opaque payload is RFC 7541 Huffman-coded.
    pub const fn is_huffman(self) -> bool {
        self.huffman
    }

    /// Returns the exact parsed length integer, including any legal noncanonical encoding.
    pub const fn length(self) -> QpackInteger<'a> {
        self.length
    }

    /// Returns the opaque encoded payload; this does not Huffman-decode it.
    pub const fn encoded_payload(self) -> &'a [u8] {
        self.encoded_payload
    }

    /// Returns the complete exact string-literal bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

/// Failure to parse a QPACK N-bit-prefixed string literal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackStringLiteralParseError {
    /// N must be in the inclusive range 2 through 8.
    InvalidPrefixBits {
        /// Supplied prefix width.
        prefix_bits: u8,
    },
    /// The embedded N-1-bit length integer is invalid.
    Length(#[doc = "The nested length-integer failure."] QpackIntegerParseError),
    /// The payload length cannot be represented as an index on this target.
    LengthTooLarge {
        /// Parsed payload length.
        value: u64,
    },
    /// The payload ends after the available input.
    Incomplete {
        /// Bytes required for the complete literal.
        required: usize,
        /// Bytes available.
        available: usize,
    },
}

impl fmt::Display for QpackStringLiteralParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefixBits { prefix_bits } => {
                write!(
                    f,
                    "QPACK string prefix width must be 2 through 8, got {prefix_bits}"
                )
            }
            Self::Length(error) => write!(f, "QPACK string length is invalid: {error}"),
            Self::LengthTooLarge { value } => {
                write!(f, "QPACK string length cannot be indexed: {value}")
            }
            Self::Incomplete {
                required,
                available,
            } => write!(
                f,
                "QPACK string input is incomplete: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Builds a canonical QPACK N-bit-prefixed string literal in caller-owned storage.
pub struct QpackStringLiteralBuilder<'a, 'payload> {
    destination: &'a mut [u8],
    prefix_bits: u8,
    previous_high_bits: u8,
    huffman: bool,
    encoded_payload: &'payload [u8],
}

impl<'a, 'payload> QpackStringLiteralBuilder<'a, 'payload> {
    /// Creates a builder around opaque, already-encoded payload bytes.
    pub fn new(
        destination: &'a mut [u8],
        prefix_bits: u8,
        previous_high_bits: u8,
        huffman: bool,
        encoded_payload: &'payload [u8],
    ) -> Self {
        Self {
            destination,
            prefix_bits,
            previous_high_bits,
            huffman,
            encoded_payload,
        }
    }

    /// Validates all inputs and capacity before atomically writing a canonical literal.
    pub fn build(self) -> Result<QpackStringLiteral<'a>, QpackStringLiteralBuildError> {
        let plan = string_plan(
            self.prefix_bits,
            self.previous_high_bits,
            self.huffman,
            self.encoded_payload,
        )?;
        if self.destination.len() < plan.required {
            return Err(QpackStringLiteralBuildError::BufferTooShort {
                required: plan.required,
                available: self.destination.len(),
            });
        }
        write_string_prevalidated(&mut self.destination[..plan.required], plan);
        Ok(string_from_prevalidated(
            &self.destination[..plan.required],
            plan,
        ))
    }
}

/// A fully prevalidated canonical string-literal write plan.
#[derive(Clone, Copy)]
pub(super) struct QpackStringLiteralPlan<'a> {
    prefix_bits: u8,
    previous_high_bits: u8,
    huffman: bool,
    encoded_payload: &'a [u8],
    integer_bits: u8,
    high_bits: u8,
    payload_len: u64,
    length_len: usize,
    required: usize,
}

impl QpackStringLiteralPlan<'_> {
    /// Returns the fully prevalidated literal length.
    pub(super) const fn required(self) -> usize {
        self.required
    }
}

/// Preflights one canonical string literal without mutating destination storage.
pub(super) fn string_plan<'a>(
    prefix_bits: u8,
    previous_high_bits: u8,
    huffman: bool,
    encoded_payload: &'a [u8],
) -> Result<QpackStringLiteralPlan<'a>, QpackStringLiteralBuildError> {
    let (integer_bits, huffman_mask) = string_bits(prefix_bits)
        .map_err(|_| QpackStringLiteralBuildError::InvalidPrefixBits { prefix_bits })?;
    if previous_high_bits & controlled_mask(prefix_bits) != 0 {
        return Err(QpackStringLiteralBuildError::HighBitsOverlap {
            high_bits: previous_high_bits,
            prefix_bits,
        });
    }
    let payload_len = u64::try_from(encoded_payload.len()).map_err(|_| {
        QpackStringLiteralBuildError::PayloadLengthTooLarge {
            length: encoded_payload.len(),
        }
    })?;
    if payload_len > QPACK_INTEGER_MAX {
        return Err(QpackStringLiteralBuildError::Length(
            QpackIntegerBuildError::ValueTooLarge { value: payload_len },
        ));
    }
    let length_len = canonical_encoded_len(payload_len, integer_bits);
    let required = length_len
        .checked_add(encoded_payload.len())
        .ok_or(QpackStringLiteralBuildError::RequiredLengthOverflow)?;
    let high_bits = previous_high_bits | if huffman { huffman_mask } else { 0 };
    Ok(QpackStringLiteralPlan {
        prefix_bits,
        previous_high_bits,
        huffman,
        encoded_payload,
        integer_bits,
        high_bits,
        payload_len,
        length_len,
        required,
    })
}

/// Writes a fully prevalidated string literal.
pub(super) fn write_string_prevalidated(destination: &mut [u8], plan: QpackStringLiteralPlan<'_>) {
    let (length_destination, payload_destination) = destination.split_at_mut(plan.length_len);
    write_canonical_prevalidated(
        length_destination,
        plan.integer_bits,
        plan.high_bits,
        plan.payload_len,
    );
    payload_destination.copy_from_slice(plan.encoded_payload);
}

/// Creates an exact string-literal view after a prevalidated write.
pub(super) fn string_from_prevalidated<'a>(
    bytes: &'a [u8],
    plan: QpackStringLiteralPlan<'_>,
) -> QpackStringLiteral<'a> {
    let length = integer_from_prevalidated(
        &bytes[..plan.length_len],
        plan.integer_bits,
        plan.high_bits,
        plan.payload_len,
    );
    QpackStringLiteral {
        bytes,
        prefix_bits: plan.prefix_bits,
        previous_high_bits: plan.previous_high_bits,
        huffman: plan.huffman,
        length,
        encoded_payload: &bytes[plan.length_len..],
    }
}

/// Failure to build a QPACK N-bit-prefixed string literal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackStringLiteralBuildError {
    /// N must be in the inclusive range 2 through 8.
    InvalidPrefixBits {
        /// Supplied prefix width.
        prefix_bits: u8,
    },
    /// Previous-representation bits overlap H or the length prefix.
    HighBitsOverlap {
        /// Supplied high bits.
        high_bits: u8,
        /// Total string prefix width.
        prefix_bits: u8,
    },
    /// The payload length cannot be represented as a QPACK integer.
    PayloadLengthTooLarge {
        /// Supplied payload length.
        length: usize,
    },
    /// Computing the total output length overflowed `usize`.
    RequiredLengthOverflow,
    /// The caller destination cannot contain the complete literal.
    BufferTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
    },
    /// The embedded canonical length builder failed before output mutation.
    Length(#[doc = "The nested length-builder failure."] QpackIntegerBuildError),
}

impl fmt::Display for QpackStringLiteralBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefixBits { prefix_bits } => {
                write!(
                    f,
                    "QPACK string prefix width must be 2 through 8, got {prefix_bits}"
                )
            }
            Self::HighBitsOverlap {
                high_bits,
                prefix_bits,
            } => write!(
                f,
                "QPACK string high bits {high_bits:#04x} overlap the {prefix_bits}-bit string prefix"
            ),
            Self::PayloadLengthTooLarge { length } => {
                write!(
                    f,
                    "QPACK string payload length cannot be represented: {length}"
                )
            }
            Self::RequiredLengthOverflow => {
                f.write_str("QPACK string required length overflows usize")
            }
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK string buffer is too short: need {required} bytes, have {available}"
            ),
            Self::Length(error) => write!(f, "QPACK string length cannot be built: {error}"),
        }
    }
}

fn string_bits(prefix_bits: u8) -> Result<(u8, u8), QpackStringLiteralParseError> {
    match prefix_bits {
        2..=8 => Ok((prefix_bits - 1, 1u8 << (prefix_bits - 1))),
        _ => Err(QpackStringLiteralParseError::InvalidPrefixBits { prefix_bits }),
    }
}

const fn controlled_mask(prefix_bits: u8) -> u8 {
    match prefix_bits {
        2..=7 => (1u8 << prefix_bits) - 1,
        8 => u8::MAX,
        _ => 0,
    }
}
