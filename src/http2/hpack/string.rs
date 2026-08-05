//! RFC 7541 string literal framing with opaque encoded payloads.

use core::fmt;

use super::integer::{
    HpackInteger, HpackIntegerParseError, canonical_encoded_len, canonical_integer,
    write_canonical_for_valid_prefix,
};

/// A validated, exact borrowed HPACK string literal representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpackStringLiteral<'a> {
    bytes: &'a [u8],
    length: HpackInteger<'a>,
}

impl<'a> HpackStringLiteral<'a> {
    /// Parses one RFC 7541 section 5.2 string literal and excludes any following bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, HpackStringLiteralParseError> {
        let length =
            HpackInteger::parse(bytes, 7).map_err(HpackStringLiteralParseError::InvalidLength)?;
        let encoded_length = usize::try_from(length.value()).map_err(|_| {
            HpackStringLiteralParseError::EncodedLengthNotRepresentable {
                encoded_length: length.value(),
            }
        })?;
        let length_length = length.as_bytes().len();
        let total = length_length.checked_add(encoded_length).ok_or(
            HpackStringLiteralParseError::TotalLengthOverflow {
                length_length,
                encoded_length,
            },
        )?;
        if bytes.len() < total {
            return Err(HpackStringLiteralParseError::IncompleteEncodedPayload {
                required: encoded_length,
                available: bytes.len() - length_length,
            });
        }

        Ok(Self {
            bytes: &bytes[..total],
            length,
        })
    }

    /// Returns the exact string literal representation, excluding any following bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Reports whether `encoded_bytes` are RFC 7541 Huffman-coded.
    pub const fn is_huffman(self) -> bool {
        self.length.high_bits() != 0
    }

    /// Returns the opaque encoded payload without decoding Huffman data.
    pub fn encoded_bytes(self) -> &'a [u8] {
        &self.bytes[self.length.as_bytes().len()..]
    }

    /// Returns the exact raw-preserving HPACK length representation.
    pub const fn length(self) -> HpackInteger<'a> {
        self.length
    }
}

/// Failure to parse an HPACK string literal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackStringLiteralParseError {
    /// The 7-bit HPACK length integer is malformed, incomplete, or overflows `u64`.
    InvalidLength(HpackIntegerParseError),
    /// The decoded length cannot be represented as `usize`.
    EncodedLengthNotRepresentable {
        /// Decoded encoded-payload length.
        encoded_length: u64,
    },
    /// The length encoding and payload length cannot be added as `usize`.
    TotalLengthOverflow {
        /// Bytes used by the HPACK length integer.
        length_length: usize,
        /// Decoded encoded-payload length.
        encoded_length: usize,
    },
    /// The input ended before the declared opaque encoded payload.
    IncompleteEncodedPayload {
        /// Declared encoded-payload length.
        required: usize,
        /// Encoded-payload bytes available after the length integer.
        available: usize,
    },
}

impl fmt::Display for HpackStringLiteralParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(error) => write!(f, "invalid HPACK string length: {error}"),
            Self::EncodedLengthNotRepresentable { encoded_length } => write!(
                f,
                "HPACK string encoded length {encoded_length} cannot be represented as usize"
            ),
            Self::TotalLengthOverflow {
                length_length,
                encoded_length,
            } => write!(
                f,
                "HPACK string total length overflows usize: length uses {length_length} bytes and payload is {encoded_length} bytes"
            ),
            Self::IncompleteEncodedPayload {
                required,
                available,
            } => write!(
                f,
                "HPACK string encoded payload is incomplete: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Builds a canonical HPACK string literal around already encoded payload bytes.
pub struct HpackStringLiteralBuilder<'a, 'b> {
    destination: &'a mut [u8],
    huffman: bool,
    encoded_bytes: &'b [u8],
}

impl<'a, 'b> HpackStringLiteralBuilder<'a, 'b> {
    /// Creates a builder for opaque payload bytes already Huffman-encoded when `huffman` is true.
    ///
    /// This builder only frames the bytes; it does not perform Huffman encoding.
    pub fn new_encoded(destination: &'a mut [u8], huffman: bool, encoded_bytes: &'b [u8]) -> Self {
        Self {
            destination,
            huffman,
            encoded_bytes,
        }
    }

    /// Validates length and capacity before atomically writing the complete string literal.
    pub fn build(self) -> Result<HpackStringLiteral<'a>, HpackStringLiteralBuildError> {
        let encoded_length = u64::try_from(self.encoded_bytes.len()).map_err(|_| {
            HpackStringLiteralBuildError::EncodedLengthNotRepresentable {
                encoded_length: self.encoded_bytes.len(),
            }
        })?;
        let length_length = canonical_encoded_len(encoded_length, 0x7f);
        let total = length_length.checked_add(self.encoded_bytes.len()).ok_or(
            HpackStringLiteralBuildError::TotalLengthOverflow {
                length_length,
                encoded_length: self.encoded_bytes.len(),
            },
        )?;
        if self.destination.len() < total {
            return Err(HpackStringLiteralBuildError::BufferTooShort {
                required: total,
                available: self.destination.len(),
            });
        }

        let literal = &mut self.destination[..total];
        let (length_destination, payload_destination) = literal.split_at_mut(length_length);
        write_canonical_for_valid_prefix(
            length_destination,
            7,
            0x7f,
            if self.huffman { 0x80 } else { 0 },
            encoded_length,
        );
        payload_destination.copy_from_slice(self.encoded_bytes);

        let bytes = &*literal;
        Ok(HpackStringLiteral {
            bytes,
            length: canonical_integer(
                &bytes[..length_length],
                7,
                if self.huffman { 0x80 } else { 0 },
                encoded_length,
            ),
        })
    }
}

/// Failure to build an HPACK string literal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackStringLiteralBuildError {
    /// The payload length cannot be represented as `u64`.
    EncodedLengthNotRepresentable {
        /// Opaque encoded-payload length.
        encoded_length: usize,
    },
    /// The length encoding and payload length cannot be added as `usize`.
    TotalLengthOverflow {
        /// Bytes required by the HPACK length integer.
        length_length: usize,
        /// Opaque encoded-payload length.
        encoded_length: usize,
    },
    /// The caller buffer cannot contain the complete string literal.
    BufferTooShort {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
}

impl fmt::Display for HpackStringLiteralBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodedLengthNotRepresentable { encoded_length } => write!(
                f,
                "HPACK string encoded length {encoded_length} cannot be represented as u64"
            ),
            Self::TotalLengthOverflow {
                length_length,
                encoded_length,
            } => write!(
                f,
                "HPACK string total length overflows usize: length uses {length_length} bytes and payload is {encoded_length} bytes"
            ),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "HPACK string buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}
