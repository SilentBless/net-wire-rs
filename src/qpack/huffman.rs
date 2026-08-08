//! RFC 7541 Appendix B Huffman coding for QPACK strings.

use core::fmt;

use crate::rfc7541_huffman;

/// Encodes QPACK Huffman payload bytes into caller-owned storage.
pub struct QpackHuffmanEncoder<'input, 'output> {
    decoded: &'input [u8],
    destination: &'output mut [u8],
}

impl<'input, 'output> QpackHuffmanEncoder<'input, 'output> {
    /// Creates an encoder for decoded bytes and caller-owned destination storage.
    pub fn new(decoded: &'input [u8], destination: &'output mut [u8]) -> Self {
        Self {
            decoded,
            destination,
        }
    }

    /// Returns the exact RFC-padded encoded byte length.
    pub fn required_encoded_len(decoded: &[u8]) -> Result<usize, QpackHuffmanEncodeError> {
        rfc7541_huffman::encoded_len(decoded).map_err(map_encode)
    }

    /// Validates all fallible conditions before atomically writing the encoded bytes.
    pub fn encode(self) -> Result<&'output [u8], QpackHuffmanEncodeError> {
        let required = Self::required_encoded_len(self.decoded)?;
        if self.destination.len() < required {
            return Err(QpackHuffmanEncodeError::DestinationTooShort {
                required,
                available: self.destination.len(),
            });
        }
        let output = &mut self.destination[..required];
        rfc7541_huffman::encode_prevalidated(self.decoded, output);
        Ok(output)
    }
}

/// Failure to encode QPACK Huffman payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackHuffmanEncodeError {
    /// The concatenated Huffman code length cannot be represented as `usize` bits.
    EncodedBitLengthOverflow,
    /// The RFC-padded Huffman byte length cannot be represented as `usize`.
    EncodedByteLengthOverflow,
    /// The caller destination cannot contain the complete encoded sequence.
    DestinationTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
    },
}

impl fmt::Display for QpackHuffmanEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodedBitLengthOverflow => {
                f.write_str("QPACK Huffman encoded bit length overflows usize")
            }
            Self::EncodedByteLengthOverflow => {
                f.write_str("QPACK Huffman encoded byte length overflows usize")
            }
            Self::DestinationTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK Huffman destination is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Decodes QPACK Huffman payload bytes into caller-owned storage.
pub struct QpackHuffmanDecoder<'input, 'output> {
    encoded: &'input [u8],
    destination: &'output mut [u8],
}

impl<'input, 'output> QpackHuffmanDecoder<'input, 'output> {
    /// Creates a decoder for encoded bytes and caller-owned destination storage.
    pub fn new(encoded: &'input [u8], destination: &'output mut [u8]) -> Self {
        Self {
            encoded,
            destination,
        }
    }

    /// Returns the decoded byte length after validating the complete input.
    pub fn required_decoded_len(encoded: &[u8]) -> Result<usize, QpackHuffmanDecodeError> {
        rfc7541_huffman::decoded_len(encoded).map_err(map_decode)
    }

    /// Validates all fallible conditions before atomically writing decoded bytes.
    pub fn decode(self) -> Result<&'output [u8], QpackHuffmanDecodeError> {
        let required = Self::required_decoded_len(self.encoded)?;
        if self.destination.len() < required {
            return Err(QpackHuffmanDecodeError::OutputTooShort {
                required,
                available: self.destination.len(),
            });
        }
        rfc7541_huffman::decode_prevalidated(self.encoded, &mut self.destination[..required]);
        Ok(&self.destination[..required])
    }
}

/// Failure to decode QPACK Huffman payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackHuffmanDecodeError {
    /// The encoded data contains the reserved EOS symbol.
    EosSymbol,
    /// The encoded data reaches a bit sequence that is not a Huffman-code prefix.
    InvalidHuffmanCode,
    /// The trailing incomplete code is not valid RFC 7541 EOS-prefix padding.
    InvalidPadding,
    /// The decoded byte count cannot be represented as `usize`.
    DecodedLengthOverflow,
    /// The caller destination cannot contain the complete decoded sequence.
    OutputTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
    },
}

/// Decodes a payload whose validity and exact decoded output length were prevalidated.
pub(crate) fn decode_prevalidated(encoded: &[u8], destination: &mut [u8]) {
    rfc7541_huffman::decode_prevalidated(encoded, destination);
}

impl fmt::Display for QpackHuffmanDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EosSymbol => f.write_str("QPACK Huffman data contains EOS"),
            Self::InvalidHuffmanCode => f.write_str("QPACK Huffman data contains an invalid code"),
            Self::InvalidPadding => {
                f.write_str("QPACK Huffman data has invalid EOS-prefix padding")
            }
            Self::DecodedLengthOverflow => {
                f.write_str("QPACK Huffman decoded length overflows usize")
            }
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK Huffman output buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

fn map_encode(error: rfc7541_huffman::EncodeError) -> QpackHuffmanEncodeError {
    match error {
        rfc7541_huffman::EncodeError::BitLengthOverflow => {
            QpackHuffmanEncodeError::EncodedBitLengthOverflow
        }
        rfc7541_huffman::EncodeError::ByteLengthOverflow => {
            QpackHuffmanEncodeError::EncodedByteLengthOverflow
        }
    }
}

fn map_decode(error: rfc7541_huffman::DecodeError) -> QpackHuffmanDecodeError {
    match error {
        rfc7541_huffman::DecodeError::EosSymbol => QpackHuffmanDecodeError::EosSymbol,
        rfc7541_huffman::DecodeError::InvalidHuffmanCode => {
            QpackHuffmanDecodeError::InvalidHuffmanCode
        }
        rfc7541_huffman::DecodeError::InvalidPadding => QpackHuffmanDecodeError::InvalidPadding,
        rfc7541_huffman::DecodeError::DecodedLengthOverflow => {
            QpackHuffmanDecodeError::DecodedLengthOverflow
        }
    }
}
