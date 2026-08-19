//! RFC 7541 Appendix B HPACK Huffman coding.

use core::fmt;

use crate::rfc7541::huffman as rfc7541_huffman;

/// Encodes RFC 7541 Appendix B Huffman data into caller-owned storage.
pub struct HpackHuffmanEncoder<'input, 'output> {
    decoded: &'input [u8],
    destination: &'output mut [u8],
}

impl<'input, 'output> HpackHuffmanEncoder<'input, 'output> {
    /// Creates an encoder for `decoded` and caller-owned `destination` storage.
    pub fn new(decoded: &'input [u8], destination: &'output mut [u8]) -> Self {
        Self {
            decoded,
            destination,
        }
    }

    /// Returns the RFC-padded encoded length required for `decoded`.
    pub fn required_encoded_len(decoded: &[u8]) -> Result<usize, HpackHuffmanEncodeError> {
        rfc7541_huffman::encoded_len(decoded).map_err(map_encode_error)
    }

    /// Validates capacity before atomically writing the RFC-padded encoded bytes.
    pub fn encode(self) -> Result<&'output [u8], HpackHuffmanEncodeError> {
        let required = Self::required_encoded_len(self.decoded)?;
        if self.destination.len() < required {
            return Err(HpackHuffmanEncodeError::DestinationTooShort {
                required,
                available: self.destination.len(),
            });
        }
        let destination = &mut self.destination[..required];
        Self::encode_prevalidated(self.decoded, destination);
        Ok(destination)
    }

    /// Writes a preflighted RFC-padded encoding into an exact-size destination.
    pub(super) fn encode_prevalidated(decoded: &[u8], destination: &mut [u8]) {
        rfc7541_huffman::encode_prevalidated(decoded, destination);
    }
}

/// Failure to encode RFC 7541 Appendix B Huffman data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackHuffmanEncodeError {
    /// The concatenated Huffman code length cannot be represented as `usize` bits.
    EncodedBitLengthOverflow,
    /// The RFC-padded Huffman byte length cannot be represented as `usize`.
    EncodedByteLengthOverflow,
    /// The caller destination cannot contain the complete encoded byte sequence.
    DestinationTooShort {
        /// Encoded bytes required.
        required: usize,
        /// Destination bytes available.
        available: usize,
    },
}

impl fmt::Display for HpackHuffmanEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodedBitLengthOverflow => {
                f.write_str("HPACK Huffman encoded bit length overflows usize")
            }
            Self::EncodedByteLengthOverflow => {
                f.write_str("HPACK Huffman encoded byte length overflows usize")
            }
            Self::DestinationTooShort {
                required,
                available,
            } => write!(
                f,
                "HPACK Huffman destination is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

/// Decodes an RFC 7541 Appendix B Huffman byte sequence into caller-owned storage.
pub struct HpackHuffmanDecoder<'input, 'output> {
    encoded: &'input [u8],
    destination: &'output mut [u8],
}

impl<'input, 'output> HpackHuffmanDecoder<'input, 'output> {
    /// Creates a decoder for `encoded` and caller-owned `destination` storage.
    pub fn new(encoded: &'input [u8], destination: &'output mut [u8]) -> Self {
        Self {
            encoded,
            destination,
        }
    }

    /// Returns the decoded byte length after validating the complete input.
    pub fn required_decoded_len(encoded: &[u8]) -> Result<usize, HpackHuffmanDecodeError> {
        rfc7541_huffman::decoded_len(encoded).map_err(map_decode_error)
    }

    /// Validates the complete input before atomically writing its decoded bytes.
    pub fn decode(self) -> Result<&'output [u8], HpackHuffmanDecodeError> {
        let required = Self::required_decoded_len(self.encoded)?;
        if self.destination.len() < required {
            return Err(HpackHuffmanDecodeError::OutputTooShort {
                required,
                available: self.destination.len(),
            });
        }
        rfc7541_huffman::decode_prevalidated(self.encoded, &mut self.destination[..required]);
        Ok(&self.destination[..required])
    }
}

/// Failure to decode an RFC 7541 Appendix B Huffman byte sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackHuffmanDecodeError {
    /// The encoded data contains the reserved EOS symbol.
    EosSymbol,
    /// The encoded data reaches a bit sequence that is not a Huffman-code prefix.
    InvalidHuffmanCode,
    /// The trailing incomplete code is not valid RFC 7541 EOS-prefix padding.
    InvalidPadding,
    /// The decoded byte count cannot be represented as `usize`.
    DecodedLengthOverflow,
    /// The caller destination cannot contain the complete decoded byte sequence.
    OutputTooShort {
        /// Decoded bytes required.
        required: usize,
        /// Destination bytes available.
        available: usize,
    },
}

impl fmt::Display for HpackHuffmanDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EosSymbol => f.write_str("HPACK Huffman data contains EOS"),
            Self::InvalidHuffmanCode => f.write_str("HPACK Huffman data contains an invalid code"),
            Self::InvalidPadding => {
                f.write_str("HPACK Huffman data has invalid EOS-prefix padding")
            }
            Self::DecodedLengthOverflow => {
                f.write_str("HPACK Huffman decoded length overflows usize")
            }
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "HPACK Huffman output buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}

fn map_encode_error(error: rfc7541_huffman::EncodeError) -> HpackHuffmanEncodeError {
    match error {
        rfc7541_huffman::EncodeError::BitLengthOverflow => {
            HpackHuffmanEncodeError::EncodedBitLengthOverflow
        }
        rfc7541_huffman::EncodeError::ByteLengthOverflow => {
            HpackHuffmanEncodeError::EncodedByteLengthOverflow
        }
    }
}

fn map_decode_error(error: rfc7541_huffman::DecodeError) -> HpackHuffmanDecodeError {
    match error {
        rfc7541_huffman::DecodeError::EosSymbol => HpackHuffmanDecodeError::EosSymbol,
        rfc7541_huffman::DecodeError::InvalidHuffmanCode => {
            HpackHuffmanDecodeError::InvalidHuffmanCode
        }
        rfc7541_huffman::DecodeError::InvalidPadding => HpackHuffmanDecodeError::InvalidPadding,
        rfc7541_huffman::DecodeError::DecodedLengthOverflow => {
            HpackHuffmanDecodeError::DecodedLengthOverflow
        }
    }
}
