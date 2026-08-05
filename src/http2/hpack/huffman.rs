//! RFC 7541 Appendix B HPACK Huffman coding.

use core::fmt;

/// RFC 7541 Appendix B Huffman codes indexed by byte value, followed by EOS at index 256.
///
/// Each tuple contains the least-significant-bit-aligned code and its bit length.
pub(crate) const HUFFMAN_CODES: [(u32, u8); 257] = [
    (0x00001ff8, 13),
    (0x007fffd8, 23),
    (0x0fffffe2, 28),
    (0x0fffffe3, 28),
    (0x0fffffe4, 28),
    (0x0fffffe5, 28),
    (0x0fffffe6, 28),
    (0x0fffffe7, 28),
    (0x0fffffe8, 28),
    (0x00ffffea, 24),
    (0x3ffffffc, 30),
    (0x0fffffe9, 28),
    (0x0fffffea, 28),
    (0x3ffffffd, 30),
    (0x0fffffeb, 28),
    (0x0fffffec, 28),
    (0x0fffffed, 28),
    (0x0fffffee, 28),
    (0x0fffffef, 28),
    (0x0ffffff0, 28),
    (0x0ffffff1, 28),
    (0x0ffffff2, 28),
    (0x3ffffffe, 30),
    (0x0ffffff3, 28),
    (0x0ffffff4, 28),
    (0x0ffffff5, 28),
    (0x0ffffff6, 28),
    (0x0ffffff7, 28),
    (0x0ffffff8, 28),
    (0x0ffffff9, 28),
    (0x0ffffffa, 28),
    (0x0ffffffb, 28),
    (0x00000014, 6),
    (0x000003f8, 10),
    (0x000003f9, 10),
    (0x00000ffa, 12),
    (0x00001ff9, 13),
    (0x00000015, 6),
    (0x000000f8, 8),
    (0x000007fa, 11),
    (0x000003fa, 10),
    (0x000003fb, 10),
    (0x000000f9, 8),
    (0x000007fb, 11),
    (0x000000fa, 8),
    (0x00000016, 6),
    (0x00000017, 6),
    (0x00000018, 6),
    (0x00000000, 5),
    (0x00000001, 5),
    (0x00000002, 5),
    (0x00000019, 6),
    (0x0000001a, 6),
    (0x0000001b, 6),
    (0x0000001c, 6),
    (0x0000001d, 6),
    (0x0000001e, 6),
    (0x0000001f, 6),
    (0x0000005c, 7),
    (0x000000fb, 8),
    (0x00007ffc, 15),
    (0x00000020, 6),
    (0x00000ffb, 12),
    (0x000003fc, 10),
    (0x00001ffa, 13),
    (0x00000021, 6),
    (0x0000005d, 7),
    (0x0000005e, 7),
    (0x0000005f, 7),
    (0x00000060, 7),
    (0x00000061, 7),
    (0x00000062, 7),
    (0x00000063, 7),
    (0x00000064, 7),
    (0x00000065, 7),
    (0x00000066, 7),
    (0x00000067, 7),
    (0x00000068, 7),
    (0x00000069, 7),
    (0x0000006a, 7),
    (0x0000006b, 7),
    (0x0000006c, 7),
    (0x0000006d, 7),
    (0x0000006e, 7),
    (0x0000006f, 7),
    (0x00000070, 7),
    (0x00000071, 7),
    (0x00000072, 7),
    (0x000000fc, 8),
    (0x00000073, 7),
    (0x000000fd, 8),
    (0x00001ffb, 13),
    (0x0007fff0, 19),
    (0x00001ffc, 13),
    (0x00003ffc, 14),
    (0x00000022, 6),
    (0x00007ffd, 15),
    (0x00000003, 5),
    (0x00000023, 6),
    (0x00000004, 5),
    (0x00000024, 6),
    (0x00000005, 5),
    (0x00000025, 6),
    (0x00000026, 6),
    (0x00000027, 6),
    (0x00000006, 5),
    (0x00000074, 7),
    (0x00000075, 7),
    (0x00000028, 6),
    (0x00000029, 6),
    (0x0000002a, 6),
    (0x00000007, 5),
    (0x0000002b, 6),
    (0x00000076, 7),
    (0x0000002c, 6),
    (0x00000008, 5),
    (0x00000009, 5),
    (0x0000002d, 6),
    (0x00000077, 7),
    (0x00000078, 7),
    (0x00000079, 7),
    (0x0000007a, 7),
    (0x0000007b, 7),
    (0x00007ffe, 15),
    (0x000007fc, 11),
    (0x00003ffd, 14),
    (0x00001ffd, 13),
    (0x0ffffffc, 28),
    (0x000fffe6, 20),
    (0x003fffd2, 22),
    (0x000fffe7, 20),
    (0x000fffe8, 20),
    (0x003fffd3, 22),
    (0x003fffd4, 22),
    (0x003fffd5, 22),
    (0x007fffd9, 23),
    (0x003fffd6, 22),
    (0x007fffda, 23),
    (0x007fffdb, 23),
    (0x007fffdc, 23),
    (0x007fffdd, 23),
    (0x007fffde, 23),
    (0x00ffffeb, 24),
    (0x007fffdf, 23),
    (0x00ffffec, 24),
    (0x00ffffed, 24),
    (0x003fffd7, 22),
    (0x007fffe0, 23),
    (0x00ffffee, 24),
    (0x007fffe1, 23),
    (0x007fffe2, 23),
    (0x007fffe3, 23),
    (0x007fffe4, 23),
    (0x001fffdc, 21),
    (0x003fffd8, 22),
    (0x007fffe5, 23),
    (0x003fffd9, 22),
    (0x007fffe6, 23),
    (0x007fffe7, 23),
    (0x00ffffef, 24),
    (0x003fffda, 22),
    (0x001fffdd, 21),
    (0x000fffe9, 20),
    (0x003fffdb, 22),
    (0x003fffdc, 22),
    (0x007fffe8, 23),
    (0x007fffe9, 23),
    (0x001fffde, 21),
    (0x007fffea, 23),
    (0x003fffdd, 22),
    (0x003fffde, 22),
    (0x00fffff0, 24),
    (0x001fffdf, 21),
    (0x003fffdf, 22),
    (0x007fffeb, 23),
    (0x007fffec, 23),
    (0x001fffe0, 21),
    (0x001fffe1, 21),
    (0x003fffe0, 22),
    (0x001fffe2, 21),
    (0x007fffed, 23),
    (0x003fffe1, 22),
    (0x007fffee, 23),
    (0x007fffef, 23),
    (0x000fffea, 20),
    (0x003fffe2, 22),
    (0x003fffe3, 22),
    (0x003fffe4, 22),
    (0x007ffff0, 23),
    (0x003fffe5, 22),
    (0x003fffe6, 22),
    (0x007ffff1, 23),
    (0x03ffffe0, 26),
    (0x03ffffe1, 26),
    (0x000fffeb, 20),
    (0x0007fff1, 19),
    (0x003fffe7, 22),
    (0x007ffff2, 23),
    (0x003fffe8, 22),
    (0x01ffffec, 25),
    (0x03ffffe2, 26),
    (0x03ffffe3, 26),
    (0x03ffffe4, 26),
    (0x07ffffde, 27),
    (0x07ffffdf, 27),
    (0x03ffffe5, 26),
    (0x00fffff1, 24),
    (0x01ffffed, 25),
    (0x0007fff2, 19),
    (0x001fffe3, 21),
    (0x03ffffe6, 26),
    (0x07ffffe0, 27),
    (0x07ffffe1, 27),
    (0x03ffffe7, 26),
    (0x07ffffe2, 27),
    (0x00fffff2, 24),
    (0x001fffe4, 21),
    (0x001fffe5, 21),
    (0x03ffffe8, 26),
    (0x03ffffe9, 26),
    (0x0ffffffd, 28),
    (0x07ffffe3, 27),
    (0x07ffffe4, 27),
    (0x07ffffe5, 27),
    (0x000fffec, 20),
    (0x00fffff3, 24),
    (0x000fffed, 20),
    (0x001fffe6, 21),
    (0x003fffe9, 22),
    (0x001fffe7, 21),
    (0x001fffe8, 21),
    (0x007ffff3, 23),
    (0x003fffea, 22),
    (0x003fffeb, 22),
    (0x01ffffee, 25),
    (0x01ffffef, 25),
    (0x00fffff4, 24),
    (0x00fffff5, 24),
    (0x03ffffea, 26),
    (0x007ffff4, 23),
    (0x03ffffeb, 26),
    (0x07ffffe6, 27),
    (0x03ffffec, 26),
    (0x03ffffed, 26),
    (0x07ffffe7, 27),
    (0x07ffffe8, 27),
    (0x07ffffe9, 27),
    (0x07ffffea, 27),
    (0x07ffffeb, 27),
    (0x0ffffffe, 28),
    (0x07ffffec, 27),
    (0x07ffffed, 27),
    (0x07ffffee, 27),
    (0x07ffffef, 27),
    (0x07fffff0, 27),
    (0x03ffffee, 26),
    (0x3fffffff, 30),
];

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
        let mut bits = 0usize;
        for &byte in decoded {
            bits = bits
                .checked_add(usize::from(HUFFMAN_CODES[usize::from(byte)].1))
                .ok_or(HpackHuffmanEncodeError::EncodedBitLengthOverflow)?;
        }

        bits.checked_add(7)
            .ok_or(HpackHuffmanEncodeError::EncodedByteLengthOverflow)
            .map(|padded_bits| padded_bits / 8)
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
        let mut pending = 0u64;
        let mut pending_bits = 0u8;
        let mut output = 0usize;

        for &byte in decoded {
            let (code, code_bits) = HUFFMAN_CODES[usize::from(byte)];
            pending = (pending << code_bits) | u64::from(code);
            pending_bits += code_bits;

            while pending_bits >= 8 {
                pending_bits -= 8;
                destination[output] = (pending >> pending_bits) as u8;
                output += 1;
                pending &= (1u64 << pending_bits) - 1;
            }
        }

        if pending_bits != 0 {
            destination[output] =
                ((pending << (8 - pending_bits)) | ((1u64 << (8 - pending_bits)) - 1)) as u8;
        }
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
        let mut code = 0u32;
        let mut bits = 0u8;
        let mut length = 0usize;

        for byte in encoded {
            for shift in (0..8).rev() {
                code = (code << 1) | u32::from((byte >> shift) & 1);
                bits += 1;

                if let Some(symbol) = symbol_for(code, bits) {
                    if symbol == 256 {
                        return Err(HpackHuffmanDecodeError::EosSymbol);
                    }
                    length = length
                        .checked_add(1)
                        .ok_or(HpackHuffmanDecodeError::DecodedLengthOverflow)?;
                    code = 0;
                    bits = 0;
                } else if !is_prefix(code, bits) {
                    return Err(HpackHuffmanDecodeError::InvalidHuffmanCode);
                }
            }
        }

        validate_tail(code, bits)?;
        Ok(length)
    }

    /// Validates the complete input before atomically writing its decoded bytes.
    pub fn decode(mut self) -> Result<&'output [u8], HpackHuffmanDecodeError> {
        let required = Self::required_decoded_len(self.encoded)?;
        if self.destination.len() < required {
            return Err(HpackHuffmanDecodeError::OutputTooShort {
                required,
                available: self.destination.len(),
            });
        }

        self.write_decoded();
        Ok(&self.destination[..required])
    }

    fn write_decoded(&mut self) {
        let mut code = 0u32;
        let mut bits = 0u8;
        let mut output = 0usize;

        for byte in self.encoded {
            for shift in (0..8).rev() {
                code = (code << 1) | u32::from((byte >> shift) & 1);
                bits += 1;

                if let Some(symbol) = symbol_for(code, bits) {
                    if let (0..=255, Some(slot)) = (symbol, self.destination.get_mut(output)) {
                        *slot = symbol as u8;
                        output += 1;
                    }
                    code = 0;
                    bits = 0;
                }
            }
        }
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

fn symbol_for(code: u32, bits: u8) -> Option<usize> {
    HUFFMAN_CODES
        .iter()
        .position(|&(candidate, candidate_bits)| candidate_bits == bits && candidate == code)
}

fn is_prefix(code: u32, bits: u8) -> bool {
    HUFFMAN_CODES.iter().any(|&(candidate, candidate_bits)| {
        candidate_bits > bits && (candidate >> (candidate_bits - bits)) == code
    })
}

fn validate_tail(code: u32, bits: u8) -> Result<(), HpackHuffmanDecodeError> {
    if bits == 0 {
        return Ok(());
    }
    if bits > 7 || code != (1u32 << bits) - 1 {
        return Err(HpackHuffmanDecodeError::InvalidPadding);
    }
    Ok(())
}
