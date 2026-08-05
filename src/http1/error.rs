//! HTTP/1 parsing and construction errors.

use core::fmt;

/// Failure to parse HTTP/1 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http1ParseError {
    /// More bytes are required to complete the declared structure.
    Incomplete {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
    /// The request or response start line is malformed.
    InvalidStartLine,
    /// A header or trailer field is malformed.
    InvalidField,
    /// A `Content-Length` value is invalid.
    InvalidContentLength,
    /// A `Content-Length` value exceeds `usize`.
    ContentLengthOverflow,
    /// Multiple `Content-Length` values disagree.
    ConflictingContentLength,
    /// `Transfer-Encoding` and `Content-Length` both occur.
    TransferEncodingWithContentLength,
    /// Transfer coding syntax is malformed.
    InvalidTransferEncoding,
    /// `chunked` is not final, is repeated, or has parameters.
    InvalidChunkedTransferEncoding,
    /// A chunk size is malformed.
    InvalidChunkSize,
    /// A chunk size exceeds `usize`.
    ChunkSizeOverflow,
    /// A chunk data terminator is malformed.
    InvalidChunkTerminator,
    /// A trailer field or trailer terminator is malformed.
    InvalidTrailer,
    /// The decoded chunk data total exceeds `usize`.
    DecodedSizeOverflow,
}

impl fmt::Display for Http1ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Incomplete { .. } => "incomplete HTTP/1 input",
            Self::InvalidStartLine => "invalid HTTP/1 start line",
            Self::InvalidField => "invalid HTTP/1 field",
            Self::InvalidContentLength => "invalid HTTP Content-Length",
            Self::ContentLengthOverflow => "HTTP Content-Length exceeds platform limit",
            Self::ConflictingContentLength => "conflicting HTTP Content-Length values",
            Self::TransferEncodingWithContentLength => "HTTP Transfer-Encoding with Content-Length",
            Self::InvalidTransferEncoding => "invalid HTTP Transfer-Encoding",
            Self::InvalidChunkedTransferEncoding => "invalid HTTP chunked Transfer-Encoding",
            Self::InvalidChunkSize => "invalid HTTP chunk size",
            Self::ChunkSizeOverflow => "HTTP chunk size exceeds platform limit",
            Self::InvalidChunkTerminator => "invalid HTTP chunk terminator",
            Self::InvalidTrailer => "invalid HTTP trailer",
            Self::DecodedSizeOverflow => "decoded HTTP chunk data exceeds platform limit",
        })
    }
}

/// Failure to build HTTP/1 bytes in caller-owned storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http1BuildError {
    /// A start-line component or field is invalid.
    InvalidValue,
    /// The finished head length exceeds `usize`.
    LengthTooLarge,
    /// The caller buffer cannot contain the finished encoding.
    BufferTooShort {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
}

impl fmt::Display for Http1BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue => f.write_str("invalid HTTP/1 builder value"),
            Self::LengthTooLarge => f.write_str("HTTP/1 head length exceeds platform limit"),
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "HTTP/1 buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}
