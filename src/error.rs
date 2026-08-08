//! Shared parsing failures for validated wire-format views.

use core::fmt;

/// Failure to validate bytes required by a wire-format view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The supplied bytes do not contain the required prefix or declared packet length.
    Truncated {
        /// Minimum number of bytes required.
        minimum: usize,
        /// Number of bytes supplied.
        available: usize,
    },
    /// A packet contains a version other than the one required by its format.
    InvalidVersion {
        /// Required version.
        expected: u8,
        /// Encoded version.
        actual: u8,
    },
    /// A header length field is smaller than the format minimum.
    InvalidHeaderLength {
        /// Minimum valid header length.
        minimum: usize,
        /// Encoded header length.
        actual: usize,
    },
    /// A declared packet length is smaller than its validated header.
    InvalidTotalLength {
        /// Validated header length.
        header_length: usize,
        /// Declared packet length.
        total_length: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { minimum, available } => {
                write!(
                    f,
                    "packet is truncated: need {minimum} bytes, have {available}"
                )
            }
            Self::InvalidVersion { expected, actual } => {
                write!(
                    f,
                    "invalid packet version: expected {expected}, got {actual}"
                )
            }
            Self::InvalidHeaderLength { minimum, actual } => {
                write!(f, "invalid header length: minimum {minimum}, got {actual}")
            }
            Self::InvalidTotalLength {
                header_length,
                total_length,
            } => {
                write!(
                    f,
                    "invalid total length: header {header_length}, total {total_length}"
                )
            }
        }
    }
}
