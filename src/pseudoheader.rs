//! Errors shared by transport checksums that use IP pseudoheaders.

use core::fmt;

/// Failure to represent a transport message length in an IP pseudoheader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PseudoHeaderChecksumError {
    /// The message length cannot be represented by the pseudoheader's length field.
    LengthTooLarge {
        /// Largest representable message length on this platform.
        maximum: usize,
        /// Actual message length.
        actual: usize,
    },
}

impl fmt::Display for PseudoHeaderChecksumError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthTooLarge { maximum, actual } => write!(
                formatter,
                "transport message length {actual} exceeds pseudoheader maximum {maximum}"
            ),
        }
    }
}
