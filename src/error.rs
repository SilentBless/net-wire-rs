//! Shared parsing failures for validated wire-format views.

use core::fmt;

/// Failure to validate bytes required by a wire-format view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The supplied bytes do not contain the parser's required fixed prefix.
    Truncated {
        /// Minimum number of bytes required by the parser.
        minimum: usize,
        /// Number of bytes supplied to the parser.
        available: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { minimum, available } => {
                write!(
                    formatter,
                    "frame is truncated: need {minimum} bytes, have {available}"
                )
            }
        }
    }
}
