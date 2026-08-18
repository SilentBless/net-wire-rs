//! TLS parsing and construction errors.

use core::fmt;

/// Failure to validate a TLS wire layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsParseError {
    /// Fewer bytes than a fixed prefix or declared vector were supplied.
    Incomplete {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
    /// A declared vector or value violates its format constraints.
    InvalidValue,
    /// A structured payload has trailing bytes after its required fields.
    TrailingBytes,
}

impl fmt::Display for TlsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete {
                required,
                available,
            } => write!(
                f,
                "TLS input is incomplete: need {required} bytes, have {available}"
            ),
            Self::InvalidValue => f.write_str("invalid TLS vector or value"),
            Self::TrailingBytes => f.write_str("TLS payload has trailing bytes"),
        }
    }
}

/// Failure to mutate a TLS record field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsRecordMutationError {
    /// A field value could not be encoded at its required wire width.
    InvalidFieldEncoding {
        /// Field whose encoding plan was invalid.
        field: &'static str,
        /// Required fixed width.
        expected: usize,
        /// Actual planned width.
        actual: usize,
    },
}

impl fmt::Display for TlsRecordMutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => write!(
                f,
                "TLS field {field} encoding: expected {expected} bytes, got {actual}"
            ),
        }
    }
}

impl core::error::Error for TlsRecordMutationError {}

/// Failure to construct TLS bytes in caller-provided storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsBuildError {
    /// An input vector or scalar violates the TLS encoding rules.
    InvalidValue,
    /// A requested length cannot be represented by the TLS field.
    LengthTooLarge,
    /// A field value could not be encoded at its required wire width.
    InvalidFieldEncoding {
        /// Field whose encoding plan was invalid.
        field: &'static str,
        /// Required fixed width.
        expected: usize,
        /// Actual planned width.
        actual: usize,
    },
    /// Validated builder inputs could not be represented by their wire layout.
    InvalidRepresentation,
    /// The caller buffer cannot contain the finished encoding.
    BufferTooShort {
        /// Required bytes.
        required: usize,
        /// Available bytes.
        available: usize,
    },
}

impl fmt::Display for TlsBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue => f.write_str("invalid TLS builder value"),
            Self::LengthTooLarge => f.write_str("TLS length is not representable"),
            Self::InvalidFieldEncoding {
                field,
                expected,
                actual,
            } => write!(
                f,
                "TLS field {field} encoding: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidRepresentation => {
                f.write_str("validated TLS bytes could not be represented")
            }
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "TLS buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}
