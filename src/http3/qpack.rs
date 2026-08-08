//! HTTP/3 handoff from typed field-section frames to the QPACK decoder.
//!
//! This module deliberately owns only the typed HTTP/3-to-QPACK boundary. Stream state,
//! blocked-section retention, and QPACK decoder feedback remain caller responsibilities.

use core::fmt;

use crate::qpack::field::section::decode::{
    QpackFieldSectionDecodeError, QpackFieldSectionDecodeOutcome, QpackFieldSectionDecoder,
    QpackFieldSectionOutput,
};
use crate::qpack::table::dynamic::QpackDynamicTable;

use super::frame::{Http3Headers, Http3PushPromise};

/// Failure while decoding a QPACK field section carried by an HTTP/3 frame.
///
/// [`Self::DecompressionFailed`] is a peer-caused HTTP/3 connection error.
/// [`Self::OutputProvisioning`] reports insufficient caller output storage and is local, so it
/// must not be sent as an HTTP/3 peer error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3QpackFieldSectionError {
    /// The peer's field section failed QPACK decompression.
    DecompressionFailed(QpackFieldSectionDecodeError),
    /// Caller-provided decoded-field output was insufficient.
    OutputProvisioning(QpackFieldSectionDecodeError),
}

impl Http3QpackFieldSectionError {
    /// Returns the HTTP/3 connection error code when this failure is peer-caused.
    pub const fn error_code(self) -> Option<super::codepoints::Http3ErrorCode> {
        match self {
            Self::DecompressionFailed(_) => {
                Some(super::codepoints::Http3ErrorCode::QPACK_DECOMPRESSION_FAILED)
            }
            Self::OutputProvisioning(_) => None,
        }
    }
}

impl From<QpackFieldSectionDecodeError> for Http3QpackFieldSectionError {
    fn from(error: QpackFieldSectionDecodeError) -> Self {
        match error.is_decompression_failed() {
            true => Self::DecompressionFailed(error),
            false => Self::OutputProvisioning(error),
        }
    }
}

impl fmt::Display for Http3QpackFieldSectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecompressionFailed(error) => {
                write!(f, "HTTP/3 QPACK decompression failed: {error}")
            }
            Self::OutputProvisioning(error) => {
                write!(
                    f,
                    "HTTP/3 QPACK output provisioning failed locally: {error}"
                )
            }
        }
    }
}

impl core::error::Error for Http3QpackFieldSectionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::DecompressionFailed(error) | Self::OutputProvisioning(error) => Some(error),
        }
    }
}

impl Http3Headers<'_> {
    /// Decodes this HEADERS frame's exact encoded field section into caller-owned output.
    ///
    /// The QPACK decoder's transactional output and table guarantees are preserved. A
    /// [`QpackFieldSectionDecodeOutcome::Blocked`] result is successful; retry this same field
    /// section after the dynamic table's insert count advances. Output-provisioning failures are
    /// local caller errors, not HTTP/3 peer errors.
    pub fn decode_field_section<'output>(
        &self,
        decoder: &QpackFieldSectionDecoder,
        table: &QpackDynamicTable<'_, '_>,
        output: &'output mut QpackFieldSectionOutput<'_, '_>,
    ) -> Result<QpackFieldSectionDecodeOutcome<'output>, Http3QpackFieldSectionError> {
        decode_field_section(self.encoded_field_section(), decoder, table, output)
    }
}

impl Http3PushPromise<'_> {
    /// Decodes this PUSH_PROMISE frame's exact encoded field section into caller-owned output.
    ///
    /// The QPACK decoder's transactional output and table guarantees are preserved. A
    /// [`QpackFieldSectionDecodeOutcome::Blocked`] result is successful; retry this same field
    /// section after the dynamic table's insert count advances. Output-provisioning failures are
    /// local caller errors, not HTTP/3 peer errors.
    pub fn decode_field_section<'output>(
        &self,
        decoder: &QpackFieldSectionDecoder,
        table: &QpackDynamicTable<'_, '_>,
        output: &'output mut QpackFieldSectionOutput<'_, '_>,
    ) -> Result<QpackFieldSectionDecodeOutcome<'output>, Http3QpackFieldSectionError> {
        decode_field_section(self.encoded_field_section(), decoder, table, output)
    }
}

fn decode_field_section<'output>(
    encoded_field_section: &[u8],
    decoder: &QpackFieldSectionDecoder,
    table: &QpackDynamicTable<'_, '_>,
    output: &'output mut QpackFieldSectionOutput<'_, '_>,
) -> Result<QpackFieldSectionDecodeOutcome<'output>, Http3QpackFieldSectionError> {
    decoder
        .decode(encoded_field_section, table, output)
        .map_err(Http3QpackFieldSectionError::from)
}
