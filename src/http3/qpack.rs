//! HTTP/3 handoff from typed field-section frames to the QPACK decoder.
//!
//! This module deliberately owns only the typed HTTP/3-to-QPACK boundary. Stream state,
//! blocked-section retention, and QPACK decoder feedback remain caller responsibilities.

use crate::qpack::{
    QpackDynamicTable, QpackFieldSectionDecodeOutcome, QpackFieldSectionDecoder,
    QpackFieldSectionOutput,
};

use super::{Http3Headers, Http3PushPromise, Http3QpackFieldSectionError};

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
