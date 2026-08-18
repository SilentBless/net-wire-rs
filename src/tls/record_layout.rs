//! Private TLS record physical representation.

pub(super) const TLS_RECORD_HEADER_LEN: usize = 5;

wire_repr::wire_repr! {
    /// A TLS record with a fragment bounded by its encoded length.
    pub(super) layout TlsRecordLayout {
        /// The raw TLS record content type.
        field content_type: U8 as super::types::TlsContentType;
        /// The legacy TLS record version.
        field version: BeU16 as super::types::TlsProtocolVersion;
        /// The encoded fragment length, derived from `fragment` during construction.
        field fragment_length: BeU16;
        /// The exact record fragment.
        field fragment: bytes(current_pos..current_pos + fragment_length);
    }
}
