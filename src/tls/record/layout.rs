//! Private TLS record physical representation.

pub(super) const TLS_RECORD_HEADER_LEN: usize = 5;

wire_repr::wire_repr! {
    /// A TLS record with a fragment bounded by its encoded length.
    pub(super) layout TlsRecordLayout {
        /// The raw TLS record content type.
        content_type: U8 as super::super::types::TlsContentType;
        /// The legacy TLS record version.
        version: BeU16 as super::super::types::TlsProtocolVersion;
        /// The encoded fragment length, derived from `fragment` during construction.
        fragment_length: BeU16;
        /// The exact record fragment.
        fragment: bytes(fragment_length);
    }
}
