//! Private RFC 8999 invariant long-header prefix representation.

use super::header::QuicVersion;

wire_repr::wire_repr! {
    /// The version-independent QUIC long-header prefix.
    pub(in crate::quic) layout QuicLongHeaderLayout {
        /// The raw first byte.
        first_byte: U8;
        /// The raw QUIC version.
        version: BeU32 as QuicVersion;
        /// The destination connection-ID length, derived from its bytes when building.
        destination_connection_id_length: U8;
        /// The exact destination connection-ID bytes.
        destination_connection_id: bytes(destination_connection_id_length);
        /// The source connection-ID length, derived from its bytes when building.
        source_connection_id_length: U8;
        /// The exact source connection-ID bytes.
        source_connection_id: bytes(source_connection_id_length);
    }
}

/// Returns the exact invariant-prefix extent for already validated identifier lengths.
pub(in crate::quic) fn prefix_len(
    destination_connection_id_len: usize,
    source_connection_id_len: usize,
) -> Option<usize> {
    7usize
        .checked_add(destination_connection_id_len)
        .and_then(|length| length.checked_add(source_connection_id_len))
}
