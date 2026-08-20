//! Private RFC 4443 common-header physical representation.

pub(super) const HEADER_LENGTH: usize = 4;

wire_repr::wire_repr! {
    /// An ICMPv6 message with a caller-bounded terminal body.
    pub(super) layout Icmpv6MessageLayout {
        /// The message type.
        message_type: U8 as super::types::Icmpv6Type;
        /// The type-specific code.
        code: U8;
        /// The IPv6 pseudoheader checksum.
        checksum: BeU16;
        /// Every caller-supplied byte after the common header.
        body: remaining_bytes;
    }
}
