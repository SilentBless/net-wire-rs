//! Private RFC 8200 physical representation.

pub(super) const HEADER_LENGTH: usize = 40;

#[derive(Clone, Copy)]
pub(super) struct Ipv6AddressRepr([u8; 16]);

impl Ipv6AddressRepr {
    pub(super) const fn from_address(address: super::address::Ipv6Address) -> Self {
        Self(address.octets())
    }

    pub(super) const fn into_address(self) -> super::address::Ipv6Address {
        super::address::Ipv6Address::new(self.0)
    }
}

impl From<[u8; 16]> for Ipv6AddressRepr {
    fn from(octets: [u8; 16]) -> Self {
        Self(octets)
    }
}

impl From<Ipv6AddressRepr> for [u8; 16] {
    fn from(address: Ipv6AddressRepr) -> Self {
        address.0
    }
}

wire_repr::wire_repr! {
    /// An IPv6 packet with a caller-bounded terminal payload.
    pub(super) layout Ipv6PacketLayout {
        /// The combined version, traffic class, and flow label word.
        first_word: BeU32 {
            projections {
                bits version: 28..=31;
                bits traffic_class: 20..=27;
                bits flow_label: 0..=19;
            }
        };
        /// The base header's raw Payload Length field.
        payload_length: BeU16;
        /// The next-header protocol number.
        next_header: U8;
        /// The hop limit.
        hop_limit: U8;
        /// The source IPv6 address.
        source: bytes(16) as Ipv6AddressRepr;
        /// The destination IPv6 address.
        destination: bytes(16) as Ipv6AddressRepr;
        /// Every caller-supplied byte after the fixed base header.
        payload: remaining_bytes;
    }
}
