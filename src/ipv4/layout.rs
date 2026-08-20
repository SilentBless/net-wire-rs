//! Private RFC 791 physical representation.

#[derive(Clone, Copy)]
pub(super) struct Ipv4AddressRepr([u8; 4]);

impl Ipv4AddressRepr {
    pub(super) const fn from_address(address: super::address::Ipv4Address) -> Self {
        Self(address.octets())
    }

    pub(super) const fn into_address(self) -> super::address::Ipv4Address {
        super::address::Ipv4Address::new(self.0)
    }
}

impl From<[u8; 4]> for Ipv4AddressRepr {
    fn from(octets: [u8; 4]) -> Self {
        Self(octets)
    }
}

impl From<Ipv4AddressRepr> for [u8; 4] {
    fn from(address: Ipv4AddressRepr) -> Self {
        address.0
    }
}

wire_repr::wire_repr! {
    /// An IPv4 packet with a caller-bounded terminal body.
    pub(super) layout Ipv4PacketLayout {
        /// The combined version and Internet Header Length octet.
        version_ihl: U8 {
            projections {
                bits version: 4..=7;
                bits ihl: 0..=3;
            }
        };
        /// The combined differentiated-services and ECN octet.
        dscp_ecn: U8;
        /// The complete IPv4 packet length.
        total_length: BeU16;
        /// The datagram identification.
        identification: BeU16;
        /// The flags and fragment offset.
        flags_fragment_offset: BeU16;
        /// The time to live.
        ttl: U8;
        /// The next-header protocol number.
        protocol: U8;
        /// The fixed-header checksum.
        header_checksum: BeU16;
        /// The source IPv4 address.
        source: bytes(4) as Ipv4AddressRepr;
        /// The destination IPv4 address.
        destination: bytes(4) as Ipv4AddressRepr;
        /// All caller-supplied bytes after the fixed header.
        body: remaining_bytes;
    }
}
