/// A four-octet IPv4 address in wire order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv4Address([u8; 4]);

impl Ipv4Address {
    /// Constructs an address from wire-order octets.
    #[inline]
    pub const fn new(octets: [u8; 4]) -> Self {
        Self(octets)
    }

    /// Returns wire-order octets.
    #[inline]
    pub const fn octets(self) -> [u8; 4] {
        self.0
    }
}
