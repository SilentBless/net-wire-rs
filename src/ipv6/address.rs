use core::fmt;

/// A 128-bit IPv6 address in network-byte order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv6Address([u8; 16]);

impl Ipv6Address {
    /// Constructs an address from network-order octets.
    #[inline]
    pub const fn new(octets: [u8; 16]) -> Self {
        Self(octets)
    }

    /// Returns the address as network-order octets.
    #[inline]
    pub const fn octets(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Display for Ipv6Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&core::net::Ipv6Addr::from(self.0), formatter)
    }
}
