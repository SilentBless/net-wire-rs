use core::fmt;

/// A six-octet Ethernet hardware address.
///
/// Ethernet destination and source address fields precede the protocol type in the
/// Ethernet encapsulation described by [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Constructs an address from its six wire-order octets.
    ///
    /// Ethernet addresses occupy the destination and source fields described by
    /// [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
    #[inline]
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// Returns the six wire-order octets of this address.
    ///
    /// The returned order is the Ethernet address-field order described by
    /// [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
    #[inline]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(formatter, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
    }
}

impl From<[u8; 6]> for MacAddress {
    #[inline]
    fn from(octets: [u8; 6]) -> Self {
        Self::new(octets)
    }
}

impl From<MacAddress> for [u8; 6] {
    #[inline]
    fn from(address: MacAddress) -> Self {
        address.octets()
    }
}
