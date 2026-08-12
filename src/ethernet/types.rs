//! Ethernet semantic field types.

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

/// A semantic Ethernet protocol type field.
///
/// The two-octet type field follows the destination and source addresses in the
/// Ethernet encapsulation described by [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EtherType(u16);

impl EtherType {
    /// The Internet Protocol version 4 EtherType (`0x0800`).
    ///
    /// RFC 894 specifies this value for IP datagrams on Ethernet; it is also listed in
    /// the [IANA IEEE 802 Numbers registry](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml).
    pub const IPV4: Self = Self(0x0800);

    /// The Address Resolution Protocol EtherType (`0x0806`).
    ///
    /// RFC 826 names `0x0806` as the Ethernet protocol type for ARP; it is also listed
    /// in the [IANA IEEE 802 Numbers registry](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml).
    pub const ARP: Self = Self(0x0806);

    /// The Internet Protocol version 6 EtherType (`0x86dd`).
    ///
    /// [RFC 2464 section 3](https://www.rfc-editor.org/rfc/rfc2464#section-3) specifies
    /// this value for IPv6 packets encapsulated in Ethernet; it is also listed in the
    /// [IANA IEEE 802 Numbers registry](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml).
    pub const IPV6: Self = Self(0x86dd);

    /// Constructs a protocol type from its host-order 16-bit value.
    ///
    /// The value denotes the Ethernet type field defined by
    /// [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
    #[inline]
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the host-order 16-bit value represented by this type.
    ///
    /// Ethernet transmits this value in its two-octet type field as described by
    /// [RFC 894](https://www.rfc-editor.org/rfc/rfc894).
    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }
}

impl From<u16> for EtherType {
    #[inline]
    fn from(raw: u16) -> Self {
        Self::new(raw)
    }
}

impl From<EtherType> for u16 {
    #[inline]
    fn from(ether_type: EtherType) -> Self {
        ether_type.raw()
    }
}
