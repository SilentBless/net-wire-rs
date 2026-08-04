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
