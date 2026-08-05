/// An IPv6 Next Header value from the IANA Protocol Numbers registry.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv6NextHeader(u8);

impl Ipv6NextHeader {
    /// IPv6 Hop-by-Hop Options (`0`).
    pub const HOPOPT: Self = Self(0);
    /// Routing (`43`).
    pub const ROUTING: Self = Self(43);
    /// Fragment (`44`).
    pub const FRAGMENT: Self = Self(44);
    /// Encapsulating Security Payload (`50`).
    pub const ESP: Self = Self(50);
    /// Authentication Header (`51`).
    pub const AUTHENTICATION: Self = Self(51);
    /// Destination Options (`60`).
    pub const DESTINATION_OPTIONS: Self = Self(60);
    /// Transmission Control Protocol (`6`).
    pub const TCP: Self = Self(6);
    /// User Datagram Protocol (`17`).
    pub const UDP: Self = Self(17);
    /// Internet Control Message Protocol for IPv6 (`58`).
    pub const ICMPV6: Self = Self(58);
    /// No Next Header (`59`).
    pub const NO_NEXT_HEADER: Self = Self(59);

    /// Preserves a Next Header value, including unassigned values.
    #[inline]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns the encoded Next Header value.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }
}
