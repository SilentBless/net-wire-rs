/// An IPv4 protocol field value from the IANA Protocol Numbers registry.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv4Protocol(u8);
impl Ipv4Protocol {
    /// Internet Control Message Protocol (`1`).
    pub const ICMP: Self = Self(1);
    /// Transmission Control Protocol (`6`).
    pub const TCP: Self = Self(6);
    /// User Datagram Protocol (`17`).
    pub const UDP: Self = Self(17);
    /// Preserves a protocol number, including unassigned values.
    #[inline]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }
    /// Returns the encoded protocol number.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }
}
