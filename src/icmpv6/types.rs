/// An ICMPv6 message type, preserving unknown values.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Icmpv6Type(u8);

impl Icmpv6Type {
    /// Destination Unreachable (`1`).
    pub const DESTINATION_UNREACHABLE: Self = Self(1);
    /// Packet Too Big (`2`).
    pub const PACKET_TOO_BIG: Self = Self(2);
    /// Time Exceeded (`3`).
    pub const TIME_EXCEEDED: Self = Self(3);
    /// Parameter Problem (`4`).
    pub const PARAMETER_PROBLEM: Self = Self(4);
    /// Echo Request (`128`).
    pub const ECHO_REQUEST: Self = Self(128);
    /// Echo Reply (`129`).
    pub const ECHO_REPLY: Self = Self(129);

    /// Constructs a type from its raw wire value.
    #[inline]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns the raw wire value.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }
}
