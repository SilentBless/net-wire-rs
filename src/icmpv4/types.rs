/// An ICMPv4 message type, preserving unknown values.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Icmpv4Type(u8);

impl Icmpv4Type {
    /// Echo Reply (`0`).
    pub const ECHO_REPLY: Self = Self(0);
    /// Destination Unreachable (`3`).
    pub const DESTINATION_UNREACHABLE: Self = Self(3);
    /// Echo Request (`8`).
    pub const ECHO_REQUEST: Self = Self(8);
    /// Time Exceeded (`11`).
    pub const TIME_EXCEEDED: Self = Self(11);
    /// Constructs a raw type value.
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }
    /// Returns the raw type value.
    pub const fn raw(self) -> u8 {
        self.0
    }
}
