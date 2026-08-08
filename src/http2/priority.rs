/// The priority section carried by a HEADERS frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Priority {
    raw_dependency: u32,
    weight: u8,
}

impl Http2Priority {
    /// Creates a priority section from its raw dependency field and encoded weight.
    pub const fn new(raw_dependency: u32, weight: u8) -> Self {
        Self {
            raw_dependency,
            weight,
        }
    }

    pub(super) fn parse(bytes: &[u8]) -> Self {
        Self {
            raw_dependency: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            weight: bytes[4],
        }
    }

    /// Returns whether the exclusive dependency bit is set.
    pub const fn is_exclusive(self) -> bool {
        self.raw_dependency & 0x8000_0000 != 0
    }

    /// Returns the raw dependency field, including the exclusive bit.
    pub const fn raw_dependency(self) -> u32 {
        self.raw_dependency
    }

    /// Returns the 31-bit stream dependency value.
    pub const fn dependency(self) -> u32 {
        self.raw_dependency & 0x7fff_ffff
    }

    /// Returns the raw encoded weight.
    pub const fn weight(self) -> u8 {
        self.weight
    }
}
