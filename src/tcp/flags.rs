//! TCP control flags.

use core::ops::{BitOr, BitOrAssign};

/// The eight TCP control flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct TcpFlags(u8);
impl TcpFlags {
    /// FIN flag.
    pub const FIN: Self = Self(1);
    /// SYN flag.
    pub const SYN: Self = Self(2);
    /// RST flag.
    pub const RST: Self = Self(4);
    /// PSH flag.
    pub const PSH: Self = Self(8);
    /// ACK flag.
    pub const ACK: Self = Self(16);
    /// URG flag.
    pub const URG: Self = Self(32);
    /// ECE flag.
    pub const ECE: Self = Self(64);
    /// CWR flag.
    pub const CWR: Self = Self(128);
    /// Constructs flags from their wire value.
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }
    /// Returns the wire value.
    pub const fn raw(self) -> u8 {
        self.0
    }
    /// Returns whether all flags in `other` are set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    /// Returns the union of two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
impl BitOr for TcpFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}
impl BitOrAssign for TcpFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = self.union(rhs);
    }
}
