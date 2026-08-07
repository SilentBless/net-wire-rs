//! KCP scalar wire values and stateless sequence helpers.

/// A KCP conversation identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KcpConversationId(u32);

impl KcpConversationId {
    /// Creates a conversation identifier from its raw wire value.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw wire value.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// A raw KCP command byte, including values not known by this crate.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KcpCommand(u8);

impl KcpCommand {
    /// Data segment command (`81`).
    pub const PUSH: Self = Self(81);
    /// Acknowledgment segment command (`82`).
    pub const ACK: Self = Self(82);
    /// Window-size probe command (`83`).
    pub const WASK: Self = Self(83);
    /// Window-size report command (`84`).
    pub const WINS: Self = Self(84);

    /// Creates a command from its raw wire value.
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns the raw wire value.
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Classifies this command when it is one of KCP's upstream-defined commands.
    pub const fn known(self) -> Option<KcpKnownCommand> {
        KcpKnownCommand::from_raw(self.0)
    }
}

/// A KCP command defined by the upstream wire format.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KcpKnownCommand {
    /// Data segment (`81`).
    Push,
    /// Acknowledgment segment (`82`).
    Ack,
    /// Window-size probe (`83`).
    Wask,
    /// Window-size report (`84`).
    Wins,
}

impl KcpKnownCommand {
    /// Classifies an upstream-defined raw command value.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            81 => Some(Self::Push),
            82 => Some(Self::Ack),
            83 => Some(Self::Wask),
            84 => Some(Self::Wins),
            _ => None,
        }
    }

    /// Returns this command as its raw-preserving wire value.
    pub const fn command(self) -> KcpCommand {
        match self {
            Self::Push => KcpCommand::PUSH,
            Self::Ack => KcpCommand::ACK,
            Self::Wask => KcpCommand::WASK,
            Self::Wins => KcpCommand::WINS,
        }
    }

    /// Returns this command's raw wire value.
    pub const fn raw(self) -> u8 {
        self.command().raw()
    }
}

/// A KCP fragment number.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KcpFragment(u8);

impl KcpFragment {
    /// Creates a fragment number from its raw wire value.
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns the raw wire value.
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Returns whether this is the final fragment of a message.
    pub const fn is_final(self) -> bool {
        self.0 == 0
    }
}

/// A KCP timestamp interpreted modulo 2^32.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KcpTimestamp(u32);

impl KcpTimestamp {
    /// Creates a timestamp from its raw wire value.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw wire value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the upstream-compatible signed modular distance from `earlier` to `self`.
    pub const fn distance_from(self, earlier: Self) -> i32 {
        self.0.wrapping_sub(earlier.0) as i32
    }

    /// Returns whether this timestamp is before `other` in upstream-compatible modular order.
    ///
    /// The ordering is meaningful only when the values differ by less than half the `u32` range.
    /// At exactly half the range, this follows upstream signed-difference behavior despite the
    /// ambiguous modular ordering.
    pub const fn is_before(self, other: Self) -> bool {
        self.distance_from(other) < 0
    }

    /// Returns whether this timestamp is after `other` in upstream-compatible modular order.
    ///
    /// The ordering is meaningful only when the values differ by less than half the `u32` range.
    /// At exactly half the range, this follows upstream signed-difference behavior despite the
    /// ambiguous modular ordering.
    pub const fn is_after(self, other: Self) -> bool {
        self.distance_from(other) > 0
    }
}

/// A KCP sequence number interpreted modulo 2^32.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KcpSequenceNumber(u32);

impl KcpSequenceNumber {
    /// Creates a sequence number from its raw wire value.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw wire value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the upstream-compatible signed modular distance from `earlier` to `self`.
    pub const fn distance_from(self, earlier: Self) -> i32 {
        self.0.wrapping_sub(earlier.0) as i32
    }

    /// Returns whether this sequence number is before `other` in upstream-compatible modular order.
    ///
    /// The ordering is meaningful only when the values differ by less than half the `u32` range.
    /// At exactly half the range, this follows upstream signed-difference behavior despite the
    /// ambiguous modular ordering.
    pub const fn is_before(self, other: Self) -> bool {
        self.distance_from(other) < 0
    }

    /// Returns whether this sequence number is after `other` in upstream-compatible modular order.
    ///
    /// The ordering is meaningful only when the values differ by less than half the `u32` range.
    /// At exactly half the range, this follows upstream signed-difference behavior despite the
    /// ambiguous modular ordering.
    pub const fn is_after(self, other: Self) -> bool {
        self.distance_from(other) > 0
    }
}

/// A KCP unacknowledged sequence-number marker.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KcpUnacknowledged(u32);

impl KcpUnacknowledged {
    /// Creates an unacknowledged marker from its raw wire value.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw wire value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Converts this marker explicitly to the corresponding sequence number.
    pub const fn into_sequence_number(self) -> KcpSequenceNumber {
        KcpSequenceNumber::new(self.0)
    }
}
