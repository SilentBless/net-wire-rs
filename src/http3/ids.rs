//! HTTP/3 protocol identifiers.

/// An HTTP/3 push identifier without semantic validation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Http3PushId(u64);

impl Http3PushId {
    /// Creates a raw push identifier.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw push identifier value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// An HTTP/3 stream identifier without semantic validation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Http3StreamId(u64);

impl Http3StreamId {
    /// Creates a raw stream identifier.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw stream identifier value.
    pub const fn value(self) -> u64 {
        self.0
    }
}
