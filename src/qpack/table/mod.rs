//! Shared QPACK table primitives.

mod dynamic;
mod r#static;

pub use dynamic::{QpackDynamicTable, QpackDynamicTableEntry, QpackDynamicTableError};
pub use r#static::{QPACK_STATIC_TABLE_LEN, QpackStaticTable};

/// A borrowed QPACK header field with byte-oriented name and value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackHeaderFieldRef<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

impl<'a> QpackHeaderFieldRef<'a> {
    /// Creates a borrowed header field from opaque name and value bytes.
    pub const fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self { name, value }
    }

    /// Returns the opaque header name bytes.
    pub const fn name(self) -> &'a [u8] {
        self.name
    }

    /// Returns the opaque header value bytes.
    pub const fn value(self) -> &'a [u8] {
        self.value
    }
}
