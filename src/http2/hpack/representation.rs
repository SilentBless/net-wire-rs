//! RFC 7541 section 6 header-field representation parsing.

use core::fmt;

use super::integer::{HpackInteger, HpackIntegerParseError};
use super::string::{HpackStringLiteral, HpackStringLiteralParseError};

/// One exact borrowed RFC 7541 section 6 header-field representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackRepresentation<'a> {
    /// An indexed header field.
    Indexed(HpackIndexedField<'a>),
    /// A literal header field.
    Literal(HpackLiteralField<'a>),
    /// A dynamic table size update.
    DynamicTableSizeUpdate(HpackDynamicTableSizeUpdate<'a>),
}

impl<'a> HpackRepresentation<'a> {
    /// Parses one representation and excludes any following bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, HpackRepresentationParseError> {
        let first = *bytes
            .first()
            .ok_or(HpackRepresentationParseError::IndexedIndex(
                HpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0,
                },
            ))?;

        if first & 0x80 != 0 {
            HpackIndexedField::parse(bytes).map(Self::Indexed)
        } else if first & 0x40 != 0 {
            HpackLiteralField::parse(bytes, HpackLiteralMode::IncrementalIndexing)
                .map(Self::Literal)
        } else if first & 0x20 != 0 {
            HpackDynamicTableSizeUpdate::parse(bytes).map(Self::DynamicTableSizeUpdate)
        } else if first & 0x10 != 0 {
            HpackLiteralField::parse(bytes, HpackLiteralMode::NeverIndexed).map(Self::Literal)
        } else {
            HpackLiteralField::parse(bytes, HpackLiteralMode::WithoutIndexing).map(Self::Literal)
        }
    }
}

/// An exact borrowed RFC 7541 section 6.1 indexed header field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpackIndexedField<'a> {
    bytes: &'a [u8],
    index: HpackInteger<'a>,
}

impl<'a> HpackIndexedField<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, HpackRepresentationParseError> {
        let index =
            HpackInteger::parse(bytes, 7).map_err(HpackRepresentationParseError::IndexedIndex)?;
        if index.value() == 0 {
            return Err(HpackRepresentationParseError::IndexedFieldZero);
        }
        Ok(Self {
            bytes: index.as_bytes(),
            index,
        })
    }

    /// Returns the exact indexed-field representation.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact raw-preserving index representation.
    pub const fn index(self) -> HpackInteger<'a> {
        self.index
    }

    /// Returns the decoded index value.
    pub const fn index_value(self) -> u64 {
        self.index.value()
    }
}

/// The indexing behavior requested by an HPACK literal header field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackLiteralMode {
    /// Insert the field into the dynamic table.
    IncrementalIndexing,
    /// Do not insert the field into the dynamic table.
    WithoutIndexing,
    /// Do not insert the field into the dynamic table and mark it sensitive.
    NeverIndexed,
}

/// An exact borrowed RFC 7541 literal header field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpackLiteralField<'a> {
    bytes: &'a [u8],
    mode: HpackLiteralMode,
    name_index: HpackInteger<'a>,
    name: Option<HpackStringLiteral<'a>>,
    value: HpackStringLiteral<'a>,
}

impl<'a> HpackLiteralField<'a> {
    fn parse(
        bytes: &'a [u8],
        mode: HpackLiteralMode,
    ) -> Result<Self, HpackRepresentationParseError> {
        let prefix_bits = match mode {
            HpackLiteralMode::IncrementalIndexing => 6,
            HpackLiteralMode::WithoutIndexing | HpackLiteralMode::NeverIndexed => 4,
        };
        let name_index = HpackInteger::parse(bytes, prefix_bits)
            .map_err(HpackRepresentationParseError::LiteralNameIndex)?;
        let after_name_index = bytes
            .get(name_index.as_bytes().len()..)
            .ok_or(HpackRepresentationParseError::LengthOverflow)?;
        let name = if name_index.value() == 0 {
            let name = HpackStringLiteral::parse(after_name_index)
                .map_err(HpackRepresentationParseError::LiteralName)?;
            Some(name)
        } else {
            None
        };
        let after_name = match name {
            Some(name) => after_name_index
                .get(name.as_bytes().len()..)
                .ok_or(HpackRepresentationParseError::LengthOverflow)?,
            None => after_name_index,
        };
        let value = HpackStringLiteral::parse(after_name)
            .map_err(HpackRepresentationParseError::LiteralValue)?;
        let total = name_index
            .as_bytes()
            .len()
            .checked_add(name.map_or(0, |literal| literal.as_bytes().len()))
            .and_then(|length| length.checked_add(value.as_bytes().len()))
            .ok_or(HpackRepresentationParseError::LengthOverflow)?;
        let representation = bytes
            .get(..total)
            .ok_or(HpackRepresentationParseError::LengthOverflow)?;

        Ok(Self {
            bytes: representation,
            mode,
            name_index,
            name,
            value,
        })
    }

    /// Returns the exact literal-field representation.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the literal field's indexing mode.
    pub const fn mode(self) -> HpackLiteralMode {
        self.mode
    }

    /// Returns the exact raw-preserving name index representation.
    pub const fn name_index(self) -> HpackInteger<'a> {
        self.name_index
    }

    /// Returns the decoded name index value; zero means `name` is present.
    pub const fn name_index_value(self) -> u64 {
        self.name_index.value()
    }

    /// Returns the literal name when the name index is zero.
    pub const fn name(self) -> Option<HpackStringLiteral<'a>> {
        self.name
    }

    /// Returns the required opaque literal value.
    pub const fn value(self) -> HpackStringLiteral<'a> {
        self.value
    }
}

/// An exact borrowed RFC 7541 section 6.3 dynamic table size update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpackDynamicTableSizeUpdate<'a> {
    bytes: &'a [u8],
    size: HpackInteger<'a>,
}

impl<'a> HpackDynamicTableSizeUpdate<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, HpackRepresentationParseError> {
        let size = HpackInteger::parse(bytes, 5)
            .map_err(HpackRepresentationParseError::DynamicTableSize)?;
        Ok(Self {
            bytes: size.as_bytes(),
            size,
        })
    }

    /// Returns the exact dynamic-table-size-update representation.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact raw-preserving size representation.
    pub const fn size(self) -> HpackInteger<'a> {
        self.size
    }

    /// Returns the decoded dynamic table size.
    pub const fn size_value(self) -> u64 {
        self.size.value()
    }
}

/// Failure to parse an HPACK header-field representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpackRepresentationParseError {
    /// The indexed-field integer is malformed, incomplete, or overflows `u64`.
    IndexedIndex(HpackIntegerParseError),
    /// An indexed header field used forbidden index zero.
    IndexedFieldZero,
    /// The literal field's name index is malformed, incomplete, or overflows `u64`.
    LiteralNameIndex(HpackIntegerParseError),
    /// The literal field's name string is malformed or incomplete.
    LiteralName(HpackStringLiteralParseError),
    /// The literal field's value string is malformed or incomplete.
    LiteralValue(HpackStringLiteralParseError),
    /// The dynamic table size integer is malformed, incomplete, or overflows `u64`.
    DynamicTableSize(HpackIntegerParseError),
    /// Component lengths cannot be represented while framing the representation.
    LengthOverflow,
}

impl fmt::Display for HpackRepresentationParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexedIndex(error) => write!(f, "invalid HPACK indexed field index: {error}"),
            Self::IndexedFieldZero => f.write_str("HPACK indexed field index must not be zero"),
            Self::LiteralNameIndex(error) => {
                write!(f, "invalid HPACK literal field name index: {error}")
            }
            Self::LiteralName(error) => write!(f, "invalid HPACK literal field name: {error}"),
            Self::LiteralValue(error) => write!(f, "invalid HPACK literal field value: {error}"),
            Self::DynamicTableSize(error) => write!(f, "invalid HPACK dynamic table size: {error}"),
            Self::LengthOverflow => f.write_str("HPACK representation length overflows usize"),
        }
    }
}
