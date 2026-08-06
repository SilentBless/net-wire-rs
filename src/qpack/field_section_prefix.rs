//! RFC 9204 section 4.5.1 encoded field-section prefixes.

use core::fmt;

use super::{
    QPACK_INTEGER_MAX, QpackInteger, QpackIntegerBuildError, QpackIntegerParseError,
    integer::{canonical_encoded_len, integer_from_prevalidated, write_canonical_prevalidated},
};

/// A validated, exact borrowed QPACK encoded field-section prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackFieldSectionPrefix<'a> {
    bytes: &'a [u8],
    encoded_required_insert_count: QpackInteger<'a>,
    negative: bool,
    delta_base: QpackInteger<'a>,
}

impl<'a> QpackFieldSectionPrefix<'a> {
    /// Parses one RFC 9204 section 4.5.1 prefix and excludes following field-line bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, QpackFieldSectionPrefixParseError> {
        let encoded_required_insert_count = QpackInteger::parse(bytes, 8)
            .map_err(QpackFieldSectionPrefixParseError::RequiredInsertCount)?;
        let required_insert_count_len = encoded_required_insert_count.as_bytes().len();
        let delta_bytes = &bytes[required_insert_count_len..];
        let delta_base = QpackInteger::parse(delta_bytes, 7)
            .map_err(QpackFieldSectionPrefixParseError::DeltaBase)?;
        let length = required_insert_count_len
            .checked_add(delta_base.as_bytes().len())
            .ok_or(QpackFieldSectionPrefixParseError::LengthOverflow)?;
        Ok(Self {
            bytes: &bytes[..length],
            encoded_required_insert_count,
            negative: delta_base.high_bits() & 0x80 != 0,
            delta_base,
        })
    }

    /// Returns the complete exact prefix bytes, excluding following field-line bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Returns the exact encoded Required Insert Count integer.
    pub const fn encoded_required_insert_count(self) -> QpackInteger<'a> {
        self.encoded_required_insert_count
    }
    /// Returns whether the Delta Base sign bit is set.
    pub const fn is_negative(self) -> bool {
        self.negative
    }
    /// Returns the exact Delta Base integer.
    pub const fn delta_base(self) -> QpackInteger<'a> {
        self.delta_base
    }
}

/// Failure to parse a QPACK encoded field-section prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackFieldSectionPrefixParseError {
    /// The Encoded Required Insert Count integer is invalid.
    RequiredInsertCount(
        #[doc = "The nested Required Insert Count failure."] QpackIntegerParseError,
    ),
    /// The signed Delta Base integer is invalid.
    DeltaBase(#[doc = "The nested Delta Base failure."] QpackIntegerParseError),
    /// Computing the complete prefix length overflowed `usize`.
    LengthOverflow,
}
impl fmt::Display for QpackFieldSectionPrefixParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiredInsertCount(error) => {
                write!(f, "QPACK Encoded Required Insert Count is invalid: {error}")
            }
            Self::DeltaBase(error) => write!(f, "QPACK Delta Base is invalid: {error}"),
            Self::LengthOverflow => {
                f.write_str("QPACK field-section prefix length overflows usize")
            }
        }
    }
}
impl core::error::Error for QpackFieldSectionPrefixParseError {}

/// A fully validated, allocation-free field-section prefix write plan.
#[derive(Clone, Copy)]
pub(crate) struct QpackFieldSectionPrefixPlan {
    encoded_required_insert_count: u64,
    negative: bool,
    delta_base: u64,
    required_insert_count_len: usize,
    encoded_len: usize,
}
impl QpackFieldSectionPrefixPlan {
    /// Returns the exact number of bytes this plan writes.
    pub(crate) const fn encoded_len(self) -> usize {
        self.encoded_len
    }
    /// Writes this plan into its exact preallocated output region.
    pub(crate) fn write(self, destination: &mut [u8]) {
        if destination.len() != self.encoded_len {
            return;
        }
        let (ric, delta) = destination.split_at_mut(self.required_insert_count_len);
        write_canonical_prevalidated(ric, 8, 0, self.encoded_required_insert_count);
        write_canonical_prevalidated(
            delta,
            7,
            if self.negative { 0x80 } else { 0 },
            self.delta_base,
        );
    }
}

/// Validates one prefix emission without mutating output storage.
pub(crate) fn plan_field_section_prefix(
    encoded_required_insert_count: u64,
    negative: bool,
    delta_base: u64,
) -> Result<QpackFieldSectionPrefixPlan, QpackFieldSectionPrefixBuildError> {
    if encoded_required_insert_count > QPACK_INTEGER_MAX {
        return Err(QpackFieldSectionPrefixBuildError::RequiredInsertCount(
            QpackIntegerBuildError::ValueTooLarge {
                value: encoded_required_insert_count,
            },
        ));
    }
    if delta_base > QPACK_INTEGER_MAX {
        return Err(QpackFieldSectionPrefixBuildError::DeltaBase(
            QpackIntegerBuildError::ValueTooLarge { value: delta_base },
        ));
    }
    let required_insert_count_len = canonical_encoded_len(encoded_required_insert_count, 8);
    let delta_base_len = canonical_encoded_len(delta_base, 7);
    let encoded_len = required_insert_count_len
        .checked_add(delta_base_len)
        .ok_or(QpackFieldSectionPrefixBuildError::RequiredLengthOverflow)?;
    Ok(QpackFieldSectionPrefixPlan {
        encoded_required_insert_count,
        negative,
        delta_base,
        required_insert_count_len,
        encoded_len,
    })
}

/// Builds a canonical QPACK encoded field-section prefix in caller-owned storage.
pub struct QpackFieldSectionPrefixBuilder<'a> {
    destination: &'a mut [u8],
    encoded_required_insert_count: u64,
    negative: bool,
    delta_base: u64,
}
impl<'a> QpackFieldSectionPrefixBuilder<'a> {
    /// Creates a builder from raw encoded Required Insert Count and Delta Base values.
    pub fn new(
        destination: &'a mut [u8],
        encoded_required_insert_count: u64,
        negative: bool,
        delta_base: u64,
    ) -> Self {
        Self {
            destination,
            encoded_required_insert_count,
            negative,
            delta_base,
        }
    }
    /// Validates all inputs and capacity before atomically writing a canonical prefix.
    pub fn build(self) -> Result<QpackFieldSectionPrefix<'a>, QpackFieldSectionPrefixBuildError> {
        let plan = plan_field_section_prefix(
            self.encoded_required_insert_count,
            self.negative,
            self.delta_base,
        )?;
        let required = plan.encoded_len();
        if self.destination.len() < required {
            return Err(QpackFieldSectionPrefixBuildError::BufferTooShort {
                required,
                available: self.destination.len(),
            });
        }
        plan.write(&mut self.destination[..required]);
        let bytes = &self.destination[..required];
        let ric_len = plan.required_insert_count_len;
        Ok(QpackFieldSectionPrefix {
            bytes,
            encoded_required_insert_count: integer_from_prevalidated(
                &bytes[..ric_len],
                8,
                0,
                self.encoded_required_insert_count,
            ),
            negative: self.negative,
            delta_base: integer_from_prevalidated(
                &bytes[ric_len..],
                7,
                if self.negative { 0x80 } else { 0 },
                self.delta_base,
            ),
        })
    }
}

/// Failure to build a QPACK encoded field-section prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackFieldSectionPrefixBuildError {
    /// The Encoded Required Insert Count value is invalid.
    RequiredInsertCount(
        #[doc = "The nested Required Insert Count failure."] QpackIntegerBuildError,
    ),
    /// The Delta Base value is invalid.
    DeltaBase(#[doc = "The nested Delta Base failure."] QpackIntegerBuildError),
    /// Computing the complete prefix length overflowed `usize`.
    RequiredLengthOverflow,
    /// The caller destination cannot contain the complete prefix.
    BufferTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
    },
}
impl fmt::Display for QpackFieldSectionPrefixBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiredInsertCount(error) => write!(
                f,
                "QPACK Encoded Required Insert Count cannot be built: {error}"
            ),
            Self::DeltaBase(error) => write!(f, "QPACK Delta Base cannot be built: {error}"),
            Self::RequiredLengthOverflow => {
                f.write_str("QPACK field-section prefix length overflows usize")
            }
            Self::BufferTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK field-section prefix buffer is too short: need {required} bytes, have {available}"
            ),
        }
    }
}
impl core::error::Error for QpackFieldSectionPrefixBuildError {}
