//! RFC 9204 field-section Required Insert Count and Base arithmetic.

use core::fmt;

use super::prefix::QpackFieldSectionPrefix;

/// A resolved QPACK field-section Required Insert Count and Base.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackFieldSectionContext {
    required_insert_count: u64,
    base: u64,
}

impl QpackFieldSectionContext {
    /// Decodes a field-section prefix using the decoder's insert count and peer maximum capacity.
    pub fn decode(
        prefix: QpackFieldSectionPrefix<'_>,
        total_insert_count: u64,
        maximum_table_capacity: u64,
    ) -> Result<Self, QpackFieldSectionContextError> {
        let required_insert_count = Self::reconstruct_required_insert_count(
            prefix.encoded_required_insert_count().value(),
            total_insert_count,
            maximum_table_capacity,
        )?;
        let base = Self::resolve_base(
            required_insert_count,
            prefix.is_negative(),
            prefix.delta_base().value(),
        )?;
        Ok(Self {
            required_insert_count,
            base,
        })
    }

    /// Reconstructs a Required Insert Count according to RFC 9204 section 4.5.1.1.
    pub fn reconstruct_required_insert_count(
        encoded_required_insert_count: u64,
        total_insert_count: u64,
        maximum_table_capacity: u64,
    ) -> Result<u64, QpackFieldSectionContextError> {
        if encoded_required_insert_count == 0 {
            return Ok(0);
        }

        let max_entries = maximum_table_capacity / 32;
        if max_entries == 0 {
            return Err(QpackFieldSectionContextError::ZeroMaximumEntries {
                encoded_required_insert_count,
            });
        }
        let full_range =
            max_entries
                .checked_mul(2)
                .ok_or(QpackFieldSectionContextError::FullRangeOverflow {
                    maximum_table_capacity,
                    max_entries,
                })?;
        if encoded_required_insert_count > full_range {
            return Err(
                QpackFieldSectionContextError::EncodedRequiredInsertCountOutOfRange {
                    encoded_required_insert_count,
                    full_range,
                },
            );
        }
        let maximum_value = total_insert_count.checked_add(max_entries).ok_or(
            QpackFieldSectionContextError::MaximumValueOverflow {
                total_insert_count,
                max_entries,
            },
        )?;
        let max_wrapped_quotient = maximum_value / full_range;
        let max_wrapped = max_wrapped_quotient.checked_mul(full_range).ok_or(
            QpackFieldSectionContextError::RequiredInsertCountOverflow {
                max_wrapped: max_wrapped_quotient,
                encoded_required_insert_count,
            },
        )?;
        let mut reconstructed = max_wrapped
            .checked_add(encoded_required_insert_count - 1)
            .ok_or(QpackFieldSectionContextError::RequiredInsertCountOverflow {
                max_wrapped,
                encoded_required_insert_count,
            })?;
        if reconstructed > maximum_value {
            if reconstructed <= full_range {
                return Err(QpackFieldSectionContextError::RequiredInsertCountTooOld {
                    reconstructed,
                    maximum_value,
                    full_range,
                });
            }
            reconstructed = reconstructed.checked_sub(full_range).ok_or(
                QpackFieldSectionContextError::RequiredInsertCountTooOld {
                    reconstructed,
                    maximum_value,
                    full_range,
                },
            )?;
        }
        if reconstructed == 0 {
            return Err(QpackFieldSectionContextError::RequiredInsertCountZero);
        }
        Ok(reconstructed)
    }

    /// Encodes a nonzero Required Insert Count modulo the RFC 9204 full range.
    pub fn encode_required_insert_count(
        required_insert_count: u64,
        maximum_table_capacity: u64,
    ) -> Result<u64, QpackFieldSectionContextError> {
        if required_insert_count == 0 {
            return Ok(0);
        }

        let max_entries = maximum_table_capacity / 32;
        if max_entries == 0 {
            return Err(QpackFieldSectionContextError::ZeroMaximumEntries {
                encoded_required_insert_count: required_insert_count,
            });
        }
        let full_range =
            max_entries
                .checked_mul(2)
                .ok_or(QpackFieldSectionContextError::FullRangeOverflow {
                    maximum_table_capacity,
                    max_entries,
                })?;
        required_insert_count
            .checked_rem(full_range)
            .and_then(|count| count.checked_add(1))
            .ok_or(QpackFieldSectionContextError::RequiredInsertCountOverflow {
                max_wrapped: required_insert_count,
                encoded_required_insert_count: required_insert_count,
            })
    }

    /// Resolves a Base from a Required Insert Count, sign bit, and Delta Base.
    pub fn resolve_base(
        required_insert_count: u64,
        negative: bool,
        delta_base: u64,
    ) -> Result<u64, QpackFieldSectionContextError> {
        if negative {
            if delta_base >= required_insert_count {
                return Err(QpackFieldSectionContextError::BaseUnderflow {
                    required_insert_count,
                    delta_base,
                });
            }
            required_insert_count
                .checked_sub(delta_base)
                .and_then(|base| base.checked_sub(1))
                .ok_or(QpackFieldSectionContextError::BaseUnderflow {
                    required_insert_count,
                    delta_base,
                })
        } else {
            required_insert_count.checked_add(delta_base).ok_or(
                QpackFieldSectionContextError::BaseOverflow {
                    required_insert_count,
                    delta_base,
                },
            )
        }
    }

    /// Returns the resolved Required Insert Count.
    pub const fn required_insert_count(self) -> u64 {
        self.required_insert_count
    }

    /// Returns the resolved Base.
    pub const fn base(self) -> u64 {
        self.base
    }
}

/// A failure while resolving QPACK field-section prefix semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackFieldSectionContextError {
    /// Doubling the maximum entry count overflowed `u64`.
    FullRangeOverflow {
        /// The peer's maximum dynamic-table capacity.
        maximum_table_capacity: u64,
        /// The maximum entry count derived from that capacity.
        max_entries: u64,
    },
    /// A nonzero count cannot be represented when the maximum entry count is zero.
    ZeroMaximumEntries {
        /// The triggering encoded or semantic Required Insert Count.
        encoded_required_insert_count: u64,
    },
    /// The encoded Required Insert Count exceeds the full range.
    EncodedRequiredInsertCountOutOfRange {
        /// The wire Encoded Required Insert Count.
        encoded_required_insert_count: u64,
        /// Twice the maximum entry count.
        full_range: u64,
    },
    /// Adding the maximum entry count to the decoder insert count overflowed `u64`.
    MaximumValueOverflow {
        /// The decoder's total insert count.
        total_insert_count: u64,
        /// The maximum entry count derived from peer capacity.
        max_entries: u64,
    },
    /// Reconstructing or encoding the Required Insert Count overflowed `u64`.
    RequiredInsertCountOverflow {
        /// The wrapped count or quotient involved in the failed calculation.
        max_wrapped: u64,
        /// The encoded or semantic Required Insert Count involved in the calculation.
        encoded_required_insert_count: u64,
    },
    /// The reconstructed count cannot be valid for the decoder state.
    RequiredInsertCountTooOld {
        /// The reconstructed Required Insert Count.
        reconstructed: u64,
        /// The largest Required Insert Count valid for the decoder state.
        maximum_value: u64,
        /// Twice the maximum entry count.
        full_range: u64,
    },
    /// A nonzero encoded count reconstructed to zero.
    RequiredInsertCountZero,
    /// Adding Delta Base to Required Insert Count overflowed `u64`.
    BaseOverflow {
        /// The Required Insert Count.
        required_insert_count: u64,
        /// The Delta Base.
        delta_base: u64,
    },
    /// Subtracting Delta Base and one from Required Insert Count underflowed `u64`.
    BaseUnderflow {
        /// The Required Insert Count.
        required_insert_count: u64,
        /// The Delta Base.
        delta_base: u64,
    },
}

impl fmt::Display for QpackFieldSectionContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullRangeOverflow {
                maximum_table_capacity,
                max_entries,
            } => write!(
                formatter,
                "QPACK full range overflows u64 for maximum table capacity {maximum_table_capacity} and maximum entries {max_entries}"
            ),
            Self::ZeroMaximumEntries {
                encoded_required_insert_count,
            } => write!(
                formatter,
                "QPACK Required Insert Count {encoded_required_insert_count} is nonzero with zero maximum entries"
            ),
            Self::EncodedRequiredInsertCountOutOfRange {
                encoded_required_insert_count,
                full_range,
            } => write!(
                formatter,
                "QPACK Encoded Required Insert Count {encoded_required_insert_count} exceeds full range {full_range}"
            ),
            Self::MaximumValueOverflow {
                total_insert_count,
                max_entries,
            } => write!(
                formatter,
                "QPACK maximum Required Insert Count overflows u64 for insert count {total_insert_count} and maximum entries {max_entries}"
            ),
            Self::RequiredInsertCountOverflow {
                max_wrapped,
                encoded_required_insert_count,
            } => write!(
                formatter,
                "QPACK Required Insert Count overflows u64 for wrapped value {max_wrapped} and count {encoded_required_insert_count}"
            ),
            Self::RequiredInsertCountTooOld {
                reconstructed,
                maximum_value,
                full_range,
            } => write!(
                formatter,
                "QPACK Required Insert Count {reconstructed} exceeds maximum {maximum_value} for full range {full_range}"
            ),
            Self::RequiredInsertCountZero => formatter
                .write_str("QPACK nonzero Encoded Required Insert Count reconstructed to zero"),
            Self::BaseOverflow {
                required_insert_count,
                delta_base,
            } => write!(
                formatter,
                "QPACK Base overflows u64 for Required Insert Count {required_insert_count} and Delta Base {delta_base}"
            ),
            Self::BaseUnderflow {
                required_insert_count,
                delta_base,
            } => write!(
                formatter,
                "QPACK Base underflows u64 for Required Insert Count {required_insert_count} and Delta Base {delta_base}"
            ),
        }
    }
}

impl core::error::Error for QpackFieldSectionContextError {}
