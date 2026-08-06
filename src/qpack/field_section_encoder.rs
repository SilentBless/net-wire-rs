//! Transactional allocation-free QPACK field-section encoding.

use core::fmt;

use super::{
    QPACK_STATIC_TABLE_LEN, QpackDynamicTable, QpackDynamicTableError, QpackEncoderState,
    QpackEncoderStateError, QpackFieldLineBuildError, QpackFieldSectionContext,
    QpackFieldSectionContextError, QpackFieldSectionPrefixBuildError,
    field_line::{QpackFieldLinePlan, QpackFieldLinePlanInput, plan_field_line},
    field_section_prefix::plan_field_section_prefix,
};

/// An allocation-free QPACK field-section encoder configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackFieldSectionEncoder {
    maximum_dynamic_table_capacity: u64,
}

impl QpackFieldSectionEncoder {
    /// Creates an encoder using the peer's maximum dynamic-table capacity.
    pub const fn new(maximum_dynamic_table_capacity: u64) -> Self {
        Self {
            maximum_dynamic_table_capacity,
        }
    }

    /// Returns the peer's maximum dynamic-table capacity.
    pub const fn maximum_dynamic_table_capacity(self) -> u64 {
        self.maximum_dynamic_table_capacity
    }

    /// Encodes one field section, retaining dynamic references only after its bytes are written.
    ///
    /// Capacity failures leave both scratch slices unchanged. Later failures can overwrite scratch,
    /// but never modify `destination` or encoder accounting. Each semantic input needs one plan
    /// slot; plan slots are opaque overwritten scratch and hold no semantic value on return.
    pub fn encode<'plan, 'output>(
        &self,
        stream_id: u64,
        plans: &[QpackFieldPlan<'plan>],
        base: QpackFieldSectionBase,
        table: &QpackDynamicTable<'_, '_>,
        state: &mut QpackEncoderState<'_, '_>,
        buffers: QpackFieldSectionEncodeBuffers<'_, 'plan, 'output>,
    ) -> Result<QpackEncodedFieldSection<'output>, QpackFieldSectionEncodeError> {
        let QpackFieldSectionEncodeBuffers {
            reference_scratch,
            field_plan_scratch,
            destination,
        } = buffers;
        let reference_count = dynamic_occurrence_count(plans)?;
        if reference_scratch.len() < reference_count {
            return Err(QpackFieldSectionEncodeError::ReferenceScratchTooShort {
                required: reference_count,
                available: reference_scratch.len(),
            });
        }
        if field_plan_scratch.len() < plans.len() {
            return Err(QpackFieldSectionEncodeError::FieldPlanScratchTooShort {
                required: plans.len(),
                available: field_plan_scratch.len(),
            });
        }

        let references = &mut reference_scratch[..reference_count];
        let mut reference_index = 0usize;
        for (field_index, plan) in plans.iter().enumerate() {
            if let Some(absolute_index) = dynamic_absolute(plan) {
                table.get_absolute(absolute_index).map_err(|error| {
                    QpackFieldSectionEncodeError::Plan(
                        QpackFieldSectionPlanError::DynamicReference { field_index, error },
                    )
                })?;
                references[reference_index] = absolute_index;
                reference_index += 1;
            } else if let Some(index) = static_index(plan)
                && index >= QPACK_STATIC_TABLE_LEN as u64
            {
                return Err(QpackFieldSectionEncodeError::Plan(
                    QpackFieldSectionPlanError::StaticIndexOutOfRange { field_index, index },
                ));
            }
        }

        let required_insert_count = required_insert_count(references)?;
        let insert_count = table.insert_count();
        let base = match base {
            QpackFieldSectionBase::RequiredInsertCount => required_insert_count,
            QpackFieldSectionBase::Explicit(base) => {
                if base > insert_count {
                    return Err(QpackFieldSectionEncodeError::BaseExceedsInsertCount {
                        base,
                        insert_count,
                    });
                }
                base
            }
        };
        let (negative, delta_base) = prefix_delta(required_insert_count, base);
        let encoded_required_insert_count = QpackFieldSectionContext::encode_required_insert_count(
            required_insert_count,
            self.maximum_dynamic_table_capacity,
        )
        .map_err(QpackFieldSectionEncodeError::RequiredInsertCountEncoding)?;
        let prefix = plan_field_section_prefix(encoded_required_insert_count, negative, delta_base)
            .map_err(QpackFieldSectionEncodeError::PrefixPlanning)?;

        let mut total = prefix.encoded_len();
        for (field_index, input) in plans.iter().enumerate() {
            let input = field_line_input(*input, base);
            let wire_plan = plan_field_line(input).map_err(|error| {
                QpackFieldSectionEncodeError::Plan(QpackFieldSectionPlanError::FieldLine {
                    field_index,
                    error,
                })
            })?;
            total = total
                .checked_add(wire_plan.encoded_len())
                .ok_or(QpackFieldSectionEncodeError::OutputLengthOverflow)?;
            field_plan_scratch[field_index].wire_plan = wire_plan;
        }
        if destination.len() < total {
            return Err(QpackFieldSectionEncodeError::DestinationTooShort {
                required: total,
                available: destination.len(),
            });
        }

        let reservation = state
            .reserve_registration(stream_id, required_insert_count, references, insert_count)
            .map_err(QpackFieldSectionEncodeError::EncoderStateReservation)?;
        let (prefix_destination, mut fields_destination) =
            destination[..total].split_at_mut(prefix.encoded_len());
        prefix.write(prefix_destination);
        for slot in &field_plan_scratch[..plans.len()] {
            let length = slot.wire_plan.encoded_len();
            let (field_destination, remaining) = fields_destination.split_at_mut(length);
            slot.wire_plan.write(field_destination);
            fields_destination = remaining;
        }
        reservation.commit();
        Ok(QpackEncodedFieldSection {
            bytes: &destination[..total],
            required_insert_count,
            base,
        })
    }
}

/// Caller-owned workspace used by one field-section encoding operation.
pub struct QpackFieldSectionEncodeBuffers<'scratch, 'plan, 'output> {
    reference_scratch: &'scratch mut [u64],
    field_plan_scratch: &'scratch mut [QpackFieldSectionPlanSlot<'plan>],
    destination: &'output mut [u8],
}

impl<'scratch, 'plan, 'output> QpackFieldSectionEncodeBuffers<'scratch, 'plan, 'output> {
    /// Creates an encoding workspace from reference, wire-plan, and output storage.
    pub fn new(
        reference_scratch: &'scratch mut [u64],
        field_plan_scratch: &'scratch mut [QpackFieldSectionPlanSlot<'plan>],
        destination: &'output mut [u8],
    ) -> Self {
        Self {
            reference_scratch,
            field_plan_scratch,
            destination,
        }
    }
}

/// One semantic field representation supplied to [`QpackFieldSectionEncoder`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackFieldPlan<'a> {
    /// An indexed reference to the static table.
    IndexedStatic {
        /// Zero-based static-table index.
        index: u64,
    },
    /// An indexed reference to the dynamic table by zero-based absolute index.
    IndexedDynamic {
        /// Zero-based dynamic absolute index.
        absolute_index: u64,
    },
    /// A literal with a static-table name reference.
    LiteralStaticNameReference {
        /// Whether the field must not be inserted by a recipient.
        never_indexed: bool,
        /// Zero-based static-table name index.
        name_index: u64,
        /// Whether `encoded_value` has Huffman coding.
        value_huffman: bool,
        /// Opaque already-encoded value bytes.
        encoded_value: &'a [u8],
    },
    /// A literal with a dynamic-table name reference by zero-based absolute index.
    LiteralDynamicNameReference {
        /// Whether the field must not be inserted by a recipient.
        never_indexed: bool,
        /// Zero-based dynamic absolute name index.
        name_absolute_index: u64,
        /// Whether `encoded_value` has Huffman coding.
        value_huffman: bool,
        /// Opaque already-encoded value bytes.
        encoded_value: &'a [u8],
    },
    /// A literal name and value with already-encoded opaque payloads.
    LiteralName {
        /// Whether the field must not be inserted by a recipient.
        never_indexed: bool,
        /// Whether `encoded_name` has Huffman coding.
        name_huffman: bool,
        /// Opaque already-encoded name bytes.
        encoded_name: &'a [u8],
        /// Whether `encoded_value` has Huffman coding.
        value_huffman: bool,
        /// Opaque already-encoded value bytes.
        encoded_value: &'a [u8],
    },
}

/// Selects the field section Base used to translate dynamic absolute indexes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackFieldSectionBase {
    /// Use Required Insert Count as the Base.
    RequiredInsertCount,
    /// Use this explicit Base.
    Explicit(#[doc = "The explicit Base."] u64),
}

/// Opaque caller-owned storage for one retained field-line wire plan.
///
/// Initialize arrays with [`Self::EMPTY`]. Supply at least one slot for every semantic plan.
/// Slots are overwritten scratch and have no semantic value after encoding returns.
#[derive(Clone, Copy)]
pub struct QpackFieldSectionPlanSlot<'a> {
    wire_plan: QpackFieldLinePlan<'a>,
}
impl<'a> QpackFieldSectionPlanSlot<'a> {
    /// Empty opaque storage suitable for caller array initialization.
    pub const EMPTY: Self = Self {
        wire_plan: QpackFieldLinePlan::empty(),
    };
}

/// The exact encoded field-section bytes and resolved context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackEncodedFieldSection<'a> {
    bytes: &'a [u8],
    required_insert_count: u64,
    base: u64,
}
impl<'a> QpackEncodedFieldSection<'a> {
    /// Returns the complete encoded prefix and field lines.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Returns the semantic Required Insert Count.
    pub const fn required_insert_count(self) -> u64 {
        self.required_insert_count
    }
    /// Returns the resolved Base.
    pub const fn base(self) -> u64 {
        self.base
    }
    /// Returns the encoded byte length.
    pub const fn len(self) -> usize {
        self.bytes.len()
    }
    /// Returns whether no bytes were encoded.
    pub const fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }
}

/// A field-specific planning failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackFieldSectionPlanError {
    /// A static-table index is outside RFC 9204 Appendix A.
    StaticIndexOutOfRange {
        /// Index of the semantic field plan.
        field_index: usize,
        /// Invalid static-table index.
        index: u64,
    },
    /// A dynamic absolute index cannot be resolved from the active dynamic table.
    DynamicReference {
        /// Index of the semantic field plan.
        field_index: usize,
        /// Nested dynamic-table lookup failure.
        error: QpackDynamicTableError,
    },

    /// A field-line wire representation cannot be planned.
    FieldLine {
        /// Index of the semantic field plan.
        field_index: usize,
        /// Nested field-line planning failure.
        error: QpackFieldLineBuildError,
    },
}
impl fmt::Display for QpackFieldSectionPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaticIndexOutOfRange { field_index, index } => write!(
                f,
                "QPACK field {field_index} has static-table index {index} outside the table"
            ),
            Self::DynamicReference { field_index, error } => write!(
                f,
                "QPACK field {field_index} has an invalid dynamic reference: {error}"
            ),

            Self::FieldLine { field_index, error } => {
                write!(f, "QPACK field {field_index} cannot be planned: {error}")
            }
        }
    }
}
impl core::error::Error for QpackFieldSectionPlanError {}

/// Failure to encode one QPACK field section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackFieldSectionEncodeError {
    /// Counting dynamic-reference occurrences overflowed `usize`.
    ReferenceCountOverflow,
    /// The caller supplied too little reference scratch.
    ReferenceScratchTooShort {
        /// Required number of reference slots.
        required: usize,
        /// Available reference slots.
        available: usize,
    },
    /// The caller supplied too little retained field-plan scratch.
    FieldPlanScratchTooShort {
        /// Required number of plan slots.
        required: usize,
        /// Available plan slots.
        available: usize,
    },
    /// One semantic field plan is invalid.
    Plan(QpackFieldSectionPlanError),
    /// Adding one to the largest dynamic absolute index overflowed `u64`.
    RequiredInsertCountOverflow {
        /// Largest zero-based absolute index.
        absolute_index: u64,
    },
    /// The explicit Base is greater than the dynamic table insert count.
    BaseExceedsInsertCount {
        /// Requested Base.
        base: u64,
        /// Current dynamic-table insert count.
        insert_count: u64,
    },

    /// Required Insert Count context encoding failed.
    RequiredInsertCountEncoding(QpackFieldSectionContextError),
    /// Prefix wire planning failed.
    PrefixPlanning(QpackFieldSectionPrefixBuildError),
    /// Summing the complete output length overflowed `usize`.
    OutputLengthOverflow,
    /// The destination is too short for the complete field section.
    DestinationTooShort {
        /// Required output bytes.
        required: usize,
        /// Available output bytes.
        available: usize,
    },
    /// Encoder accounting could not reserve the dynamic references.
    EncoderStateReservation(QpackEncoderStateError),
}
impl QpackFieldSectionEncodeError {
    /// Returns whether this failure is caused by insufficient caller-owned scratch or output storage.
    pub const fn is_provisioning_error(self) -> bool {
        matches!(
            self,
            Self::ReferenceScratchTooShort { .. }
                | Self::FieldPlanScratchTooShort { .. }
                | Self::DestinationTooShort { .. }
        )
    }
}
impl fmt::Display for QpackFieldSectionEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReferenceCountOverflow => {
                f.write_str("QPACK dynamic reference count overflows usize")
            }
            Self::ReferenceScratchTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK reference scratch needs {required} slots, has {available}"
            ),
            Self::FieldPlanScratchTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK field-plan scratch needs {required} slots, has {available}"
            ),
            Self::Plan(error) => write!(f, "QPACK field-section plan is invalid: {error}"),
            Self::RequiredInsertCountOverflow { absolute_index } => write!(
                f,
                "QPACK Required Insert Count overflows for absolute index {absolute_index}"
            ),
            Self::BaseExceedsInsertCount { base, insert_count } => {
                write!(f, "QPACK Base {base} exceeds insert count {insert_count}")
            }

            Self::RequiredInsertCountEncoding(error) => {
                write!(f, "QPACK Required Insert Count cannot be encoded: {error}")
            }
            Self::PrefixPlanning(error) => {
                write!(f, "QPACK field-section prefix cannot be planned: {error}")
            }
            Self::OutputLengthOverflow => {
                f.write_str("QPACK field-section output length overflows usize")
            }
            Self::DestinationTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK field-section destination needs {required} bytes, has {available}"
            ),
            Self::EncoderStateReservation(error) => write!(
                f,
                "QPACK encoder state cannot reserve field section: {error}"
            ),
        }
    }
}
impl core::error::Error for QpackFieldSectionEncodeError {}

fn dynamic_occurrence_count(
    plans: &[QpackFieldPlan<'_>],
) -> Result<usize, QpackFieldSectionEncodeError> {
    let mut count = 0usize;
    for plan in plans {
        if dynamic_absolute(plan).is_some() {
            count = count
                .checked_add(1)
                .ok_or(QpackFieldSectionEncodeError::ReferenceCountOverflow)?;
        }
    }
    Ok(count)
}
fn dynamic_absolute(plan: &QpackFieldPlan<'_>) -> Option<u64> {
    match *plan {
        QpackFieldPlan::IndexedDynamic { absolute_index } => Some(absolute_index),
        QpackFieldPlan::LiteralDynamicNameReference {
            name_absolute_index,
            ..
        } => Some(name_absolute_index),
        _ => None,
    }
}
fn static_index(plan: &QpackFieldPlan<'_>) -> Option<u64> {
    match *plan {
        QpackFieldPlan::IndexedStatic { index } => Some(index),
        QpackFieldPlan::LiteralStaticNameReference { name_index, .. } => Some(name_index),
        _ => None,
    }
}
fn required_insert_count(references: &[u64]) -> Result<u64, QpackFieldSectionEncodeError> {
    let mut largest = match references.first() {
        Some(value) => *value,
        None => return Ok(0),
    };
    for &reference in &references[1..] {
        if reference > largest {
            largest = reference;
        }
    }
    largest
        .checked_add(1)
        .ok_or(QpackFieldSectionEncodeError::RequiredInsertCountOverflow {
            absolute_index: largest,
        })
}
fn prefix_delta(required_insert_count: u64, base: u64) -> (bool, u64) {
    if base >= required_insert_count {
        return (false, base - required_insert_count);
    }
    (true, required_insert_count - base - 1)
}
fn field_line_input<'a>(plan: QpackFieldPlan<'a>, base: u64) -> QpackFieldLinePlanInput<'a> {
    match plan {
        QpackFieldPlan::IndexedStatic { index } => QpackFieldLinePlanInput::IndexedStatic { index },
        QpackFieldPlan::IndexedDynamic { absolute_index } => {
            dynamic_indexed_input(absolute_index, base)
        }
        QpackFieldPlan::LiteralStaticNameReference {
            never_indexed,
            name_index,
            value_huffman,
            encoded_value,
        } => QpackFieldLinePlanInput::LiteralStaticNameReference {
            never_indexed,
            index: name_index,
            value_huffman,
            encoded_value,
        },
        QpackFieldPlan::LiteralDynamicNameReference {
            never_indexed,
            name_absolute_index,
            value_huffman,
            encoded_value,
        } => dynamic_name_input(
            never_indexed,
            name_absolute_index,
            value_huffman,
            encoded_value,
            base,
        ),
        QpackFieldPlan::LiteralName {
            never_indexed,
            name_huffman,
            encoded_name,
            value_huffman,
            encoded_value,
        } => QpackFieldLinePlanInput::LiteralName {
            never_indexed,
            name_huffman,
            encoded_name,
            value_huffman,
            encoded_value,
        },
    }
}
fn dynamic_indexed_input(absolute_index: u64, base: u64) -> QpackFieldLinePlanInput<'static> {
    if absolute_index < base {
        QpackFieldLinePlanInput::IndexedDynamicPreBase {
            relative_index: base - absolute_index - 1,
        }
    } else {
        QpackFieldLinePlanInput::IndexedDynamicPostBase {
            post_base_index: absolute_index - base,
        }
    }
}
fn dynamic_name_input<'a>(
    never_indexed: bool,
    absolute_index: u64,
    value_huffman: bool,
    encoded_value: &'a [u8],
    base: u64,
) -> QpackFieldLinePlanInput<'a> {
    if absolute_index < base {
        QpackFieldLinePlanInput::LiteralDynamicPreBaseNameReference {
            never_indexed,
            relative_index: base - absolute_index - 1,
            value_huffman,
            encoded_value,
        }
    } else {
        QpackFieldLinePlanInput::LiteralDynamicPostBaseNameReference {
            never_indexed,
            post_base_index: absolute_index - base,
            value_huffman,
            encoded_value,
        }
    }
}
