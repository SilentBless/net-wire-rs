//! Caller-owned encoder accounting for outstanding dynamic QPACK references.

use core::fmt;

use crate::qpack::stream::decoder::{
    QpackDecoderInstruction, QpackDecoderInstructions, QpackDecoderInstructionsParseError,
};

/// Metadata for one outstanding field section that contains dynamic references.
///
/// The reference range identifies internal packed storage used for eviction protection and
/// decoder-instruction application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackEncoderOutstandingSection {
    stream_id: u64,
    required_insert_count: u64,
    reference_start: usize,
    reference_len: usize,
}

impl QpackEncoderOutstandingSection {
    /// Empty metadata suitable for caller-supplied section storage.
    pub const EMPTY: Self = Self {
        stream_id: 0,
        required_insert_count: 0,
        reference_start: 0,
        reference_len: 0,
    };

    /// Returns the field section's stream identifier.
    pub const fn stream_id(self) -> u64 {
        self.stream_id
    }

    /// Returns the field section's Required Insert Count.
    pub const fn required_insert_count(self) -> u64 {
        self.required_insert_count
    }

    /// Returns the number of dynamic-reference occurrences in this field section.
    pub const fn reference_len(self) -> usize {
        self.reference_len
    }
}

/// A failure while accounting for an encoder field section's dynamic references.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackEncoderStateError {
    /// The Required Insert Count does not match the supplied dynamic references.
    RequiredInsertCountMismatch {
        /// The supplied Required Insert Count.
        required_insert_count: u64,
        /// The Required Insert Count implied by the references.
        expected_required_insert_count: u64,
    },
    /// Adding one to the largest absolute reference overflowed `u64`.
    RequiredInsertCountOverflow {
        /// The largest supplied zero-based absolute index.
        absolute_index: u64,
    },
    /// The Required Insert Count is greater than the encoder's insert count.
    RequiredInsertCountExceedsInsertCount {
        /// The supplied Required Insert Count.
        required_insert_count: u64,
        /// The encoder's current insert count.
        encoder_insert_count: u64,
    },
    /// The caller supplied no remaining section metadata slots.
    SectionStorageExhausted {
        /// The number of supplied section metadata slots.
        capacity: usize,
    },
    /// The caller supplied too few reference slots for all occurrences.
    ReferenceStorageTooShort {
        /// The number of additional reference slots required.
        required: usize,
        /// The number of remaining reference slots available.
        available: usize,
    },
    /// Starting a field section would exceed the peer's blocked-stream limit.
    BlockedStreamsLimitExceeded {
        /// The peer's SETTINGS_QPACK_BLOCKED_STREAMS value.
        maximum: u64,
    },
}

impl QpackEncoderStateError {
    /// Returns whether this failure is caused by insufficient caller-owned storage.
    pub const fn is_provisioning_error(self) -> bool {
        matches!(
            self,
            Self::SectionStorageExhausted { .. } | Self::ReferenceStorageTooShort { .. }
        )
    }

    /// Returns whether this failure requires choosing a nonblocking representation.
    pub const fn is_blocked_streams_limit_error(self) -> bool {
        matches!(self, Self::BlockedStreamsLimitExceeded { .. })
    }
}

impl fmt::Display for QpackEncoderStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiredInsertCountMismatch {
                required_insert_count,
                expected_required_insert_count,
            } => write!(
                formatter,
                "Required Insert Count {required_insert_count} does not match expected count {expected_required_insert_count}"
            ),
            Self::RequiredInsertCountOverflow { absolute_index } => write!(
                formatter,
                "Required Insert Count overflows u64 for absolute index {absolute_index}"
            ),
            Self::RequiredInsertCountExceedsInsertCount {
                required_insert_count,
                encoder_insert_count,
            } => write!(
                formatter,
                "Required Insert Count {required_insert_count} exceeds encoder insert count {encoder_insert_count}"
            ),
            Self::SectionStorageExhausted { capacity } => {
                write!(
                    formatter,
                    "section storage capacity {capacity} is exhausted"
                )
            }
            Self::ReferenceStorageTooShort {
                required,
                available,
            } => write!(
                formatter,
                "reference storage requires {required} slots but only {available} remain"
            ),
            Self::BlockedStreamsLimitExceeded { maximum } => {
                write!(formatter, "blocked streams exceed maximum {maximum}")
            }
        }
    }
}

impl core::error::Error for QpackEncoderStateError {}

/// A failure while applying a QPACK decoder-stream instruction to encoder accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackDecoderInstructionApplyError {
    /// A Section Acknowledgment named no outstanding dynamic-reference field section.
    SectionAcknowledgmentWithoutOutstandingReferences {
        /// The acknowledged stream identifier.
        stream_id: u64,
    },
    /// An Insert Count Increment carried an increment of zero.
    InsertCountIncrementZero,
    /// An Insert Count Increment would exceed the encoder's insert count.
    InsertCountIncrementExceedsInsertCount {
        /// The previous Known Received Count.
        known_received_count: u64,
        /// The supplied Insert Count Increment.
        increment: u64,
        /// The encoder's current insert count.
        encoder_insert_count: u64,
    },
}

impl QpackDecoderInstructionApplyError {
    /// Returns whether this failure is a QPACK decoder-stream error.
    pub const fn is_decoder_stream_error(self) -> bool {
        true
    }
}

impl fmt::Display for QpackDecoderInstructionApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SectionAcknowledgmentWithoutOutstandingReferences { stream_id } => write!(
                formatter,
                "Section Acknowledgment stream {stream_id} has no outstanding dynamic references"
            ),
            Self::InsertCountIncrementZero => {
                formatter.write_str("Insert Count Increment must be greater than zero")
            }
            Self::InsertCountIncrementExceedsInsertCount {
                known_received_count,
                increment,
                encoder_insert_count,
            } => write!(
                formatter,
                "Insert Count Increment {increment} from Known Received Count {known_received_count} exceeds encoder insert count {encoder_insert_count}"
            ),
        }
    }
}

impl core::error::Error for QpackDecoderInstructionApplyError {}

/// Failure to validate or apply a QPACK decoder-stream instruction sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackDecoderInstructionsApplyError {
    /// The complete sequence is malformed before application begins.
    Parse(QpackDecoderInstructionsParseError),
    /// Applying one validated instruction failed at this absolute byte offset.
    Apply {
        /// Absolute byte offset of the instruction that failed to apply.
        offset: usize,
        /// The instruction application failure.
        error: QpackDecoderInstructionApplyError,
    },
}

impl QpackDecoderInstructionsApplyError {
    /// Returns whether this failure is a QPACK decoder-stream error.
    pub const fn is_decoder_stream_error(self) -> bool {
        match self {
            Self::Parse(_) => true,
            Self::Apply { error, .. } => error.is_decoder_stream_error(),
        }
    }
}

impl fmt::Display for QpackDecoderInstructionsApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(
                formatter,
                "QPACK decoder instruction sequence is invalid: {error}"
            ),
            Self::Apply { offset, error } => write!(
                formatter,
                "QPACK decoder instruction application failed at byte {offset}: {error}"
            ),
        }
    }
}

impl core::error::Error for QpackDecoderInstructionsApplyError {}

/// Caller-owned encoder accounting for outstanding field sections with dynamic references.
///
/// `maximum_blocked_streams` is the peer's SETTINGS_QPACK_BLOCKED_STREAMS value. Field-section
/// encoding reserves this state before writing output and commits the reservation only after
/// emission succeeds, keeping output and accounting atomic. Packed sections and reference
/// occurrences are retained in registration order for later decoder-instruction application.
pub struct QpackEncoderState<'sections, 'references> {
    sections: &'sections mut [QpackEncoderOutstandingSection],
    references: &'references mut [u64],
    section_len: usize,
    reference_len: usize,
    known_received_count: u64,
    maximum_blocked_streams: u64,
}

/// A validated registration that keeps encoder accounting unmodified until commit.
///
/// A combined field-section encoder can retain this reservation while emitting prevalidated
/// output, then atomically commit the corresponding accounting.
pub(in crate::qpack) struct QpackEncoderStateRegistration<'state, 'sections, 'references, 'input> {
    state: &'state mut QpackEncoderState<'sections, 'references>,
    stream_id: u64,
    required_insert_count: u64,
    absolute_references: &'input [u64],
    reference_start: usize,
}

impl<'state, 'sections, 'references, 'input>
    QpackEncoderStateRegistration<'state, 'sections, 'references, 'input>
{
    /// Commits this validated registration to encoder accounting.
    pub(in crate::qpack) fn commit(self) {
        if self.absolute_references.is_empty() {
            return;
        }

        let reference_end = self.reference_start + self.absolute_references.len();
        self.state.references[self.reference_start..reference_end]
            .copy_from_slice(self.absolute_references);
        self.state.sections[self.state.section_len] = QpackEncoderOutstandingSection {
            stream_id: self.stream_id,
            required_insert_count: self.required_insert_count,
            reference_start: self.reference_start,
            reference_len: self.absolute_references.len(),
        };
        self.state.reference_len += self.absolute_references.len();
        self.state.section_len += 1;
    }
}

impl<'sections, 'references> QpackEncoderState<'sections, 'references> {
    /// Creates empty accounting backed by caller-owned section and reference storage.
    pub fn new(
        sections: &'sections mut [QpackEncoderOutstandingSection],
        references: &'references mut [u64],
        maximum_blocked_streams: u64,
    ) -> Self {
        for section in sections.iter_mut() {
            *section = QpackEncoderOutstandingSection::EMPTY;
        }
        for reference in references.iter_mut() {
            *reference = 0;
        }
        Self {
            sections,
            references,
            section_len: 0,
            reference_len: 0,
            known_received_count: 0,
            maximum_blocked_streams,
        }
    }

    /// Returns the number of inserts known to have been received by the peer decoder.
    pub const fn known_received_count(&self) -> u64 {
        self.known_received_count
    }

    /// Returns the peer's SETTINGS_QPACK_BLOCKED_STREAMS value.
    pub const fn maximum_blocked_streams(&self) -> u64 {
        self.maximum_blocked_streams
    }

    /// Returns the number of outstanding dynamic-reference field sections.
    pub const fn len(&self) -> usize {
        self.section_len
    }

    /// Returns whether there are no outstanding dynamic-reference field sections.
    pub const fn is_empty(&self) -> bool {
        self.section_len == 0
    }

    /// Returns the number of retained dynamic-reference occurrences.
    pub const fn reference_len(&self) -> usize {
        self.reference_len
    }

    /// Returns the number of caller-supplied section metadata slots.
    pub const fn section_storage_capacity(&self) -> usize {
        self.sections.len()
    }

    /// Returns the number of caller-supplied reference slots.
    pub const fn reference_storage_capacity(&self) -> usize {
        self.references.len()
    }

    /// Returns the number of distinct streams currently at risk of blocking.
    pub fn blocked_stream_count(&self) -> usize {
        let mut count = 0;
        for (index, section) in self.sections[..self.section_len].iter().enumerate() {
            if section.required_insert_count > self.known_received_count
                && !self.sections[..index].iter().any(|previous| {
                    previous.required_insert_count > self.known_received_count
                        && previous.stream_id == section.stream_id
                })
            {
                count += 1;
            }
        }
        count
    }

    /// Registers an outstanding field section containing dynamic-reference occurrences.
    ///
    /// References are copied unchanged and may contain duplicates. This method validates every
    /// condition before mutating state. It does not check whether referenced entries are active;
    /// that is the future field-section encoder's responsibility.
    pub fn register(
        &mut self,
        stream_id: u64,
        required_insert_count: u64,
        absolute_references: &[u64],
        encoder_insert_count: u64,
    ) -> Result<(), QpackEncoderStateError> {
        self.reserve_registration(
            stream_id,
            required_insert_count,
            absolute_references,
            encoder_insert_count,
        )?
        .commit();
        Ok(())
    }

    /// Validates a registration while leaving encoder accounting unmodified until commit.
    pub(in crate::qpack) fn reserve_registration<'input>(
        &mut self,
        stream_id: u64,
        required_insert_count: u64,
        absolute_references: &'input [u64],
        encoder_insert_count: u64,
    ) -> Result<
        QpackEncoderStateRegistration<'_, 'sections, 'references, 'input>,
        QpackEncoderStateError,
    > {
        if absolute_references.is_empty() {
            if required_insert_count == 0 {
                let reference_start = self.reference_len;
                return Ok(QpackEncoderStateRegistration {
                    state: self,
                    stream_id,
                    required_insert_count,
                    absolute_references,
                    reference_start,
                });
            }
            return Err(QpackEncoderStateError::RequiredInsertCountMismatch {
                required_insert_count,
                expected_required_insert_count: 0,
            });
        }

        let mut largest = absolute_references[0];
        for &absolute_index in &absolute_references[1..] {
            if absolute_index > largest {
                largest = absolute_index;
            }
        }
        let expected_required_insert_count =
            largest
                .checked_add(1)
                .ok_or(QpackEncoderStateError::RequiredInsertCountOverflow {
                    absolute_index: largest,
                })?;
        if required_insert_count != expected_required_insert_count {
            return Err(QpackEncoderStateError::RequiredInsertCountMismatch {
                required_insert_count,
                expected_required_insert_count,
            });
        }
        if required_insert_count > encoder_insert_count {
            return Err(
                QpackEncoderStateError::RequiredInsertCountExceedsInsertCount {
                    required_insert_count,
                    encoder_insert_count,
                },
            );
        }
        if self.section_len == self.sections.len() {
            return Err(QpackEncoderStateError::SectionStorageExhausted {
                capacity: self.sections.len(),
            });
        }

        let available_references = self.references.len() - self.reference_len;
        if absolute_references.len() > available_references {
            return Err(QpackEncoderStateError::ReferenceStorageTooShort {
                required: absolute_references.len(),
                available: available_references,
            });
        }

        let could_block = required_insert_count > self.known_received_count;
        let stream_already_risks_blocking = could_block
            && self.sections[..self.section_len].iter().any(|section| {
                section.stream_id == stream_id
                    && section.required_insert_count > self.known_received_count
            });
        if could_block && !stream_already_risks_blocking {
            let blocked_stream_count = self.blocked_stream_count();
            if u64::try_from(blocked_stream_count)
                .map_or(true, |count| count >= self.maximum_blocked_streams)
            {
                return Err(QpackEncoderStateError::BlockedStreamsLimitExceeded {
                    maximum: self.maximum_blocked_streams,
                });
            }
        }

        let reference_start = self.reference_len;
        Ok(QpackEncoderStateRegistration {
            state: self,
            stream_id,
            required_insert_count,
            absolute_references,
            reference_start,
        })
    }

    /// Applies one parsed decoder-stream instruction to outstanding-reference accounting.
    ///
    /// A Stream Cancellation removes all matching sections but does not advance the Known
    /// Received Count.
    pub fn apply(
        &mut self,
        instruction: QpackDecoderInstruction<'_>,
        encoder_insert_count: u64,
    ) -> Result<(), QpackDecoderInstructionApplyError> {
        match instruction {
            QpackDecoderInstruction::SectionAcknowledgment(acknowledgment) => {
                let stream_id = acknowledgment.stream_id().value();
                let section_index = self.sections[..self.section_len]
                    .iter()
                    .position(|section| section.stream_id == stream_id)
                    .ok_or(
                        QpackDecoderInstructionApplyError::SectionAcknowledgmentWithoutOutstandingReferences {
                            stream_id,
                        },
                    )?;
                self.known_received_count = self
                    .known_received_count
                    .max(self.sections[section_index].required_insert_count);
                self.remove_section(section_index);
                Ok(())
            }
            QpackDecoderInstruction::StreamCancellation(cancellation) => {
                let stream_id = cancellation.stream_id().value();
                let mut section_index = 0;
                while section_index < self.section_len {
                    if self.sections[section_index].stream_id == stream_id {
                        self.remove_section(section_index);
                    } else {
                        section_index += 1;
                    }
                }
                Ok(())
            }
            QpackDecoderInstruction::InsertCountIncrement(increment) => {
                let increment = increment.increment().value();
                if increment == 0 {
                    return Err(QpackDecoderInstructionApplyError::InsertCountIncrementZero);
                }

                let known_received_count = self.known_received_count;
                let Some(next_known_received_count) = known_received_count.checked_add(increment)
                else {
                    return Err(
                        QpackDecoderInstructionApplyError::InsertCountIncrementExceedsInsertCount {
                            known_received_count,
                            increment,
                            encoder_insert_count,
                        },
                    );
                };
                if next_known_received_count > encoder_insert_count {
                    return Err(
                        QpackDecoderInstructionApplyError::InsertCountIncrementExceedsInsertCount {
                            known_received_count,
                            increment,
                            encoder_insert_count,
                        },
                    );
                }
                self.known_received_count = next_known_received_count;
                Ok(())
            }
        }
    }

    /// Validates and applies a complete unframed decoder-stream instruction sequence.
    ///
    /// The complete sequence is validated before any accounting state or caller-owned backing
    /// storage is changed. On an application failure, earlier successful instructions remain
    /// committed, the failing instruction remains atomic under [`Self::apply`], and later
    /// instructions are not attempted.
    pub fn apply_sequence(
        &mut self,
        bytes: &[u8],
        encoder_insert_count: u64,
    ) -> Result<(), QpackDecoderInstructionsApplyError> {
        let instructions = QpackDecoderInstructions::parse(bytes)
            .map_err(QpackDecoderInstructionsApplyError::Parse)?;
        let mut offset = 0usize;

        for instruction in instructions.iter() {
            let instruction = instruction.map_err(QpackDecoderInstructionsApplyError::Parse)?;
            self.apply(instruction, encoder_insert_count)
                .map_err(|error| QpackDecoderInstructionsApplyError::Apply { offset, error })?;
            offset += instruction.as_bytes().len();
        }

        Ok(())
    }

    fn remove_section(&mut self, section_index: usize) {
        let removed = self.sections[section_index];
        let reference_end = removed.reference_start + removed.reference_len;
        self.references
            .copy_within(reference_end..self.reference_len, removed.reference_start);
        for section in &mut self.sections[section_index + 1..self.section_len] {
            section.reference_start -= removed.reference_len;
        }
        self.sections
            .copy_within(section_index + 1..self.section_len, section_index);

        self.section_len -= 1;
        self.reference_len -= removed.reference_len;
        self.sections[self.section_len] = QpackEncoderOutstandingSection::EMPTY;
        self.references[self.reference_len..self.reference_len + removed.reference_len].fill(0);
    }

    /// Returns whether an entry may be evicted without invalidating outstanding references.
    pub fn is_evictable(&self, absolute_index: u64) -> bool {
        self.known_received_count > absolute_index
            && !self.references[..self.reference_len].contains(&absolute_index)
    }
}
