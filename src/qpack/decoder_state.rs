//! Caller-owned decoder feedback accounting for RFC 9204 section 4.4.
//!
//! The decoder chooses when to emit Insert Count Increments and may coalesce them;
//! a Section Acknowledgment can also imply progress. Successful output advances this
//! accounting, so callers must retain and publish its exact bytes in invocation order.

use core::fmt;

use super::{
    QPACK_INTEGER_MAX, QpackDecodedFieldSection, QpackDecoderInstructionBuildError,
    QpackInsertCountIncrement, QpackInsertCountIncrementBuilder, QpackSectionAcknowledgment,
    QpackSectionAcknowledgmentBuilder, QpackStreamCancellation, QpackStreamCancellationBuilder,
};

/// Caller-owned QPACK decoder feedback accounting.
///
/// This tracks the decoder-side Known Received Count already reported or implied to
/// the peer encoder. It owns no output queue, stream lifecycle state, blocked payloads,
/// transport buffering, or field decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackDecoderState {
    known_received_count: u64,
}

impl QpackDecoderState {
    /// Creates decoder feedback accounting with no reported received inserts.
    pub const fn new() -> Self {
        Self {
            known_received_count: 0,
        }
    }

    /// Returns the number of received inserts already reported or implied to the encoder.
    pub const fn known_received_count(&self) -> u64 {
        self.known_received_count
    }

    /// Builds a Section Acknowledgment for a successfully decoded dynamic field section.
    ///
    /// Acknowledgments are coupled to decoded dynamic-table references rather than a
    /// caller-supplied count. A section with no dynamic references needs no acknowledgment,
    /// even when its resolved Required Insert Count is nonzero. On success, callers must retain
    /// and publish the returned bytes in invocation order because the acknowledgment advances
    /// local accounting.
    pub fn acknowledge_field_section<'a>(
        &mut self,
        destination: &'a mut [u8],
        stream_id: u64,
        section: QpackDecodedFieldSection<'_>,
    ) -> Result<Option<QpackSectionAcknowledgment<'a>>, QpackDecoderFeedbackError> {
        if !section.contains_dynamic_references() {
            return Ok(None);
        }

        let required_insert_count = section.required_insert_count();
        let acknowledgment = QpackSectionAcknowledgmentBuilder::new(destination, stream_id)
            .build()
            .map_err(QpackDecoderFeedbackError::InstructionBuild)?;
        self.known_received_count = self.known_received_count.max(required_insert_count);
        Ok(Some(acknowledgment))
    }

    /// Builds a Stream Cancellation for the supplied stream lifecycle event.
    ///
    /// Stream tracking is caller and HTTP/3 lifecycle responsibility; this emits the
    /// supplied event without changing the Known Received Count.
    pub fn cancel_stream<'a>(
        &mut self,
        destination: &'a mut [u8],
        stream_id: u64,
    ) -> Result<QpackStreamCancellation<'a>, QpackDecoderFeedbackError> {
        QpackStreamCancellationBuilder::new(destination, stream_id)
            .build()
            .map_err(QpackDecoderFeedbackError::InstructionBuild)
    }

    /// Coalesces and builds one Insert Count Increment for received encoder inserts.
    ///
    /// RFC 9204 lets the decoder choose increment timing. At most `QPACK_INTEGER_MAX`
    /// pending inserts are emitted at once; callers can invoke this again for a larger
    /// pending delta. Successful output advances local accounting, so its returned bytes
    /// must be retained and published in invocation order.
    pub fn emit_insert_count_increment<'a>(
        &mut self,
        destination: &'a mut [u8],
        decoder_insert_count: u64,
    ) -> Result<Option<QpackInsertCountIncrement<'a>>, QpackDecoderFeedbackError> {
        if decoder_insert_count == self.known_received_count {
            return Ok(None);
        }
        if decoder_insert_count < self.known_received_count {
            return Err(QpackDecoderFeedbackError::InsertCountRegression {
                known_received_count: self.known_received_count,
                decoder_insert_count,
            });
        }

        let increment = core::cmp::min(
            decoder_insert_count - self.known_received_count,
            QPACK_INTEGER_MAX,
        );
        let advanced_count = self.known_received_count.checked_add(increment).ok_or(
            QpackDecoderFeedbackError::InsertCountAdvanceOverflow {
                known_received_count: self.known_received_count,
                increment,
            },
        )?;
        let instruction = QpackInsertCountIncrementBuilder::new(destination, increment)
            .build()
            .map_err(QpackDecoderFeedbackError::InstructionBuild)?;
        self.known_received_count = advanced_count;
        Ok(Some(instruction))
    }
}

impl Default for QpackDecoderState {
    fn default() -> Self {
        Self::new()
    }
}

/// Failure while emitting caller-owned QPACK decoder feedback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackDecoderFeedbackError {
    /// The supplied decoder insert count regressed below local accounting.
    InsertCountRegression {
        /// The decoder-side Known Received Count.
        known_received_count: u64,
        /// The supplied current decoder insert count.
        decoder_insert_count: u64,
    },
    /// Advancing local accounting would overflow `u64`.
    InsertCountAdvanceOverflow {
        /// The decoder-side Known Received Count.
        known_received_count: u64,
        /// The emitted Insert Count Increment.
        increment: u64,
    },
    /// A canonical decoder instruction could not be built.
    InstructionBuild(
        #[doc = "The nested local instruction build failure."] QpackDecoderInstructionBuildError,
    ),
}

impl QpackDecoderFeedbackError {
    /// Returns whether this failure is insufficient caller-owned output storage.
    pub const fn is_provisioning_error(self) -> bool {
        matches!(
            self,
            Self::InstructionBuild(QpackDecoderInstructionBuildError::BufferTooShort { .. })
        )
    }
}

impl fmt::Display for QpackDecoderFeedbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsertCountRegression {
                known_received_count,
                decoder_insert_count,
            } => write!(
                formatter,
                "decoder insert count {decoder_insert_count} regresses below Known Received Count {known_received_count}"
            ),
            Self::InsertCountAdvanceOverflow {
                known_received_count,
                increment,
            } => write!(
                formatter,
                "Known Received Count {known_received_count} cannot advance by {increment}"
            ),
            Self::InstructionBuild(error) => write!(
                formatter,
                "QPACK decoder feedback instruction cannot be built: {error}"
            ),
        }
    }
}

impl core::error::Error for QpackDecoderFeedbackError {}
