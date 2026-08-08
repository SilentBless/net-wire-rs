//! RFC 9204 encoder- and decoder-stream instructions.

pub(crate) mod decoder;
mod encoder;

pub use decoder::{
    QpackDecoderInstruction, QpackDecoderInstructionBuildError, QpackDecoderInstructionIter,
    QpackDecoderInstructionParseError, QpackDecoderInstructions,
    QpackDecoderInstructionsParseError, QpackInsertCountIncrement,
    QpackInsertCountIncrementBuilder, QpackSectionAcknowledgment,
    QpackSectionAcknowledgmentBuilder, QpackStreamCancellation, QpackStreamCancellationBuilder,
};
pub use encoder::{
    QpackDuplicate, QpackDuplicateBuilder, QpackEncoderInstruction, QpackEncoderInstructionApplier,
    QpackEncoderInstructionApplyError, QpackEncoderInstructionApplyOutcome,
    QpackEncoderInstructionBuildError, QpackEncoderInstructionIter,
    QpackEncoderInstructionParseError, QpackEncoderInstructions,
    QpackEncoderInstructionsApplyError, QpackEncoderInstructionsParseError,
    QpackInsertWithLiteralName, QpackInsertWithLiteralNameBuilder, QpackInsertWithNameReference,
    QpackInsertWithNameReferenceBuilder, QpackSetDynamicTableCapacity,
    QpackSetDynamicTableCapacityBuilder,
};
