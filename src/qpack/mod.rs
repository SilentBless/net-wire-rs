//! RFC 9204 QPACK primitives.

mod blocked_streams;
mod decoder_instruction;
mod decoder_state;
mod dynamic_table;
mod encoder_instruction;
mod encoder_state;
mod encoder_stream;
mod field_line;
mod field_section_context;
mod field_section_decoder;
mod field_section_encoder;
mod field_section_prefix;
mod huffman;
mod integer;
mod static_table;
mod string;

pub use blocked_streams::{
    QpackBlockedStream, QpackBlockedStreams, QpackBlockedStreamsError, QpackReadyBlockedStreamIter,
};
pub use decoder_instruction::{
    QpackDecoderInstruction, QpackDecoderInstructionBuildError, QpackDecoderInstructionIter,
    QpackDecoderInstructionParseError, QpackDecoderInstructions,
    QpackDecoderInstructionsParseError, QpackInsertCountIncrement,
    QpackInsertCountIncrementBuilder, QpackSectionAcknowledgment,
    QpackSectionAcknowledgmentBuilder, QpackStreamCancellation, QpackStreamCancellationBuilder,
};
pub use decoder_state::{QpackDecoderFeedbackError, QpackDecoderState};
pub use dynamic_table::{QpackDynamicTable, QpackDynamicTableEntry, QpackDynamicTableError};
pub use encoder_instruction::{
    QpackDuplicate, QpackDuplicateBuilder, QpackEncoderInstruction,
    QpackEncoderInstructionBuildError, QpackEncoderInstructionIter,
    QpackEncoderInstructionParseError, QpackEncoderInstructions,
    QpackEncoderInstructionsParseError, QpackInsertWithLiteralName,
    QpackInsertWithLiteralNameBuilder, QpackInsertWithNameReference,
    QpackInsertWithNameReferenceBuilder, QpackSetDynamicTableCapacity,
    QpackSetDynamicTableCapacityBuilder,
};
pub use encoder_state::{
    QpackDecoderInstructionApplyError, QpackDecoderInstructionsApplyError,
    QpackEncoderOutstandingSection, QpackEncoderState, QpackEncoderStateError,
};
pub use encoder_stream::{
    QpackEncoderInstructionApplier, QpackEncoderInstructionApplyError,
    QpackEncoderInstructionApplyOutcome, QpackEncoderInstructionsApplyError,
};
pub use field_line::{
    QpackFieldLine, QpackFieldLineBuildError, QpackFieldLineIter, QpackFieldLineParseError,
    QpackFieldLines, QpackFieldLinesParseError, QpackIndexedFieldLine,
    QpackIndexedFieldLineBuilder, QpackIndexedPostBaseFieldLine,
    QpackIndexedPostBaseFieldLineBuilder, QpackLiteralNameFieldLine,
    QpackLiteralNameFieldLineBuilder, QpackLiteralNameReferenceFieldLine,
    QpackLiteralNameReferenceFieldLineBuilder, QpackLiteralPostBaseNameReferenceFieldLine,
    QpackLiteralPostBaseNameReferenceFieldLineBuilder,
};
pub use field_section_context::{QpackFieldSectionContext, QpackFieldSectionContextError};
pub use field_section_decoder::{
    QpackDecodedFieldEntry, QpackDecodedFieldIter, QpackDecodedFieldRef, QpackDecodedFieldSection,
    QpackFieldSectionBlocked, QpackFieldSectionDecodeError, QpackFieldSectionDecodeOutcome,
    QpackFieldSectionDecoder, QpackFieldSectionOutput,
};
pub use field_section_encoder::{
    QpackEncodedFieldSection, QpackFieldPlan, QpackFieldSectionBase,
    QpackFieldSectionEncodeBuffers, QpackFieldSectionEncodeError, QpackFieldSectionEncoder,
    QpackFieldSectionPlanError, QpackFieldSectionPlanSlot,
};
pub use field_section_prefix::{
    QpackFieldSectionPrefix, QpackFieldSectionPrefixBuildError, QpackFieldSectionPrefixBuilder,
    QpackFieldSectionPrefixParseError,
};
pub use huffman::{
    QpackHuffmanDecodeError, QpackHuffmanDecoder, QpackHuffmanEncodeError, QpackHuffmanEncoder,
};
pub use integer::{
    QPACK_INTEGER_MAX, QpackInteger, QpackIntegerBuildError, QpackIntegerBuilder,
    QpackIntegerParseError,
};
pub use static_table::{QPACK_STATIC_TABLE_LEN, QpackHeaderFieldRef, QpackStaticTable};
pub use string::{
    QpackStringLiteral, QpackStringLiteralBuildError, QpackStringLiteralBuilder,
    QpackStringLiteralParseError,
};
