//! QPACK encoded field-section prefixes, context, and transactions.

mod context;
pub(crate) mod decode;
mod encode;
mod prefix;

pub use context::{QpackFieldSectionContext, QpackFieldSectionContextError};
pub use decode::{
    QpackDecodedFieldEntry, QpackDecodedFieldIter, QpackDecodedFieldRef, QpackDecodedFieldSection,
    QpackFieldSectionBlocked, QpackFieldSectionDecodeError, QpackFieldSectionDecodeOutcome,
    QpackFieldSectionDecoder, QpackFieldSectionOutput,
};
pub use encode::{
    QpackEncodedFieldSection, QpackFieldPlan, QpackFieldSectionBase,
    QpackFieldSectionEncodeBuffers, QpackFieldSectionEncodeError, QpackFieldSectionEncoder,
    QpackFieldSectionPlanError, QpackFieldSectionPlanSlot,
};

pub use prefix::{
    QpackFieldSectionPrefix, QpackFieldSectionPrefixBuildError, QpackFieldSectionPrefixBuilder,
    QpackFieldSectionPrefixParseError,
};
