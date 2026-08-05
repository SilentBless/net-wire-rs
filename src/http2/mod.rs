//! Raw, allocation-free HTTP/2 wire views and caller-buffer construction.

mod builder;
mod error;
mod frame;
/// RFC 7541 HPACK wire primitives.
pub mod hpack;
mod sequence;
mod standard;
mod types;

pub use builder::{
    Http2ContinuationBuilder, Http2DataBuilder, Http2FrameBuilder, Http2GoawayBuilder,
    Http2HeadersBuilder, Http2PingBuilder, Http2PriorityFrameBuilder, Http2PushPromiseBuilder,
    Http2RstStreamBuilder, Http2SettingsBuilder, Http2WindowUpdateBuilder,
};
pub use error::{Http2BuildError, Http2ParseError, Http2StreamIdError};
pub use frame::{HTTP2_CLIENT_PREFACE, Http2ClientPreface, Http2Frame, Http2FrameMut};
pub use hpack::{
    HPACK_STATIC_TABLE_LEN, HpackBlockDecoder, HpackBlockEncoder, HpackDecodeError,
    HpackDecodeStep, HpackDecodedField, HpackDecodedFieldMode, HpackDecoderContext,
    HpackDynamicTable, HpackDynamicTableEntry, HpackDynamicTableError,
    HpackDynamicTableInsertResult, HpackDynamicTableSizeUpdate, HpackDynamicTableSizeUpdateBuilder,
    HpackEncodeError, HpackEncodeLiteralName, HpackEncoderContext, HpackHeaderFieldRef,
    HpackHuffmanDecodeError, HpackHuffmanDecoder, HpackHuffmanEncodeError, HpackHuffmanEncoder,
    HpackIndexedField, HpackIndexedFieldBuilder, HpackInteger, HpackIntegerBuildError,
    HpackIntegerBuilder, HpackIntegerParseError, HpackLiteralField, HpackLiteralFieldBuilder,
    HpackLiteralHuffman, HpackLiteralMode, HpackLiteralName, HpackLiteralValue,
    HpackRepresentation, HpackRepresentationBuildError, HpackRepresentationParseError,
    HpackStaticTable, HpackStringLiteral, HpackStringLiteralBuildError, HpackStringLiteralBuilder,
    HpackStringLiteralParseError,
};
pub use sequence::{
    Http2HeaderBlockFragment, Http2HeaderBlockSequence, Http2HeaderBlockSequenceError,
};
pub use standard::{
    Http2Continuation, Http2Data, Http2Goaway, Http2Headers, Http2Ping, Http2Priority,
    Http2PriorityFrame, Http2PushPromise, Http2RstStream, Http2Setting, Http2Settings,
    Http2SettingsIter, Http2WindowIncrement, Http2WindowUpdate,
};

pub use types::{Http2ErrorCode, Http2FrameType, Http2SettingId, Http2StreamId};
