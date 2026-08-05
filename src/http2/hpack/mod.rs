//! HPACK wire primitives.

mod context;
mod decoder;
mod encoder;
mod huffman;
mod integer;
mod representation;
mod representation_builder;
mod string;
mod table;

pub use context::{HpackDecoderContext, HpackEncoderContext};
pub use decoder::{
    HpackBlockDecoder, HpackDecodeError, HpackDecodeStep, HpackDecodedField, HpackDecodedFieldMode,
};
pub use encoder::{
    HpackBlockEncoder, HpackEncodeError, HpackEncodeLiteralName, HpackLiteralHuffman,
};
pub use huffman::{
    HpackHuffmanDecodeError, HpackHuffmanDecoder, HpackHuffmanEncodeError, HpackHuffmanEncoder,
};
pub use integer::{
    HpackInteger, HpackIntegerBuildError, HpackIntegerBuilder, HpackIntegerParseError,
};
pub use representation::{
    HpackDynamicTableSizeUpdate, HpackIndexedField, HpackLiteralField, HpackLiteralMode,
    HpackRepresentation, HpackRepresentationParseError,
};
pub use representation_builder::{
    HpackDynamicTableSizeUpdateBuilder, HpackIndexedFieldBuilder, HpackLiteralFieldBuilder,
    HpackLiteralName, HpackLiteralValue, HpackRepresentationBuildError,
};
pub use string::{
    HpackStringLiteral, HpackStringLiteralBuildError, HpackStringLiteralBuilder,
    HpackStringLiteralParseError,
};
pub use table::{
    HPACK_STATIC_TABLE_LEN, HpackDynamicTable, HpackDynamicTableEntry, HpackDynamicTableError,
    HpackDynamicTableInsertResult, HpackHeaderFieldRef, HpackStaticTable,
};
