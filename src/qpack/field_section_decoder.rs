//! Transactional semantic decoding of one RFC 9204 encoded field section.

use core::{fmt, iter::FusedIterator};

use super::{
    QPACK_STATIC_TABLE_LEN, QpackDynamicTable, QpackDynamicTableError, QpackFieldLine,
    QpackFieldLines, QpackFieldLinesParseError, QpackFieldSectionContext,
    QpackFieldSectionContextError, QpackFieldSectionPrefix, QpackFieldSectionPrefixParseError,
    QpackHeaderFieldRef, QpackHuffmanDecodeError, QpackHuffmanDecoder, QpackStaticTable,
    QpackStringLiteral,
};

/// Metadata for one packed decoded field in [`QpackFieldSectionOutput`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackDecodedFieldEntry {
    offset: usize,
    name_len: usize,
    value_len: usize,
    never_indexed: bool,
}

impl QpackDecodedFieldEntry {
    /// An empty metadata entry suitable for caller-owned metadata storage.
    pub const EMPTY: Self = Self {
        offset: 0,
        name_len: 0,
        value_len: 0,
        never_indexed: false,
    };

    /// Returns whether the wire representation prohibited intermediary indexing.
    pub const fn never_indexed(self) -> bool {
        self.never_indexed
    }
}

/// Caller-owned storage for decoded QPACK field-section bytes and metadata.
pub struct QpackFieldSectionOutput<'bytes, 'fields> {
    bytes: &'bytes mut [u8],
    fields: &'fields mut [QpackDecodedFieldEntry],
    len: usize,
}

impl<'bytes, 'fields> QpackFieldSectionOutput<'bytes, 'fields> {
    /// Creates empty decoded field-section output backed by caller storage.
    pub fn new(bytes: &'bytes mut [u8], fields: &'fields mut [QpackDecodedFieldEntry]) -> Self {
        Self {
            bytes,
            fields,
            len: 0,
        }
    }

    /// Returns the byte-storage capacity.
    pub const fn byte_capacity(&self) -> usize {
        self.bytes.len()
    }

    /// Returns the field-metadata capacity.
    pub const fn field_capacity(&self) -> usize {
        self.fields.len()
    }

    /// Returns the number of committed decoded fields.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether no decoded fields are committed.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// One decoded QPACK field borrowed from committed output storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackDecodedFieldRef<'a> {
    name: &'a [u8],
    value: &'a [u8],
    never_indexed: bool,
}

impl<'a> QpackDecodedFieldRef<'a> {
    /// Returns the decoded field name.
    pub const fn name(self) -> &'a [u8] {
        self.name
    }

    /// Returns the decoded field value.
    pub const fn value(self) -> &'a [u8] {
        self.value
    }

    /// Returns whether the wire representation prohibited intermediary indexing.
    pub const fn never_indexed(self) -> bool {
        self.never_indexed
    }
}

/// A committed decoded QPACK field section borrowed from caller-owned output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackDecodedFieldSection<'a> {
    bytes: &'a [u8],
    fields: &'a [QpackDecodedFieldEntry],
    required_insert_count: u64,
    base: u64,
    contains_dynamic_references: bool,
}

impl<'a> QpackDecodedFieldSection<'a> {
    /// Returns the resolved Required Insert Count.
    pub const fn required_insert_count(self) -> u64 {
        self.required_insert_count
    }

    /// Returns the resolved Base.
    pub const fn base(self) -> u64 {
        self.base
    }

    /// Returns whether any decoded field-line representation referenced the dynamic table.
    pub const fn contains_dynamic_references(self) -> bool {
        self.contains_dynamic_references
    }

    /// Returns the number of decoded fields.
    pub const fn len(self) -> usize {
        self.fields.len()
    }

    /// Returns whether the section contains no fields.
    pub const fn is_empty(self) -> bool {
        self.fields.is_empty()
    }

    /// Returns one decoded field when its validated metadata remains in bounds.
    pub fn get(self, index: usize) -> Option<QpackDecodedFieldRef<'a>> {
        self.fields
            .get(index)
            .and_then(|entry| field_from_entry(self.bytes, *entry))
    }

    /// Iterates over decoded fields in wire order.
    pub const fn iter(self) -> QpackDecodedFieldIter<'a> {
        QpackDecodedFieldIter {
            bytes: self.bytes,
            fields: self.fields,
            index: 0,
        }
    }
}

/// An iterator over decoded QPACK fields in wire order.
#[derive(Clone, Copy, Debug)]
pub struct QpackDecodedFieldIter<'a> {
    bytes: &'a [u8],
    fields: &'a [QpackDecodedFieldEntry],
    index: usize,
}

impl<'a> Iterator for QpackDecodedFieldIter<'a> {
    type Item = QpackDecodedFieldRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = *self.fields.get(self.index)?;
        self.index = self.index.saturating_add(1);
        field_from_entry(self.bytes, entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.fields.len().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for QpackDecodedFieldIter<'_> {
    fn len(&self) -> usize {
        self.fields.len().saturating_sub(self.index)
    }
}

impl FusedIterator for QpackDecodedFieldIter<'_> {}

/// A field section whose Required Insert Count has not yet been received.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackFieldSectionBlocked {
    required_insert_count: u64,
    base: u64,
}

impl QpackFieldSectionBlocked {
    /// Returns the resolved Required Insert Count.
    pub const fn required_insert_count(self) -> u64 {
        self.required_insert_count
    }

    /// Returns the resolved Base.
    pub const fn base(self) -> u64 {
        self.base
    }
}

/// The outcome of decoding one complete QPACK field section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackFieldSectionDecodeOutcome<'a> {
    /// The section was decoded into caller-owned output.
    Decoded(QpackDecodedFieldSection<'a>),
    /// The section is blocked awaiting dynamic-table insertions.
    Blocked(QpackFieldSectionBlocked),
}

/// A failure to semantically decode one QPACK field section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QpackFieldSectionDecodeError {
    /// The field-section prefix is malformed.
    Prefix(QpackFieldSectionPrefixParseError),
    /// The field-section prefix cannot be resolved for this decoder context.
    Context(QpackFieldSectionContextError),
    /// The encoded field-line sequence is malformed.
    FieldLines(QpackFieldLinesParseError),
    /// A static-table index is outside RFC 9204 Appendix A.
    StaticIndexOutOfRange {
        /// The requested zero-based static index.
        index: u64,
    },
    /// A dynamic-table reference is invalid for this field section.
    DynamicReference(QpackDynamicTableError),
    /// A literal field name has invalid Huffman coding.
    LiteralNameHuffman(QpackHuffmanDecodeError),
    /// A field value has invalid Huffman coding.
    ValueHuffman(QpackHuffmanDecodeError),
    /// The caller byte output cannot contain the decoded section.
    OutputBytesTooShort {
        /// Bytes required.
        required: usize,
        /// Bytes available.
        available: usize,
    },
    /// The caller metadata output cannot contain the decoded section.
    OutputFieldsTooShort {
        /// Fields required.
        required: usize,
        /// Fields available.
        available: usize,
    },
    /// Counting packed output bytes or fields overflowed `usize`.
    OutputLengthOverflow,
}

impl QpackFieldSectionDecodeError {
    /// Returns whether this error represents QPACK decompression failure.
    pub const fn is_decompression_failed(self) -> bool {
        matches!(
            self,
            Self::Prefix(_)
                | Self::Context(_)
                | Self::FieldLines(_)
                | Self::StaticIndexOutOfRange { .. }
                | Self::DynamicReference(_)
                | Self::LiteralNameHuffman(_)
                | Self::ValueHuffman(_)
        )
    }

    /// Returns whether this error is solely insufficient caller output provisioning.
    pub const fn is_output_provisioning_error(self) -> bool {
        !self.is_decompression_failed()
    }
}

impl fmt::Display for QpackFieldSectionDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prefix(error) => write!(f, "invalid QPACK field-section prefix: {error}"),
            Self::Context(error) => write!(f, "invalid QPACK field-section context: {error}"),
            Self::FieldLines(error) => write!(f, "invalid QPACK field lines: {error}"),
            Self::StaticIndexOutOfRange { index } => {
                write!(f, "QPACK static index {index} is out of range")
            }
            Self::DynamicReference(error) => write!(f, "invalid QPACK dynamic reference: {error}"),
            Self::LiteralNameHuffman(error) => {
                write!(f, "invalid QPACK literal-name Huffman data: {error}")
            }
            Self::ValueHuffman(error) => write!(f, "invalid QPACK value Huffman data: {error}"),
            Self::OutputBytesTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK field-section output bytes are too short: need {required}, have {available}"
            ),
            Self::OutputFieldsTooShort {
                required,
                available,
            } => write!(
                f,
                "QPACK field-section output fields are too short: need {required}, have {available}"
            ),
            Self::OutputLengthOverflow => {
                f.write_str("QPACK field-section output length overflows usize")
            }
        }
    }
}

impl core::error::Error for QpackFieldSectionDecodeError {}

/// A QPACK field-section decoder configured with the locally advertised maximum table capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QpackFieldSectionDecoder {
    maximum_dynamic_table_capacity: u64,
}

impl QpackFieldSectionDecoder {
    /// Creates a decoder configured with the locally advertised maximum dynamic-table capacity.
    pub const fn new(maximum_dynamic_table_capacity: u64) -> Self {
        Self {
            maximum_dynamic_table_capacity,
        }
    }

    /// Returns the locally advertised maximum dynamic-table capacity.
    pub const fn maximum_dynamic_table_capacity(self) -> u64 {
        self.maximum_dynamic_table_capacity
    }

    /// Decodes one complete field-section payload into caller-owned output transactionally.
    pub fn decode<'output>(
        &self,
        encoded: &[u8],
        table: &QpackDynamicTable<'_, '_>,
        output: &'output mut QpackFieldSectionOutput<'_, '_>,
    ) -> Result<QpackFieldSectionDecodeOutcome<'output>, QpackFieldSectionDecodeError> {
        let prefix = QpackFieldSectionPrefix::parse(encoded)
            .map_err(QpackFieldSectionDecodeError::Prefix)?;
        let context = QpackFieldSectionContext::decode(
            prefix,
            table.insert_count(),
            self.maximum_dynamic_table_capacity,
        )
        .map_err(QpackFieldSectionDecodeError::Context)?;
        if context.required_insert_count() > table.insert_count() {
            return Ok(QpackFieldSectionDecodeOutcome::Blocked(
                QpackFieldSectionBlocked {
                    required_insert_count: context.required_insert_count(),
                    base: context.base(),
                },
            ));
        }

        let lines = QpackFieldLines::parse(&encoded[prefix.as_bytes().len()..])
            .map_err(QpackFieldSectionDecodeError::FieldLines)?;
        let required = preflight(lines, table, context)?;
        if output.fields.len() < required.fields {
            return Err(QpackFieldSectionDecodeError::OutputFieldsTooShort {
                required: required.fields,
                available: output.fields.len(),
            });
        }
        if output.bytes.len() < required.bytes {
            return Err(QpackFieldSectionDecodeError::OutputBytesTooShort {
                required: required.bytes,
                available: output.bytes.len(),
            });
        }

        // Revalidate immediately before the infallible, prevalidated commit pass. The encoded
        // bytes and table are immutably borrowed, so this establishes the facts used below.
        let verified = preflight(lines, table, context)?;
        if verified != required {
            return Err(QpackFieldSectionDecodeError::OutputLengthOverflow);
        }
        commit(
            lines,
            table,
            context,
            output,
            required.bytes,
            required.fields,
        )?;

        let bytes = &output.bytes[..required.bytes];
        let fields = &output.fields[..required.fields];
        Ok(QpackFieldSectionDecodeOutcome::Decoded(
            QpackDecodedFieldSection {
                bytes,
                fields,
                required_insert_count: context.required_insert_count(),
                base: context.base(),
                contains_dynamic_references: verified.contains_dynamic_references,
            },
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Preflight {
    bytes: usize,
    fields: usize,
    contains_dynamic_references: bool,
}

fn preflight(
    lines: QpackFieldLines<'_>,
    table: &QpackDynamicTable<'_, '_>,
    context: QpackFieldSectionContext,
) -> Result<Preflight, QpackFieldSectionDecodeError> {
    let mut bytes = 0usize;
    let mut fields = 0usize;
    let mut contains_dynamic_references = false;
    for line in lines.iter() {
        let line = match line {
            Ok(line) => line,
            // QpackFieldLines::parse validated this exact immutable sequence.
            Err(_) => return Err(QpackFieldSectionDecodeError::OutputLengthOverflow),
        };
        let (name, value, references_dynamic_table) = line_lengths(line, table, context)?;
        bytes = bytes
            .checked_add(name)
            .and_then(|length| length.checked_add(value))
            .ok_or(QpackFieldSectionDecodeError::OutputLengthOverflow)?;
        fields = fields
            .checked_add(1)
            .ok_or(QpackFieldSectionDecodeError::OutputLengthOverflow)?;
        contains_dynamic_references |= references_dynamic_table;
    }
    Ok(Preflight {
        bytes,
        fields,
        contains_dynamic_references,
    })
}

fn line_lengths(
    line: QpackFieldLine<'_>,
    table: &QpackDynamicTable<'_, '_>,
    context: QpackFieldSectionContext,
) -> Result<(usize, usize, bool), QpackFieldSectionDecodeError> {
    match line {
        QpackFieldLine::Indexed(line) => {
            let field = resolve_indexed(line.is_static(), line.index().value(), table, context)?;
            Ok((field.name().len(), field.value().len(), !line.is_static()))
        }
        QpackFieldLine::IndexedPostBase(line) => {
            let field = table
                .get_post_base(
                    context.required_insert_count(),
                    context.base(),
                    line.index().value(),
                )
                .map_err(QpackFieldSectionDecodeError::DynamicReference)?;
            Ok((field.name().len(), field.value().len(), true))
        }
        QpackFieldLine::LiteralNameReference(line) => {
            let name =
                resolve_indexed(line.is_static(), line.name_index().value(), table, context)?
                    .name();
            Ok((
                name.len(),
                literal_len(line.value(), false)?,
                !line.is_static(),
            ))
        }
        QpackFieldLine::LiteralPostBaseNameReference(line) => {
            let name = table
                .get_post_base(
                    context.required_insert_count(),
                    context.base(),
                    line.name_index().value(),
                )
                .map_err(QpackFieldSectionDecodeError::DynamicReference)?
                .name();
            Ok((name.len(), literal_len(line.value(), false)?, true))
        }
        QpackFieldLine::LiteralName(line) => Ok((
            literal_len(line.name(), true)?,
            literal_len(line.value(), false)?,
            false,
        )),
    }
}

fn resolve_indexed<'a>(
    is_static: bool,
    index: u64,
    table: &'a QpackDynamicTable<'_, '_>,
    context: QpackFieldSectionContext,
) -> Result<QpackHeaderFieldRef<'a>, QpackFieldSectionDecodeError> {
    if is_static {
        static_field(index)
    } else {
        table
            .get_field_relative(context.required_insert_count(), context.base(), index)
            .map_err(QpackFieldSectionDecodeError::DynamicReference)
    }
}

fn literal_len(
    literal: QpackStringLiteral<'_>,
    name: bool,
) -> Result<usize, QpackFieldSectionDecodeError> {
    if !literal.is_huffman() {
        return Ok(literal.encoded_payload().len());
    }
    QpackHuffmanDecoder::required_decoded_len(literal.encoded_payload()).map_err(|error| {
        if name {
            QpackFieldSectionDecodeError::LiteralNameHuffman(error)
        } else {
            QpackFieldSectionDecodeError::ValueHuffman(error)
        }
    })
}

fn static_field(index: u64) -> Result<QpackHeaderFieldRef<'static>, QpackFieldSectionDecodeError> {
    if index >= QPACK_STATIC_TABLE_LEN as u64 {
        return Err(QpackFieldSectionDecodeError::StaticIndexOutOfRange { index });
    }
    QpackStaticTable::get(index as usize)
        .ok_or(QpackFieldSectionDecodeError::StaticIndexOutOfRange { index })
}

fn commit(
    lines: QpackFieldLines<'_>,
    table: &QpackDynamicTable<'_, '_>,
    context: QpackFieldSectionContext,
    output: &mut QpackFieldSectionOutput<'_, '_>,
    required_bytes: usize,
    required_fields: usize,
) -> Result<(), QpackFieldSectionDecodeError> {
    let mut offset = 0usize;
    let mut field_index = 0usize;
    for line in lines.iter() {
        let line = match line {
            Ok(line) => line,
            Err(_) => return Err(QpackFieldSectionDecodeError::OutputLengthOverflow),
        };
        let entry = write_prevalidated_line(line, table, context, &mut output.bytes[offset..])?;
        output.fields[field_index] = QpackDecodedFieldEntry {
            offset,
            name_len: entry.name_len,
            value_len: entry.value_len,
            never_indexed: entry.never_indexed,
        };
        offset += entry.name_len + entry.value_len;
        field_index += 1;
    }
    if offset != required_bytes || field_index != required_fields {
        return Err(QpackFieldSectionDecodeError::OutputLengthOverflow);
    }
    output.len = required_fields;
    Ok(())
}

fn write_prevalidated_line(
    line: QpackFieldLine<'_>,
    table: &QpackDynamicTable<'_, '_>,
    context: QpackFieldSectionContext,
    destination: &mut [u8],
) -> Result<QpackDecodedFieldEntry, QpackFieldSectionDecodeError> {
    match line {
        QpackFieldLine::Indexed(line) => {
            let field = resolve_indexed(line.is_static(), line.index().value(), table, context)?;
            Ok(write_field(field, destination, false))
        }
        QpackFieldLine::IndexedPostBase(line) => {
            let field = table
                .get_post_base(
                    context.required_insert_count(),
                    context.base(),
                    line.index().value(),
                )
                .map_err(QpackFieldSectionDecodeError::DynamicReference)?;
            Ok(write_field(field, destination, false))
        }
        QpackFieldLine::LiteralNameReference(line) => {
            let name =
                resolve_indexed(line.is_static(), line.name_index().value(), table, context)?
                    .name();
            let value_len = literal_len(line.value(), false)?;
            Ok(write_name_and_literal(
                name,
                line.value(),
                value_len,
                line.is_never_indexed(),
                destination,
            ))
        }
        QpackFieldLine::LiteralPostBaseNameReference(line) => {
            let name = table
                .get_post_base(
                    context.required_insert_count(),
                    context.base(),
                    line.name_index().value(),
                )
                .map_err(QpackFieldSectionDecodeError::DynamicReference)?
                .name();
            let value_len = literal_len(line.value(), false)?;
            Ok(write_name_and_literal(
                name,
                line.value(),
                value_len,
                line.is_never_indexed(),
                destination,
            ))
        }
        QpackFieldLine::LiteralName(line) => {
            let name_len = literal_len(line.name(), true)?;
            let value_len = literal_len(line.value(), false)?;
            write_prevalidated_literal(line.name(), name_len, destination);
            write_prevalidated_literal(line.value(), value_len, &mut destination[name_len..]);
            Ok(QpackDecodedFieldEntry {
                offset: 0,
                name_len,
                value_len,
                never_indexed: line.is_never_indexed(),
            })
        }
    }
}

fn write_field(
    field: QpackHeaderFieldRef<'_>,
    destination: &mut [u8],
    never_indexed: bool,
) -> QpackDecodedFieldEntry {
    let name_len = field.name().len();
    let value_len = field.value().len();
    destination[..name_len].copy_from_slice(field.name());
    destination[name_len..name_len + value_len].copy_from_slice(field.value());
    QpackDecodedFieldEntry {
        offset: 0,
        name_len,
        value_len,
        never_indexed,
    }
}

fn write_name_and_literal(
    name: &[u8],
    value: QpackStringLiteral<'_>,
    value_len: usize,
    never_indexed: bool,
    destination: &mut [u8],
) -> QpackDecodedFieldEntry {
    destination[..name.len()].copy_from_slice(name);
    write_prevalidated_literal(value, value_len, &mut destination[name.len()..]);
    QpackDecodedFieldEntry {
        offset: 0,
        name_len: name.len(),
        value_len,
        never_indexed,
    }
}

fn write_prevalidated_literal(
    literal: QpackStringLiteral<'_>,
    decoded_len: usize,
    destination: &mut [u8],
) {
    if literal.is_huffman() {
        super::huffman::decode_prevalidated(
            literal.encoded_payload(),
            &mut destination[..decoded_len],
        );
    } else {
        destination[..decoded_len].copy_from_slice(literal.encoded_payload());
    }
}

fn field_from_entry<'a>(
    bytes: &'a [u8],
    entry: QpackDecodedFieldEntry,
) -> Option<QpackDecodedFieldRef<'a>> {
    let name_end = entry.offset.checked_add(entry.name_len)?;
    let value_end = name_end.checked_add(entry.value_len)?;
    Some(QpackDecodedFieldRef {
        name: bytes.get(entry.offset..name_end)?,
        value: bytes.get(name_end..value_end)?,
        never_indexed: entry.never_indexed,
    })
}
