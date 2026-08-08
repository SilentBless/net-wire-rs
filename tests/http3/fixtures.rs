use net_wire::qpack::{
    QpackDecodedFieldEntry, QpackDecodedFieldSection, QpackDynamicTable,
    QpackFieldSectionDecodeOutcome, QpackFieldSectionDecoder, QpackFieldSectionOutput,
    QpackLiteralNameFieldLineBuilder,
};

pub(crate) type DecodedFieldSpec<'a> = (&'a [u8], &'a [u8], bool);

pub(crate) fn with_decoded_fields<R>(
    fields: &[DecodedFieldSpec<'_>],
    check: impl FnOnce(QpackDecodedFieldSection<'_>) -> R,
) -> R {
    let mut wire = [0_u8; 512];
    wire[..2].copy_from_slice(&[0, 0]);
    let mut wire_len = 2;
    for &(name, value, never_indexed) in fields {
        let line = QpackLiteralNameFieldLineBuilder::new(
            &mut wire[wire_len..],
            never_indexed,
            false,
            name,
            false,
            value,
        )
        .build()
        .unwrap();
        wire_len += line.as_bytes().len();
    }
    let mut storage = [];
    let mut entries = [];
    let table = QpackDynamicTable::new(&mut storage, &mut entries);
    let decoder = QpackFieldSectionDecoder::new(0);
    let mut bytes = [0_u8; 512];
    let mut metadata = [QpackDecodedFieldEntry::EMPTY; 16];
    let mut output = QpackFieldSectionOutput::new(&mut bytes, &mut metadata);
    let decoded = match decoder
        .decode(&wire[..wire_len], &table, &mut output)
        .unwrap()
    {
        QpackFieldSectionDecodeOutcome::Decoded(section) => section,
        QpackFieldSectionDecodeOutcome::Blocked(_) => panic!("literal field section is ready"),
    };
    check(decoded)
}
