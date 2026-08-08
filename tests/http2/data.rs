use net_wire::http2::{
    Http2BuildError, Http2ContinuationBuilder, Http2Data, Http2DataBuilder, Http2ParseError,
    Http2StreamId,
};

#[test]
fn typed_standard_builders_write_exact_payloads_and_preserve_suffixes() {
    let mut unpadded_destination = [0xaa; 16];
    let unpadded = Http2DataBuilder::new(
        &mut unpadded_destination,
        Http2StreamId::from_value(1).unwrap(),
        0x81,
        &[0xde, 0xad],
        None,
    )
    .build()
    .unwrap();
    assert_eq!(
        unpadded.as_bytes(),
        &[0, 0, 2, 0, 0x81, 0, 0, 0, 1, 0xde, 0xad]
    );
    assert_eq!(unpadded.data(), [0xde, 0xad]);
    assert_eq!(unpadded.pad_length(), None);
    assert!(unpadded_destination[11..].iter().all(|byte| *byte == 0xaa));

    let mut padded_zero_destination = [0xaa; 16];
    let padded_zero = Http2DataBuilder::new(
        &mut padded_zero_destination,
        Http2StreamId::from_value(3).unwrap(),
        0,
        &[],
        Some(0),
    )
    .build()
    .unwrap();
    assert_eq!(padded_zero.as_bytes(), &[0, 0, 1, 0, 0x08, 0, 0, 0, 3, 0]);
    assert_eq!(padded_zero.data(), []);
    assert_eq!(padded_zero.pad_length(), Some(0));
    assert!(
        padded_zero_destination[10..]
            .iter()
            .all(|byte| *byte == 0xaa)
    );

    let mut padded_destination = [0xaa; 20];
    let padded = Http2DataBuilder::new(
        &mut padded_destination,
        Http2StreamId::from_value(5).unwrap(),
        0x81,
        &[0xbe],
        Some(2),
    )
    .build()
    .unwrap();
    assert_eq!(
        padded.as_bytes(),
        &[0, 0, 4, 0, 0x89, 0, 0, 0, 5, 2, 0xbe, 0, 0]
    );
    assert_eq!(padded.data(), [0xbe]);
    assert_eq!(padded.padding(), [0, 0]);
    assert!(padded_destination[13..].iter().all(|byte| *byte == 0xaa));
}

#[test]
fn typed_standard_builders_fail_atomically() {
    let mut zero = [0xaa; 16];
    let before = zero;
    assert_eq!(
        Http2DataBuilder::new(
            &mut zero,
            Http2StreamId::from_value(0).unwrap(),
            0,
            &[],
            None
        )
        .build(),
        Err(Http2BuildError::ZeroStreamId)
    );
    assert_eq!(zero, before);

    let mut reserved = [0xaa; 16];
    let before = reserved;
    assert_eq!(
        Http2ContinuationBuilder::new(&mut reserved, Http2StreamId::new(0x8000_0001), 0, &[])
            .build(),
        Err(Http2BuildError::ReservedStreamId)
    );
    assert_eq!(reserved, before);

    let mut padded_flag = [0xaa; 16];
    let before = padded_flag;
    assert_eq!(
        Http2DataBuilder::new(
            &mut padded_flag,
            Http2StreamId::from_value(1).unwrap(),
            0x08,
            &[],
            None,
        )
        .build(),
        Err(Http2BuildError::DataPaddedFlagSet)
    );
    assert_eq!(padded_flag, before);

    let mut maximum = [0xaa; 16];
    let before = maximum;
    assert_eq!(
        Http2DataBuilder::new(
            &mut maximum,
            Http2StreamId::from_value(1).unwrap(),
            0,
            &[1, 2],
            Some(1),
        )
        .build_with_maximum(3),
        Err(Http2BuildError::PayloadTooLarge {
            maximum: 3,
            actual: 4,
        })
    );
    assert_eq!(maximum, before);

    let mut short = [0xaa; 11];
    let before = short;
    assert_eq!(
        Http2ContinuationBuilder::new(
            &mut short,
            Http2StreamId::from_value(1).unwrap(),
            0,
            &[1, 2, 3],
        )
        .build(),
        Err(Http2BuildError::BufferTooShort {
            required: 12,
            available: 11,
        })
    );
    assert_eq!(short, before);
}

#[test]
fn typed_data_exposes_unpadded_and_empty_padded_payloads() {
    let unpadded = [0, 0, 2, 0, 0x80, 0, 0, 0, 1, 0xde, 0xad];
    let data = Http2Data::parse(&unpadded, 2).unwrap();
    assert_eq!(data.frame().as_bytes(), unpadded);
    assert_eq!(data.as_bytes(), unpadded);
    assert_eq!(data.data(), [0xde, 0xad]);
    assert_eq!(data.padding(), []);
    assert_eq!(data.pad_length(), None);

    let padded_empty = [0, 0, 1, 0, 0x08, 0, 0, 0, 1, 0];
    let data = Http2Data::parse(&padded_empty, 1).unwrap();
    assert_eq!(data.data(), []);
    assert_eq!(data.padding(), []);
    assert_eq!(data.pad_length(), Some(0));
}

#[test]
fn typed_data_rejects_invalid_padding() {
    let wire = [0, 0, 1, 0, 0x08, 0, 0, 0, 1, 1];
    assert_eq!(
        Http2Data::parse(&wire, 1),
        Err(Http2ParseError::InvalidPadding {
            padding_length: 1,
            payload_length: 1,
        })
    );
}
