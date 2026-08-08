use net_wire::http3::{
    Http3PushId, Http3StreamType, Http3UniStreamBuildError, Http3UniStreamField,
    Http3UniStreamHeader, Http3UniStreamHeaderBuilder, Http3UniStreamKind,
    Http3UniStreamParseError,
};
use net_wire::quic::{QuicVarIntBuildError, QuicVarIntParseError};

#[test]
fn unidirectional_stream_header_control_is_available() {
    let header = Http3UniStreamHeader::parse(&[0]).unwrap();
    assert_eq!(header.kind(), Http3UniStreamKind::Control);
    let mut destination = [0; 1];
    let header = Http3UniStreamHeaderBuilder::new(&mut destination, Http3UniStreamKind::Control)
        .build()
        .unwrap();
    assert_eq!(header.as_bytes(), &[0]);
}

#[test]
fn unidirectional_stream_header_parses_all_kinds() {
    let cases = [
        (
            &[0x00][..],
            Http3UniStreamKind::Control,
            Http3StreamType::CONTROL,
            None,
        ),
        (
            &[0x01, 0x40, 0x2a],
            Http3UniStreamKind::Push(Http3PushId::new(42)),
            Http3StreamType::PUSH,
            Some(Http3PushId::new(42)),
        ),
        (
            &[0x02],
            Http3UniStreamKind::QpackEncoder,
            Http3StreamType::QPACK_ENCODER,
            None,
        ),
        (
            &[0x03],
            Http3UniStreamKind::QpackDecoder,
            Http3StreamType::QPACK_DECODER,
            None,
        ),
        (
            &[0x22],
            Http3UniStreamKind::Unknown(Http3StreamType::new(0x22)),
            Http3StreamType::new(0x22),
            None,
        ),
        (
            &[0x21],
            Http3UniStreamKind::Unknown(Http3StreamType::new(0x21)),
            Http3StreamType::new(0x21),
            None,
        ),
    ];
    for (wire, kind, stream_type, push_id) in cases {
        let header = Http3UniStreamHeader::parse(wire).unwrap();
        assert_eq!(header.kind(), kind);
        assert_eq!(header.stream_type(), stream_type);
        assert_eq!(header.push_id(), push_id);
    }
}

#[test]
fn unidirectional_stream_header_preserves_exact_varints_and_excludes_suffixes() {
    let control_wire = [0x40, 0x00, 0x80, 0x00, 0x00, 0x02];
    let control = Http3UniStreamHeader::parse(&control_wire).unwrap();
    assert_eq!(control.stream_type_varint().as_bytes(), &[0x40, 0x00]);
    assert_eq!(control.as_bytes(), &[0x40, 0x00]);
    assert_eq!(
        &control_wire[control.as_bytes().len()..],
        &[0x80, 0x00, 0x00, 0x02]
    );

    let push_wire = [0x40, 0x01, 0x80, 0x00, 0x00, 0x2a, 0xfa];
    let push = Http3UniStreamHeader::parse(&push_wire).unwrap();
    assert_eq!(push.stream_type_varint().as_bytes(), &[0x40, 0x01]);
    assert_eq!(
        push.push_id_varint().unwrap().as_bytes(),
        &[0x80, 0x00, 0x00, 0x2a]
    );
    assert_eq!(push.as_bytes(), &push_wire[..6]);
    assert_eq!(&push_wire[push.as_bytes().len()..], &[0xfa]);

    for wire in [&[0x02, 0x40, 0x01][..], &[0x21, 0x80, 0x00, 0x00, 0x02][..]] {
        let header = Http3UniStreamHeader::parse(wire).unwrap();
        assert_eq!(header.as_bytes(), &wire[..1]);
        assert_eq!(&wire[header.as_bytes().len()..], &wire[1..]);
    }
}

#[test]
fn unidirectional_stream_header_reports_exact_parse_errors() {
    let stream_type_errors = [(&[][..], 1, 0), (&[0x40][..], 2, 1)];
    for (wire, required, available) in stream_type_errors {
        assert_eq!(
            Http3UniStreamHeader::parse(wire),
            Err(Http3UniStreamParseError::VarInt {
                field: Http3UniStreamField::StreamType,
                offset: 0,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available
                },
            })
        );
    }
    let push_id_errors = [
        (&[0x01][..], 1, 0, 1),
        (&[0x01, 0x40][..], 2, 1, 1),
        (&[0x40, 0x01, 0x80, 0x00, 0x00][..], 4, 3, 2),
    ];
    for (wire, required, available, offset) in push_id_errors {
        assert_eq!(
            Http3UniStreamHeader::parse(wire),
            Err(Http3UniStreamParseError::VarInt {
                field: Http3UniStreamField::PushId,
                offset,
                error: QuicVarIntParseError::Incomplete {
                    required,
                    available
                },
            })
        );
    }
}

#[test]
fn unidirectional_stream_header_builder_writes_canonical_headers() {
    let mut control_destination = [0xaa; 2];
    let control =
        Http3UniStreamHeaderBuilder::new(&mut control_destination, Http3UniStreamKind::Control)
            .build()
            .unwrap();
    assert_eq!(control.kind(), Http3UniStreamKind::Control);
    assert_eq!(control.stream_type(), Http3StreamType::CONTROL);
    assert_eq!(control.stream_type_varint().as_bytes(), &[0]);
    assert_eq!(control.push_id(), None);
    assert_eq!(control.as_bytes(), &[0]);
    assert_eq!(&control_destination[1..], &[0xaa]);

    let mut push_destination = [0xaa; 4];
    let push = Http3UniStreamHeaderBuilder::new(
        &mut push_destination,
        Http3UniStreamKind::Push(Http3PushId::new(64)),
    )
    .build()
    .unwrap();
    assert_eq!(push.kind(), Http3UniStreamKind::Push(Http3PushId::new(64)));
    assert_eq!(push.stream_type_varint().as_bytes(), &[0x01]);
    assert_eq!(push.push_id_varint().unwrap().as_bytes(), &[0x40, 0x40]);
    assert_eq!(push.as_bytes(), &[0x01, 0x40, 0x40]);
    assert_eq!(&push_destination[3..], &[0xaa]);

    let cases = [
        (
            Http3UniStreamKind::QpackEncoder,
            Http3StreamType::QPACK_ENCODER,
            &[0x02][..],
        ),
        (
            Http3UniStreamKind::QpackDecoder,
            Http3StreamType::QPACK_DECODER,
            &[0x03][..],
        ),
        (
            Http3UniStreamKind::Unknown(Http3StreamType::new(0x40)),
            Http3StreamType::new(0x40),
            &[0x40, 0x40],
        ),
        (
            Http3UniStreamKind::Unknown(Http3StreamType::new(0x21)),
            Http3StreamType::new(0x21),
            &[0x21],
        ),
    ];
    for (kind, stream_type, expected) in cases {
        let mut destination = [0xaa; 3];
        let header = Http3UniStreamHeaderBuilder::new(&mut destination, kind)
            .build()
            .unwrap();
        assert_eq!(header.kind(), kind);
        assert_eq!(header.stream_type(), stream_type);
        assert_eq!(header.stream_type_varint().as_bytes(), expected);
        assert_eq!(header.push_id(), None);
        assert_eq!(header.as_bytes(), expected);
        assert_eq!(&destination[expected.len()..], &[0xaa; 3][expected.len()..]);
    }
}

#[test]
fn unidirectional_stream_header_builder_rejects_invalid_inputs_atomically() {
    for value in 0..=3 {
        let mut destination = [0xaa; 3];
        let stream_type = Http3StreamType::new(value);
        assert_eq!(
            Http3UniStreamHeaderBuilder::new(
                &mut destination,
                Http3UniStreamKind::Unknown(stream_type),
            )
            .build(),
            Err(Http3UniStreamBuildError::KnownTypeMarkedUnknown { stream_type })
        );
        assert_eq!(destination, [0xaa; 3]);
    }

    let mut stream_type_destination = [0xaa; 8];
    assert_eq!(
        Http3UniStreamHeaderBuilder::new(
            &mut stream_type_destination,
            Http3UniStreamKind::Unknown(Http3StreamType::new(u64::MAX)),
        )
        .build(),
        Err(Http3UniStreamBuildError::VarInt {
            field: Http3UniStreamField::StreamType,
            error: QuicVarIntBuildError::ValueTooLarge { value: u64::MAX },
        })
    );
    assert_eq!(stream_type_destination, [0xaa; 8]);

    let mut push_id_destination = [0xaa; 8];
    assert_eq!(
        Http3UniStreamHeaderBuilder::new(
            &mut push_id_destination,
            Http3UniStreamKind::Push(Http3PushId::new(u64::MAX)),
        )
        .build(),
        Err(Http3UniStreamBuildError::VarInt {
            field: Http3UniStreamField::PushId,
            error: QuicVarIntBuildError::ValueTooLarge { value: u64::MAX },
        })
    );
    assert_eq!(push_id_destination, [0xaa; 8]);

    let mut short_destination = [0xaa; 2];
    assert_eq!(
        Http3UniStreamHeaderBuilder::new(
            &mut short_destination,
            Http3UniStreamKind::Push(Http3PushId::new(64)),
        )
        .build(),
        Err(Http3UniStreamBuildError::BufferTooShort {
            required: 3,
            available: 2,
        })
    );
    assert_eq!(short_destination, [0xaa; 2]);
}
