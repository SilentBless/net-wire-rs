use net_wire::http3::{
    Http3ErrorCode, Http3Frame, Http3FrameBuildError, Http3FrameBuilder, Http3FrameMut,
    Http3FrameParseError, Http3FrameType, Http3PushId, Http3SettingId, Http3StreamId,
    Http3StreamType,
};
use net_wire::quic::{QuicVarIntBuildError, QuicVarIntParseError};

#[test]
fn raw_scalars_preserve_unknown_values() {
    let unknown = u64::MAX;

    assert_eq!(Http3FrameType::new(unknown).value(), unknown);
    assert_eq!(Http3SettingId::new(unknown).value(), unknown);
    assert_eq!(Http3StreamType::new(unknown).value(), unknown);
    assert_eq!(Http3StreamId::new(unknown).value(), unknown);
    assert_eq!(Http3PushId::new(unknown).value(), unknown);
    assert_eq!(Http3ErrorCode::new(unknown).value(), unknown);

    assert_eq!(Http3FrameType::SETTINGS.value(), 0x04);
    assert_eq!(Http3SettingId::MAX_FIELD_SECTION_SIZE.value(), 0x06);
    assert_eq!(Http3StreamType::QPACK_ENCODER.value(), 0x02);
    assert_eq!(Http3ErrorCode::QPACK_DECODER_STREAM_ERROR.value(), 0x202);
}

#[test]
fn raw_frame_parses_exact_noncanonical_varints_and_excludes_suffix() {
    let wire = [0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad, 0xfa];
    let frame = Http3Frame::parse(&wire, 2).unwrap();

    assert_eq!(frame.frame_type(), Http3FrameType::new(0x21));
    assert_eq!(frame.frame_type_varint().as_bytes(), &[0x40, 0x21]);
    assert_eq!(
        frame.payload_length_varint().as_bytes(),
        &[0x80, 0x00, 0x00, 0x02]
    );
    assert_eq!(frame.payload(), &[0xde, 0xad]);
    assert_eq!(frame.as_bytes(), &wire[..8]);
    assert_eq!(&wire[frame.as_bytes().len()..], &[0xfa]);
}

#[test]
fn raw_frame_reports_exact_structural_errors() {
    assert_eq!(
        Http3Frame::parse(&[], 0),
        Err(Http3FrameParseError::TypeVarInt(
            QuicVarIntParseError::Incomplete {
                required: 1,
                available: 0,
            }
        ))
    );
    assert_eq!(
        Http3Frame::parse(&[0x80, 0x00, 0x00], 0),
        Err(Http3FrameParseError::TypeVarInt(
            QuicVarIntParseError::Incomplete {
                required: 4,
                available: 3,
            }
        ))
    );
    assert_eq!(
        Http3Frame::parse(&[0x01], 0),
        Err(Http3FrameParseError::LengthVarInt(
            QuicVarIntParseError::Incomplete {
                required: 1,
                available: 0,
            }
        ))
    );
    assert_eq!(
        Http3Frame::parse(&[0x01, 0x40], 0),
        Err(Http3FrameParseError::LengthVarInt(
            QuicVarIntParseError::Incomplete {
                required: 2,
                available: 1,
            }
        ))
    );
    assert_eq!(
        Http3Frame::parse(&[0x01, 0x03], 2),
        Err(Http3FrameParseError::PayloadTooLarge {
            maximum: 2,
            actual: 3,
        })
    );
    assert_eq!(
        Http3Frame::parse(&[0x01, 0x03, 0xaa], 3),
        Err(Http3FrameParseError::IncompletePayload {
            required: 5,
            available: 3,
        })
    );
}

#[test]
fn mutable_raw_frame_bounds_one_prefix_and_preserves_its_suffix() {
    let mut wire = [0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad, 0xfa];
    {
        let mut frame = Http3FrameMut::parse(&mut wire, 2).unwrap();

        assert_eq!(frame.frame_type(), Http3FrameType::new(0x21));
        assert_eq!(frame.payload_length(), 2);
        assert_eq!(
            frame.as_bytes(),
            &[0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xde, 0xad]
        );
        frame.payload_mut()[1] = 0xbe;
        assert_eq!(frame.payload(), &[0xde, 0xbe]);
    }

    assert_eq!(wire, [0x40, 0x21, 0x80, 0x00, 0x00, 0x02, 0xde, 0xbe, 0xfa]);
}

#[test]
fn raw_builder_canonically_writes_a_destination_backed_frame() {
    let mut destination = [0xaa; 8];
    {
        let frame: Http3Frame<'_> =
            Http3FrameBuilder::new(&mut destination, Http3FrameType::new(0x40), &[0xde, 0xad])
                .build()
                .unwrap();

        assert!(frame.frame_type_varint().is_canonical());
        assert!(frame.payload_length_varint().is_canonical());
        assert_eq!(frame.frame_type_varint().as_bytes(), &[0x40, 0x40]);
        assert_eq!(frame.payload_length_varint().as_bytes(), &[0x02]);
        assert_eq!(frame.frame_type(), Http3FrameType::new(0x40));
        assert_eq!(frame.payload(), &[0xde, 0xad]);
        assert_eq!(frame.as_bytes(), &[0x40, 0x40, 0x02, 0xde, 0xad]);
    }
    assert_eq!(&destination[5..], &[0xaa, 0xaa, 0xaa]);
}

#[test]
fn raw_builder_failures_are_atomic() {
    let mut too_large_destination = [0xaa; 8];
    assert_eq!(
        Http3FrameBuilder::new(
            &mut too_large_destination,
            Http3FrameType::new(u64::MAX),
            &[],
        )
        .build(),
        Err(Http3FrameBuildError::TypeVarInt(
            QuicVarIntBuildError::ValueTooLarge { value: u64::MAX }
        ))
    );
    assert_eq!(too_large_destination, [0xaa; 8]);

    let mut short_destination = [0xaa; 4];
    assert_eq!(
        Http3FrameBuilder::new(
            &mut short_destination,
            Http3FrameType::new(0x40),
            &[0xde, 0xad],
        )
        .build(),
        Err(Http3FrameBuildError::BufferTooShort {
            required: 5,
            available: 4,
        })
    );
    assert_eq!(short_destination, [0xaa; 4]);
}
