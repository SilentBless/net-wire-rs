use std::error::Error;
use std::iter::FusedIterator;

use net_wire::kcp::{
    KCP_SEGMENT_HEADER_LEN, KcpCommand, KcpConversationId, KcpFragment, KcpKnownCommand,
    KcpSegment, KcpSegmentBuildError, KcpSegmentBuilder, KcpSegmentIter, KcpSegmentMut,
    KcpSegmentParseError, KcpSegments, KcpSegmentsParseError, KcpSequenceNumber, KcpTimestamp,
    KcpUnacknowledged,
};

const SEGMENT: [u8; 27] = [
    0x44, 0x33, 0x22, 0x11, 0x51, 0x02, 0x66, 0x55, 0xaa, 0x99, 0x88, 0x77, 0xee, 0xdd, 0xcc, 0xbb,
    0x67, 0x45, 0x23, 0x01, 0x03, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe,
];

#[test]
fn canonical_namespace_and_scalars_preserve_wire_values() {
    let _: net_wire::kcp::KcpConversationId = KcpConversationId::new(1);
    assert_eq!(KCP_SEGMENT_HEADER_LEN, 24);

    assert_eq!(KcpConversationId::new(u32::MAX).raw(), u32::MAX);
    assert_eq!(KcpFragment::new(u8::MAX).raw(), u8::MAX);
    assert!(!KcpFragment::new(u8::MAX).is_final());
    assert!(KcpFragment::new(0).is_final());
    assert_eq!(KcpTimestamp::new(u32::MAX).raw(), u32::MAX);
    assert_eq!(KcpSequenceNumber::new(u32::MAX).raw(), u32::MAX);
    assert_eq!(KcpUnacknowledged::new(u32::MAX).raw(), u32::MAX);
    assert_eq!(
        KcpUnacknowledged::new(u32::MAX).into_sequence_number(),
        KcpSequenceNumber::new(u32::MAX)
    );

    for (known, command) in [
        (KcpKnownCommand::Push, KcpCommand::PUSH),
        (KcpKnownCommand::Ack, KcpCommand::ACK),
        (KcpKnownCommand::Wask, KcpCommand::WASK),
        (KcpKnownCommand::Wins, KcpCommand::WINS),
    ] {
        assert_eq!(known.raw(), command.raw());
        assert_eq!(known.command(), command);
        assert_eq!(KcpKnownCommand::from_raw(command.raw()), Some(known));
        assert_eq!(command.known(), Some(known));
    }
    let unknown = KcpCommand::new(0xff);
    assert_eq!(unknown.raw(), 0xff);
    assert_eq!(unknown.known(), None);
    assert_eq!(KcpKnownCommand::from_raw(0xff), None);
}

#[test]
fn timestamp_and_sequence_use_signed_wrapping_order() {
    let timestamp = KcpTimestamp::new(0);
    let timestamp_previous = KcpTimestamp::new(u32::MAX);
    assert_eq!(timestamp.distance_from(timestamp_previous), 1);
    assert!(timestamp.is_after(timestamp_previous));
    assert!(timestamp_previous.is_before(timestamp));
    let timestamp_half = KcpTimestamp::new(0x8000_0000);
    assert_eq!(timestamp_half.distance_from(KcpTimestamp::new(0)), i32::MIN);
    assert!(timestamp_half.is_before(KcpTimestamp::new(0)));

    let sequence = KcpSequenceNumber::new(0);
    let sequence_previous = KcpSequenceNumber::new(u32::MAX);
    assert_eq!(sequence.distance_from(sequence_previous), 1);
    assert!(sequence.is_after(sequence_previous));
    assert!(sequence_previous.is_before(sequence));
    let sequence_half = KcpSequenceNumber::new(0x8000_0000);
    assert_eq!(
        sequence_half.distance_from(KcpSequenceNumber::new(0)),
        i32::MIN
    );
    assert!(sequence_half.is_before(KcpSequenceNumber::new(0)));
}

#[test]
fn segment_parsing_preserves_exact_fields_and_suffix() {
    let bytes = [
        0x44, 0x33, 0x22, 0x11, 0x51, 0x02, 0x66, 0x55, 0xaa, 0x99, 0x88, 0x77, 0xee, 0xdd, 0xcc,
        0xbb, 0x67, 0x45, 0x23, 0x01, 0x03, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xca,
    ];
    let (segment, suffix) = KcpSegment::parse(&bytes).unwrap();
    assert_eq!(segment.as_bytes(), SEGMENT);
    assert_eq!(suffix, [0xef, 0xca]);
    assert_eq!(segment.conversation_id().raw(), 0x1122_3344);
    assert_eq!(segment.command(), KcpCommand::PUSH);
    assert_eq!(segment.fragment().raw(), 2);
    assert_eq!(segment.window_size(), 0x5566);
    assert_eq!(segment.timestamp().raw(), 0x7788_99aa);
    assert_eq!(segment.sequence_number().raw(), 0xbbcc_ddee);
    assert_eq!(segment.unacknowledged().raw(), 0x0123_4567);
    assert_eq!(segment.payload_length(), 3);
    assert_eq!(segment.payload(), [0xde, 0xad, 0xbe]);
}

#[test]
fn segment_accepts_zero_payload_and_raw_unknown_fields() {
    let zero = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0,
    ];
    let (segment, suffix) = KcpSegment::parse(&zero).unwrap();
    assert!(suffix.is_empty());
    assert_eq!(segment.conversation_id().raw(), u32::MAX);
    assert_eq!(segment.command().raw(), u8::MAX);
    assert_eq!(segment.command().known(), None);
    assert_eq!(segment.fragment().raw(), u8::MAX);
    assert_eq!(segment.window_size(), u16::MAX);
    assert_eq!(segment.timestamp().raw(), u32::MAX);
    assert_eq!(segment.sequence_number().raw(), u32::MAX);
    assert_eq!(segment.unacknowledged().raw(), u32::MAX);
    assert_eq!(segment.payload_length(), 0);
    assert!(segment.payload().is_empty());
}

#[test]
fn segment_reports_all_truncation_boundaries() {
    for available in 0..KCP_SEGMENT_HEADER_LEN {
        assert_eq!(
            KcpSegment::parse(&SEGMENT[..available]),
            Err(KcpSegmentParseError::HeaderTruncated {
                required: KCP_SEGMENT_HEADER_LEN,
                available
            })
        );
    }
    assert_eq!(
        KcpSegment::parse(&SEGMENT[..26]),
        Err(KcpSegmentParseError::PayloadTruncated {
            required: SEGMENT.len(),
            available: 26
        })
    );
    let error = KcpSegment::parse(&SEGMENT[..26]).unwrap_err();
    assert!(Error::source(&error).is_none());
}

#[test]
fn sequences_are_strict_and_iterate_valid_prefix_once() {
    assert_eq!(
        KcpSegments::parse(&[]),
        Err(KcpSegmentsParseError::EmptySequence)
    );

    let mut concatenated = [0; 54];
    concatenated[..27].copy_from_slice(&SEGMENT);
    concatenated[27..].copy_from_slice(&SEGMENT);
    let sequence = KcpSegments::parse(&concatenated).unwrap();
    assert_eq!(sequence.as_bytes(), concatenated);
    assert_eq!(
        sequence
            .iter()
            .map(|segment| segment.unwrap().payload())
            .collect::<Vec<_>>(),
        vec![&[0xde, 0xad, 0xbe][..], &[0xde, 0xad, 0xbe][..]]
    );

    let mut partial_header = [0; 32];
    partial_header[..27].copy_from_slice(&SEGMENT);
    let trailing_error = KcpSegments::parse(&partial_header).unwrap_err();
    assert_eq!(
        trailing_error,
        KcpSegmentsParseError::Segment {
            offset: 27,
            error: KcpSegmentParseError::HeaderTruncated {
                required: 24,
                available: 5
            }
        }
    );
    assert_eq!(
        Error::source(&trailing_error).unwrap().to_string(),
        "KCP segment header is truncated: need 24 bytes, have 5"
    );

    let mut late_payload = [0; 56];
    late_payload[..27].copy_from_slice(&SEGMENT);
    late_payload[27..51].copy_from_slice(&SEGMENT[..24]);
    late_payload[47..51].copy_from_slice(&6_u32.to_le_bytes());
    late_payload[51..].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xca]);
    let late_error = KcpSegments::parse(&late_payload[..53]).unwrap_err();
    assert_eq!(
        late_error,
        KcpSegmentsParseError::Segment {
            offset: 27,
            error: KcpSegmentParseError::PayloadTruncated {
                required: 30,
                available: 26
            }
        }
    );

    fn require_fused<I: FusedIterator>(_iterator: I) {}
    require_fused(KcpSegmentIter::new(&partial_header));
    let mut iterator = KcpSegmentIter::new(&partial_header);
    assert_eq!(iterator.next().unwrap().unwrap().as_bytes(), SEGMENT);
    assert_eq!(iterator.next(), Some(Err(trailing_error)));
    assert_eq!(iterator.next(), None);
    assert_eq!(iterator.next(), None);
}

#[test]
fn builder_uses_defaults_canonical_bytes_and_atomic_failures() {
    let mut defaults = [0; 24];
    let built = KcpSegmentBuilder::new(
        &mut defaults,
        KcpConversationId::new(7),
        KcpCommand::ACK,
        &[],
    )
    .build()
    .unwrap();
    assert_eq!(
        built.as_bytes(),
        [
            7, 0, 0, 0, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );

    let mut destination = [0xa5; 29];
    {
        let built = KcpSegmentBuilder::new(
            &mut destination,
            KcpConversationId::new(0x1122_3344),
            KcpCommand::PUSH,
            &[0xde, 0xad, 0xbe],
        )
        .fragment(KcpFragment::new(2))
        .window_size(0x5566)
        .timestamp(KcpTimestamp::new(0x7788_99aa))
        .sequence_number(KcpSequenceNumber::new(0xbbcc_ddee))
        .unacknowledged(KcpUnacknowledged::new(0x0123_4567))
        .build()
        .unwrap();
        assert_eq!(built.as_bytes(), SEGMENT);
    }
    assert_eq!(&destination[27..], [0xa5, 0xa5]);

    let mut too_short = [0xa5; 26];
    let before = too_short;
    assert_eq!(
        KcpSegmentBuilder::new(
            &mut too_short,
            KcpConversationId::new(1),
            KcpCommand::PUSH,
            &[0xde, 0xad, 0xbe]
        )
        .build(),
        Err(KcpSegmentBuildError::BufferTooShort {
            required: 27,
            available: 26
        })
    );
    assert_eq!(too_short, before);
    assert!(
        Error::source(&KcpSegmentBuildError::BufferTooShort {
            required: 27,
            available: 26
        })
        .is_none()
    );
}

#[test]
fn mutable_segment_updates_fields_and_payload_without_changing_boundary() {
    let mut bytes = [
        0x44, 0x33, 0x22, 0x11, 0x51, 0x02, 0x66, 0x55, 0xaa, 0x99, 0x88, 0x77, 0xee, 0xdd, 0xcc,
        0xbb, 0x67, 0x45, 0x23, 0x01, 0x03, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xca,
    ];
    let (mut segment, suffix) = KcpSegmentMut::parse(&mut bytes).unwrap();
    assert_eq!(suffix, [0xef, 0xca]);
    segment.set_conversation_id(KcpConversationId::new(1));
    segment.set_command(KcpCommand::ACK);
    segment.set_fragment(KcpFragment::new(0));
    segment.set_window_size(2);
    segment.set_timestamp(KcpTimestamp::new(3));
    segment.set_sequence_number(KcpSequenceNumber::new(4));
    segment.set_unacknowledged(KcpUnacknowledged::new(5));
    segment.payload_mut().copy_from_slice(&[0xbe, 0xef, 0xca]);
    assert_eq!(segment.payload_length(), 3);
    assert_eq!(segment.payload(), [0xbe, 0xef, 0xca]);
    assert_eq!(segment.as_bytes().len(), SEGMENT.len());
    assert_eq!(suffix, [0xef, 0xca]);
    assert_eq!(
        segment.as_bytes(),
        [
            1, 0, 0, 0, 82, 0, 2, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 3, 0, 0, 0, 0xbe, 0xef,
            0xca
        ]
    );
}

#[cfg(feature = "udp")]
#[test]
fn udp_adapter_validates_exact_complete_kcp_payloads() {
    use net_wire::udp::UdpDatagram;

    let datagram = [
        0, 1, 0, 2, 0, 35, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x51, 0x02, 0x66, 0x55, 0xaa, 0x99, 0x88,
        0x77, 0xee, 0xdd, 0xcc, 0xbb, 0x67, 0x45, 0x23, 0x01, 0x03, 0x00, 0x00, 0x00, 0xde, 0xad,
        0xbe,
    ];
    let datagram = UdpDatagram::parse(&datagram).unwrap();
    assert_eq!(datagram.kcp_segments().unwrap().as_bytes(), SEGMENT);

    let empty = UdpDatagram::parse(&[0, 1, 0, 2, 0, 8, 0, 0]).unwrap();
    assert_eq!(
        empty.kcp_segments(),
        Err(KcpSegmentsParseError::EmptySequence)
    );

    let malformed = [
        0, 1, 0, 2, 0, 40, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x51, 0x02, 0x66, 0x55, 0xaa, 0x99, 0x88,
        0x77, 0xee, 0xdd, 0xcc, 0xbb, 0x67, 0x45, 0x23, 0x01, 0x03, 0x00, 0x00, 0x00, 0xde, 0xad,
        0xbe, 0, 0, 0, 0, 0,
    ];
    let malformed = UdpDatagram::parse(&malformed).unwrap();
    assert_eq!(
        malformed.kcp_segments(),
        Err(KcpSegmentsParseError::Segment {
            offset: 27,
            error: KcpSegmentParseError::HeaderTruncated {
                required: 24,
                available: 5
            }
        })
    );
}
