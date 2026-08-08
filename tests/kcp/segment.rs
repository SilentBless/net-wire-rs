use std::error::Error;

use net_wire::kcp::{
    KCP_SEGMENT_HEADER_LEN, KcpCommand, KcpConversationId, KcpFragment, KcpSegment, KcpSegmentMut,
    KcpSegmentParseError, KcpSequenceNumber, KcpTimestamp, KcpUnacknowledged,
};

use super::fixtures::SEGMENT;

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
