use std::error::Error;
use std::iter::FusedIterator;

use net_wire::kcp::{KcpSegmentIter, KcpSegmentParseError, KcpSegments, KcpSegmentsParseError};

use super::fixtures::SEGMENT;

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
