use std::error::Error;

use net_wire::kcp::{
    KcpCommand, KcpConversationId, KcpFragment, KcpSegmentBuildError, KcpSegmentBuilder,
    KcpSequenceNumber, KcpTimestamp, KcpUnacknowledged,
};

use super::fixtures::SEGMENT;

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
