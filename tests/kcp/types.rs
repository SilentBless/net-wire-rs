use net_wire::kcp::{
    KCP_SEGMENT_HEADER_LEN, KcpCommand, KcpConversationId, KcpFragment, KcpKnownCommand,
    KcpSequenceNumber, KcpTimestamp, KcpUnacknowledged,
};

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
