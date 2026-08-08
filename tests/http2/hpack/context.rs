use net_wire::http2::hpack::{
    HpackDecoderContext, HpackDynamicTable, HpackDynamicTableEntry, HpackEncoderContext,
};

#[test]
fn hpack_contexts_preserve_pending_size_history_without_redundant_updates() {
    let mut encoder_bytes = [0; 128];
    let mut encoder_entries = [HpackDynamicTableEntry::EMPTY; 4];
    let encoder_table =
        HpackDynamicTable::new(&mut encoder_bytes, &mut encoder_entries, 64).unwrap();
    let mut encoder = HpackEncoderContext::new(encoder_table, 64).unwrap();
    assert_eq!(encoder.next_required_size_update(), None);
    encoder.set_allowed_maximum_size(64).unwrap();
    assert_eq!(encoder.next_required_size_update(), None);
    encoder.set_allowed_maximum_size(128).unwrap();
    assert_eq!(encoder.next_required_size_update(), Some(128));

    let mut decreasing_bytes = [0; 128];
    let mut decreasing_entries = [HpackDynamicTableEntry::EMPTY; 4];
    let decreasing_table =
        HpackDynamicTable::new(&mut decreasing_bytes, &mut decreasing_entries, 64).unwrap();
    let mut decreasing = HpackEncoderContext::new(decreasing_table, 64).unwrap();
    decreasing.set_allowed_maximum_size(48).unwrap();
    decreasing.set_allowed_maximum_size(40).unwrap();
    assert_eq!(decreasing.next_required_size_update(), Some(40));

    let mut history_bytes = [0; 128];
    let mut history_entries = [HpackDynamicTableEntry::EMPTY; 4];
    let history_table =
        HpackDynamicTable::new(&mut history_bytes, &mut history_entries, 64).unwrap();
    let mut history = HpackEncoderContext::new(history_table, 64).unwrap();
    history.set_allowed_maximum_size(32).unwrap();
    history.set_allowed_maximum_size(64).unwrap();
    assert_eq!(history.next_required_size_update(), Some(32));
    {
        let mut block = history.begin_block();
        let mut destination = [0xaa; 2];
        assert_eq!(
            block
                .encode_dynamic_table_size_update(&mut destination, 32)
                .unwrap(),
            [0x3f, 0x01]
        );
    }
    assert_eq!(history.next_required_size_update(), Some(64));

    let mut collapsed_bytes = [0; 128];
    let mut collapsed_entries = [HpackDynamicTableEntry::EMPTY; 4];
    let collapsed_table =
        HpackDynamicTable::new(&mut collapsed_bytes, &mut collapsed_entries, 64).unwrap();
    let mut collapsed = HpackEncoderContext::new(collapsed_table, 64).unwrap();
    collapsed.set_allowed_maximum_size(128).unwrap();
    collapsed.set_allowed_maximum_size(64).unwrap();
    assert_eq!(collapsed.next_required_size_update(), Some(64));

    let mut decoder_bytes = [0; 128];
    let mut decoder_entries = [HpackDynamicTableEntry::EMPTY; 4];
    let decoder_table =
        HpackDynamicTable::new(&mut decoder_bytes, &mut decoder_entries, 64).unwrap();
    let mut decoder = HpackDecoderContext::new(decoder_table, 64).unwrap();
    decoder.set_allowed_maximum_size(64).unwrap();
    assert_eq!(decoder.next_required_size_update(), None);
    decoder.set_allowed_maximum_size(128).unwrap();
    assert_eq!(decoder.next_required_size_update(), Some(128));
    decoder.set_allowed_maximum_size(64).unwrap();
    assert_eq!(decoder.next_required_size_update(), Some(64));
}
