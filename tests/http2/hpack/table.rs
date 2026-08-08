use net_wire::http2::hpack::{
    HPACK_STATIC_TABLE_LEN, HpackDynamicTable, HpackDynamicTableEntry, HpackDynamicTableError,
    HpackDynamicTableInsertResult, HpackHeaderFieldRef, HpackStaticTable,
};

#[test]
fn hpack_static_table_has_rfc_boundaries_and_complete_index_space() {
    assert_eq!(HpackStaticTable::len(), HPACK_STATIC_TABLE_LEN);
    assert_eq!(HpackStaticTable::len(), 61);
    assert!(!HpackStaticTable::is_empty());
    assert_eq!(HpackStaticTable::get(0), None);
    assert_eq!(
        HpackStaticTable::get(1),
        Some(HpackHeaderFieldRef::new(b":authority", b""))
    );
    assert_eq!(
        HpackStaticTable::get(61),
        Some(HpackHeaderFieldRef::new(b"www-authenticate", b""))
    );
    assert_eq!(HpackStaticTable::get(62), None);
    assert!((1..=HpackStaticTable::len()).all(|index| HpackStaticTable::get(index).is_some()));
}

#[test]
fn hpack_static_table_preserves_rfc_representative_ordering_and_empty_values() {
    for (index, expected) in [
        (2, HpackHeaderFieldRef::new(b":method", b"GET")),
        (3, HpackHeaderFieldRef::new(b":method", b"POST")),
        (4, HpackHeaderFieldRef::new(b":path", b"/")),
        (5, HpackHeaderFieldRef::new(b":path", b"/index.html")),
        (8, HpackHeaderFieldRef::new(b":status", b"200")),
        (14, HpackHeaderFieldRef::new(b":status", b"500")),
        (
            16,
            HpackHeaderFieldRef::new(b"accept-encoding", b"gzip, deflate"),
        ),
        (15, HpackHeaderFieldRef::new(b"accept-charset", b"")),
        (28, HpackHeaderFieldRef::new(b"content-length", b"")),
        (61, HpackHeaderFieldRef::new(b"www-authenticate", b"")),
    ] {
        assert_eq!(HpackStaticTable::get(index), Some(expected));
    }
}

#[test]
fn hpack_header_field_ref_is_copyable_and_byte_oriented() {
    let field = HpackHeaderFieldRef::new(&[0x80, 0xff], &[0, 0xfe]);
    let copied = field;
    assert_eq!(field, copied);
    assert_eq!(copied.name(), [0x80, 0xff]);
    assert_eq!(copied.value(), [0, 0xfe]);
}

#[test]
fn hpack_dynamic_table_capacity_is_proven_without_mutating_rejected_stores() {
    let mut no_bytes = [];
    let mut no_entries = [];
    let table = HpackDynamicTable::new(&mut no_bytes, &mut no_entries, 31).unwrap();
    assert_eq!(table.capacity(), 31);

    let mut bytes = [0xa5; 1];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 1];
    let before_bytes = bytes;
    let before_entries = entries;
    assert!(matches!(
        HpackDynamicTable::new(&mut bytes, &mut entries, 34),
        Err(HpackDynamicTableError::MaximumSizeExceedsCapacity {
            requested: 34,
            capacity: 33,
        })
    ));
    assert_eq!(bytes, before_bytes);
    assert_eq!(entries, before_entries);
}

#[test]
fn hpack_dynamic_table_copies_binary_fields_and_indexes_newest_first() {
    let mut bytes = [0; 36];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 68).unwrap();
    let mut name = [0xff];
    assert_eq!(
        table.insert(&name, &[0, 0x80]),
        Ok(HpackDynamicTableInsertResult::Inserted)
    );
    name[0] = 0;
    assert_eq!(name, [0]);
    assert_eq!(
        table.insert(&[], &[]),
        Ok(HpackDynamicTableInsertResult::Inserted)
    );
    assert_eq!(table.len(), 2);
    assert_eq!(table.size(), 67);
    assert_eq!(table.get(1), Some(HpackHeaderFieldRef::new(&[], &[])));
    assert_eq!(
        table.get(2),
        Some(HpackHeaderFieldRef::new(&[0xff], &[0, 0x80]))
    );
    assert_eq!(table.get(0), None);
    assert_eq!(table.get(3), None);
}

#[test]
fn hpack_dynamic_table_evicts_oldest_and_handles_oversized_entries() {
    let mut bytes = [0xcc; 36];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 68).unwrap();
    table.insert(b"a", b"1").unwrap();
    table.insert(b"b", b"2").unwrap();
    table.insert(b"c", b"3").unwrap();
    assert_eq!(table.get(1), Some(HpackHeaderFieldRef::new(b"c", b"3")));
    assert_eq!(table.get(2), Some(HpackHeaderFieldRef::new(b"b", b"2")));
    assert_eq!(table.get(3), None);
    assert_eq!(
        table.insert(&[0; 37], b""),
        Ok(HpackDynamicTableInsertResult::NotInsertedOversized)
    );
    assert!(table.is_empty());
    assert_eq!(table.get(1), None);
}

#[test]
fn hpack_dynamic_table_preserves_variable_length_entries_across_shift_and_eviction() {
    let mut bytes = [0; 96];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 4];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 128).unwrap();

    table.insert(b"a", b"111").unwrap();
    table.insert(b"bb", b"22").unwrap();
    table.insert(b"ccc", b"3").unwrap();
    table.insert(b"dddd", b"4444").unwrap();

    assert_eq!(table.size(), 112);
    assert_eq!(
        table.get(1),
        Some(HpackHeaderFieldRef::new(b"dddd", b"4444"))
    );
    assert_eq!(table.get(2), Some(HpackHeaderFieldRef::new(b"ccc", b"3")));
    assert_eq!(table.get(3), Some(HpackHeaderFieldRef::new(b"bb", b"22")));
    assert_eq!(table.get(4), None);

    table.set_maximum_size(76).unwrap();
    assert_eq!(table.size(), 76);
    assert_eq!(
        table.get(1),
        Some(HpackHeaderFieldRef::new(b"dddd", b"4444"))
    );
    assert_eq!(table.get(2), Some(HpackHeaderFieldRef::new(b"ccc", b"3")));
    assert_eq!(table.get(3), None);
}

#[test]
fn hpack_dynamic_table_resizes_and_rejects_excess_maximum_atomically() {
    let mut bytes = [0x5a; 36];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 2];
    let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 68).unwrap();
    table.insert(b"a", b"1").unwrap();
    table.insert(b"b", b"2").unwrap();
    table.set_maximum_size(34).unwrap();
    assert_eq!(table.len(), 1);
    assert_eq!(table.get(1), Some(HpackHeaderFieldRef::new(b"b", b"2")));
    table.set_maximum_size(68).unwrap();
    assert_eq!(table.maximum_size(), 68);
    let before_size = table.size();
    assert_eq!(
        table.set_maximum_size(69),
        Err(HpackDynamicTableError::MaximumSizeExceedsCapacity {
            requested: 69,
            capacity: 68,
        })
    );
    assert_eq!(table.maximum_size(), 68);
    assert_eq!(table.size(), before_size);
    assert_eq!(table.get(1), Some(HpackHeaderFieldRef::new(b"b", b"2")));
}

#[test]
fn hpack_dynamic_table_exact_maximum_and_clear_do_not_expose_stale_storage() {
    let mut bytes = [0xaa; 1];
    let mut entries = [HpackDynamicTableEntry::EMPTY; 1];
    {
        let mut table = HpackDynamicTable::new(&mut bytes, &mut entries, 33).unwrap();
        assert_eq!(
            table.insert(b"x", b""),
            Ok(HpackDynamicTableInsertResult::Inserted)
        );
        assert_eq!(table.size(), 33);
        table.clear();
        assert!(table.is_empty());
        assert_eq!(table.get(1), None);
    }
    assert_eq!(bytes[0], b'x');
}
