use net_wire::qpack::{QpackDynamicTable, QpackDynamicTableEntry, QpackDynamicTableError};

#[test]
fn qpack_dynamic_table_capacity_and_empty_storage_boundaries_are_exact() {
    let mut storage = [0; 68];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 2];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.storage_capacity(), 95);
    assert_eq!(
        (
            table.capacity(),
            table.size(),
            table.len(),
            table.insert_count()
        ),
        (0, 0, 0, 0)
    );
    assert!(table.is_empty());
    assert_eq!(table.oldest_active_absolute(), None);
    assert_eq!(
        table.set_capacity(96, |_| true),
        Err(QpackDynamicTableError::CapacityExceedsStorage {
            requested: 96,
            capacity: 95
        })
    );
    assert_eq!(table.storage_capacity(), 95);
    assert_eq!(
        (
            table.capacity(),
            table.size(),
            table.len(),
            table.insert_count()
        ),
        (0, 0, 0, 0)
    );
    assert!(table.is_empty());
    assert_eq!(table.oldest_active_absolute(), None);
    assert_eq!(table.set_capacity(95, |_| true), Ok(()));
    assert_eq!(table.insert_count(), 0);

    let mut empty_storage = [];
    let mut empty_entries = [QpackDynamicTableEntry::EMPTY; 1];
    let mut empty_table = QpackDynamicTable::new(&mut empty_storage, &mut empty_entries);
    assert_eq!(empty_table.storage_capacity(), 32);
    assert_eq!(empty_table.set_capacity(32, |_| true), Ok(()));
    assert_eq!(empty_table.insert(b"", b"", |_| true), Ok(0));
    assert_eq!(
        empty_table
            .get_absolute(0)
            .map(|field| (field.name(), field.value())),
        Ok((b"" as &[u8], b"" as &[u8]))
    );

    let mut no_storage = [];
    let mut no_entries = [];
    let mut no_table = QpackDynamicTable::new(&mut no_storage, &mut no_entries);
    assert_eq!(no_table.storage_capacity(), 31);
    assert_eq!(no_table.set_capacity(31, |_| true), Ok(()));
    assert_eq!(
        no_table.set_capacity(32, |_| true),
        Err(QpackDynamicTableError::CapacityExceedsStorage {
            requested: 32,
            capacity: 31
        })
    );
}

#[test]
fn qpack_dynamic_table_insertion_eviction_and_absolute_ids_are_exact() {
    let mut storage = [0; 70];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 4];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.set_capacity(102, |_| true), Ok(()));
    assert_eq!(table.insert(b"a", b"1", |_| true), Ok(0));
    assert_eq!(table.insert(b"b", b"2", |_| true), Ok(1));
    assert_eq!(table.insert(b"c", b"3", |_| true), Ok(2));
    assert_eq!(
        (table.size(), table.len(), table.insert_count()),
        (102, 3, 3)
    );
    assert_eq!(
        table
            .get_absolute(0)
            .map(|field| (field.name(), field.value())),
        Ok((b"a" as &[u8], b"1" as &[u8]))
    );
    assert_eq!(
        table
            .get_absolute(1)
            .map(|field| (field.name(), field.value())),
        Ok((b"b" as &[u8], b"2" as &[u8]))
    );
    assert_eq!(
        table
            .get_absolute(2)
            .map(|field| (field.name(), field.value())),
        Ok((b"c" as &[u8], b"3" as &[u8]))
    );
    assert_eq!(
        table
            .get_encoder_relative(0)
            .map(|field| (field.name(), field.value())),
        Ok((b"c" as &[u8], b"3" as &[u8]))
    );
    assert_eq!(
        table
            .get_encoder_relative(1)
            .map(|field| (field.name(), field.value())),
        Ok((b"b" as &[u8], b"2" as &[u8]))
    );
    assert_eq!(
        table
            .get_encoder_relative(2)
            .map(|field| (field.name(), field.value())),
        Ok((b"a" as &[u8], b"1" as &[u8]))
    );
    let mut evicted = [0; 3];
    let mut evicted_len = 0;
    assert_eq!(
        table.set_capacity(34, |absolute| {
            evicted[evicted_len] = absolute;
            evicted_len += 1;
            true
        }),
        Ok(())
    );
    assert_eq!(evicted_len, 2);
    assert_eq!(&evicted[..evicted_len], &[0, 1]);
    assert_eq!(
        (table.size(), table.len(), table.insert_count()),
        (34, 1, 3)
    );
    assert_eq!(
        table
            .get_absolute(2)
            .map(|field| (field.name(), field.value())),
        Ok((b"c" as &[u8], b"3" as &[u8]))
    );
    for requested in [0, 1] {
        assert_eq!(
            table.get_absolute(requested),
            Err(QpackDynamicTableError::EvictedAbsoluteIndex {
                requested,
                oldest_available: 2
            })
        );
    }
    assert_eq!(table.set_capacity(0, |_| true), Ok(()));
    assert!(table.is_empty());
    assert_eq!(table.oldest_active_absolute(), None);
    assert_eq!(table.insert_count(), 3);
    assert_eq!(table.set_capacity(34, |_| true), Ok(()));
    assert_eq!(table.insert(b"d", b"4", |_| true), Ok(3));
}

#[test]
fn qpack_dynamic_table_mutation_failures_are_atomic() {
    let mut storage = [0; 36];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 2];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.set_capacity(68, |_| true), Ok(()));
    assert_eq!(table.insert(b"a", b"1", |_| true), Ok(0));
    assert_eq!(table.insert(b"b", b"2", |_| true), Ok(1));
    let before = (
        table.capacity(),
        table.size(),
        table.len(),
        table.insert_count(),
    );
    let mut insert_calls = 0;
    assert_eq!(
        table.insert(&[0; 37], b"", |_| {
            insert_calls += 1;
            true
        }),
        Err(QpackDynamicTableError::EntryLargerThanCapacity {
            entry_size: 69,
            capacity: 68
        })
    );
    assert_eq!(insert_calls, 0);
    assert_eq!(
        (
            table.capacity(),
            table.size(),
            table.len(),
            table.insert_count()
        ),
        before
    );
    assert_eq!(
        table
            .get_absolute(0)
            .map(|field| (field.name(), field.value())),
        Ok((b"a" as &[u8], b"1" as &[u8]))
    );
    assert_eq!(
        table
            .get_absolute(1)
            .map(|field| (field.name(), field.value())),
        Ok((b"b" as &[u8], b"2" as &[u8]))
    );
    assert_eq!(
        table.insert(b"c", b"3", |_| false),
        Err(QpackDynamicTableError::EvictionBlocked { absolute_index: 0 })
    );
    assert_eq!(
        (
            table.capacity(),
            table.size(),
            table.len(),
            table.insert_count()
        ),
        before
    );
    let mut evicted = [0; 2];
    let mut evicted_len = 0;
    assert_eq!(
        table.set_capacity(0, |absolute| {
            evicted[evicted_len] = absolute;
            evicted_len += 1;
            absolute == 0
        }),
        Err(QpackDynamicTableError::EvictionBlocked { absolute_index: 1 })
    );
    assert_eq!(evicted_len, 2);
    assert_eq!(&evicted[..evicted_len], &[0, 1]);
    assert_eq!(
        (
            table.capacity(),
            table.size(),
            table.len(),
            table.insert_count()
        ),
        before
    );
    assert_eq!(
        table
            .get_absolute(0)
            .map(|field| (field.name(), field.value())),
        Ok((b"a" as &[u8], b"1" as &[u8]))
    );
    assert_eq!(
        table
            .get_absolute(1)
            .map(|field| (field.name(), field.value())),
        Ok((b"b" as &[u8], b"2" as &[u8]))
    );
}

#[test]
fn qpack_dynamic_table_relative_post_base_errors_are_exact() {
    let mut storage = [0; 70];
    let mut entries = [QpackDynamicTableEntry::EMPTY; 3];
    let mut table = QpackDynamicTable::new(&mut storage, &mut entries);
    assert_eq!(table.set_capacity(102, |_| true), Ok(()));
    assert_eq!(table.insert(b"a", b"1", |_| true), Ok(0));
    assert_eq!(table.insert(b"b", b"2", |_| true), Ok(1));
    assert_eq!(table.insert(b"c", b"3", |_| true), Ok(2));
    assert_eq!(
        table
            .get_encoder_relative(0)
            .map(|field| (field.name(), field.value())),
        Ok((b"c" as &[u8], b"3" as &[u8]))
    );
    assert_eq!(
        table
            .get_encoder_relative(2)
            .map(|field| (field.name(), field.value())),
        Ok((b"a" as &[u8], b"1" as &[u8]))
    );
    assert_eq!(
        table.get_encoder_relative(3),
        Err(QpackDynamicTableError::EncoderRelativeIndexUnderflow {
            insert_count: 3,
            index: 3
        })
    );
    assert_eq!(
        table
            .get_field_relative(3, 2, 0)
            .map(|field| (field.name(), field.value())),
        Ok((b"b" as &[u8], b"2" as &[u8]))
    );
    assert_eq!(
        table
            .get_field_relative(3, 2, 1)
            .map(|field| (field.name(), field.value())),
        Ok((b"a" as &[u8], b"1" as &[u8]))
    );
    assert_eq!(
        table.get_field_relative(3, 0, 0),
        Err(QpackDynamicTableError::FieldRelativeIndexUnderflow { base: 0, index: 0 })
    );
    assert_eq!(
        table.get_field_relative(3, 4, 0),
        Err(
            QpackDynamicTableError::ReferenceAtOrAfterRequiredInsertCount {
                requested: 3,
                required_insert_count: 3
            }
        )
    );
    assert_eq!(
        table
            .get_post_base(3, 1, 0)
            .map(|field| (field.name(), field.value())),
        Ok((b"b" as &[u8], b"2" as &[u8]))
    );
    assert_eq!(
        table
            .get_post_base(3, 1, 1)
            .map(|field| (field.name(), field.value())),
        Ok((b"c" as &[u8], b"3" as &[u8]))
    );
    assert_eq!(
        table.get_post_base(3, 1, 2),
        Err(
            QpackDynamicTableError::ReferenceAtOrAfterRequiredInsertCount {
                requested: 3,
                required_insert_count: 3
            }
        )
    );
    assert_eq!(
        table.get_post_base(3, u64::MAX, 1),
        Err(QpackDynamicTableError::PostBaseIndexOverflow {
            base: u64::MAX,
            index: 1
        })
    );
    assert_eq!(
        table.get_absolute(3),
        Err(QpackDynamicTableError::FutureAbsoluteIndex {
            requested: 3,
            insert_count: 3
        })
    );
}
