use net_wire::qpack::{
    QpackBlockedStream, QpackBlockedStreams, QpackBlockedStreamsError, QpackDynamicTable,
    QpackFieldSectionDecodeOutcome, QpackFieldSectionDecoder, QpackFieldSectionOutput,
};

#[test]
fn qpack_blocked_streams_limits_storage_are_exact() {
    let blocked = |encoded: &[u8]| {
        let mut storage = [];
        let mut entries = [];
        let table = QpackDynamicTable::new(&mut storage, &mut entries);
        let mut bytes = [];
        let mut fields = [];
        let mut output = QpackFieldSectionOutput::new(&mut bytes, &mut fields);
        match QpackFieldSectionDecoder::new(128)
            .decode(encoded, &table, &mut output)
            .expect("blocked prefix")
        {
            QpackFieldSectionDecodeOutcome::Blocked(blocked) => blocked,
            QpackFieldSectionDecodeOutcome::Decoded(_) => panic!("blocked prefix"),
        }
    };
    let blocked_one = blocked(&[2, 0]);
    assert_eq!(blocked_one.required_insert_count(), 1);

    let mut records = [QpackBlockedStream::EMPTY; 2];
    {
        let mut seeded = QpackBlockedStreams::new(&mut records, 2).expect("storage fits maximum");
        assert_eq!(seeded.register(7, blocked_one), Ok(()));
        assert_eq!(seeded.register(8, blocked_one), Ok(()));
    }
    let before = records;
    let error = match QpackBlockedStreams::new(&mut records, 3) {
        Err(error) => error,
        Ok(_) => panic!("maximum exceeds storage"),
    };
    assert_eq!(
        error,
        QpackBlockedStreamsError::MaximumBlockedStreamsExceedsStorage {
            maximum: 3,
            storage_capacity: 2,
        }
    );
    assert!(error.is_provisioning_error());
    assert!(!error.is_decompression_failed());
    assert!(error.to_string().contains("3"));
    assert!(error.to_string().contains("2"));
    assert_eq!(records, before);

    #[cfg(target_pointer_width = "32")]
    {
        let before = records;
        let error = match QpackBlockedStreams::new(&mut records, u64::MAX) {
            Err(error) => error,
            Ok(_) => panic!("maximum is unrepresentable"),
        };
        assert_eq!(
            error,
            QpackBlockedStreamsError::MaximumBlockedStreamsExceedsStorage {
                maximum: u64::MAX,
                storage_capacity: 2,
            }
        );
        assert_eq!(records, before);
    }

    {
        let cleared = QpackBlockedStreams::new(&mut records, 2).expect("storage fits maximum");
        assert_eq!(
            (
                cleared.maximum_blocked_streams(),
                cleared.storage_capacity(),
                cleared.len(),
                cleared.is_empty(),
            ),
            (2, 2, 0, true)
        );
    }
    assert_eq!(records, [QpackBlockedStream::EMPTY; 2]);

    let mut no_records = [];
    let mut none = QpackBlockedStreams::new(&mut no_records, 0).expect("zero is valid");
    assert_eq!(
        (
            none.maximum_blocked_streams(),
            none.storage_capacity(),
            none.len(),
            none.is_empty(),
        ),
        (0, 0, 0, true)
    );
    let error = none.register(0, blocked_one).expect_err("maximum is zero");
    assert_eq!(
        error,
        QpackBlockedStreamsError::BlockedStreamsLimitExceeded { maximum: 0 }
    );
    assert!(error.is_decompression_failed());
    assert!(!error.is_provisioning_error());
    assert!(error.to_string().contains("0"));
}

#[test]
fn qpack_blocked_streams_distinct_count_aggregation_and_removal_are_exact() {
    let blocked = |encoded: &[u8]| {
        let mut storage = [];
        let mut entries = [];
        let table = QpackDynamicTable::new(&mut storage, &mut entries);
        let mut bytes = [];
        let mut fields = [];
        let mut output = QpackFieldSectionOutput::new(&mut bytes, &mut fields);
        match QpackFieldSectionDecoder::new(128)
            .decode(encoded, &table, &mut output)
            .expect("blocked prefix")
        {
            QpackFieldSectionDecodeOutcome::Blocked(blocked) => blocked,
            QpackFieldSectionDecodeOutcome::Decoded(_) => panic!("blocked prefix"),
        }
    };
    let one = blocked(&[2, 0]);
    let two = blocked(&[3, 0]);
    let three = blocked(&[4, 0]);
    assert_eq!(
        (
            one.required_insert_count(),
            two.required_insert_count(),
            three.required_insert_count(),
        ),
        (1, 2, 3)
    );

    let mut records = [QpackBlockedStream::EMPTY; 3];
    let mut streams = QpackBlockedStreams::new(&mut records, 2).expect("storage fits maximum");
    assert_eq!(streams.register(0, one), Ok(()));
    assert_eq!(streams.register(u64::MAX, two), Ok(()));
    assert_eq!((streams.len(), streams.is_empty()), (2, false));
    assert_eq!(streams.register(0, one), Ok(()));
    assert_eq!(streams.register(0, three), Ok(()));
    assert_eq!(streams.len(), 2);
    let mut ready = streams.ready(3);
    assert_eq!(
        ready
            .next()
            .map(|record| (record.stream_id(), record.required_insert_count())),
        Some((0, 3))
    );
    assert_eq!(
        ready
            .next()
            .map(|record| (record.stream_id(), record.required_insert_count())),
        Some((u64::MAX, 2))
    );
    assert_eq!(ready.next(), None);
    assert!(streams.contains(0));
    assert!(streams.contains(u64::MAX));
    assert!(streams.is_blocked(0, 2));
    assert!(!streams.is_blocked(0, 3));
    assert!(streams.is_blocked(u64::MAX, 1));
    assert!(!streams.is_blocked(u64::MAX, 2));

    let before = streams.len();
    let error = streams.register(9, one).expect_err("distinct maximum");
    assert_eq!(
        error,
        QpackBlockedStreamsError::BlockedStreamsLimitExceeded { maximum: 2 }
    );
    assert!(error.is_decompression_failed());
    assert_eq!(streams.len(), before);
    let mut ready = streams.ready(3);
    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(0));
    assert_eq!(
        ready.next().map(QpackBlockedStream::stream_id),
        Some(u64::MAX)
    );
    assert_eq!(ready.next(), None);
    assert!(!streams.contains(9));
    assert!(!streams.is_blocked(9, 0));

    assert!(streams.remove(0));
    assert_eq!(streams.len(), 1);
    assert!(!streams.contains(0));
    assert!(!streams.remove(0));
    assert_eq!(streams.len(), 1);
    assert_eq!(streams.register(5, one), Ok(()));
    let mut ready = streams.ready(3);
    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(5));
    assert_eq!(
        ready.next().map(QpackBlockedStream::stream_id),
        Some(u64::MAX)
    );
    assert_eq!(ready.next(), None);
}

#[test]
fn qpack_blocked_streams_ready_iteration_is_ordered_fused_and_non_mutating() {
    fn assert_fused<I: core::iter::FusedIterator>(_iterator: &I) {}

    let blocked = |encoded: &[u8]| {
        let mut storage = [];
        let mut entries = [];
        let table = QpackDynamicTable::new(&mut storage, &mut entries);
        let mut bytes = [];
        let mut fields = [];
        let mut output = QpackFieldSectionOutput::new(&mut bytes, &mut fields);
        match QpackFieldSectionDecoder::new(128)
            .decode(encoded, &table, &mut output)
            .expect("blocked prefix")
        {
            QpackFieldSectionDecodeOutcome::Blocked(blocked) => blocked,
            QpackFieldSectionDecodeOutcome::Decoded(_) => panic!("blocked prefix"),
        }
    };
    let one = blocked(&[2, 0]);
    let two = blocked(&[3, 0]);
    let three = blocked(&[4, 0]);
    let four = blocked(&[5, 0]);

    let mut records = [QpackBlockedStream::EMPTY; 4];
    let mut streams = QpackBlockedStreams::new(&mut records, 4).expect("storage fits maximum");
    assert_eq!(streams.register(10, three), Ok(()));
    assert_eq!(streams.register(20, one), Ok(()));
    assert_eq!(streams.register(30, four), Ok(()));
    assert!(streams.remove(20));
    assert_eq!(streams.register(40, two), Ok(()));

    let mut ready = streams.ready(2);
    assert_fused(&ready);
    let (lower, upper) = ready.size_hint();
    assert!(lower <= 1);
    if let Some(upper) = upper {
        assert!(upper >= 1);
    }
    assert_eq!(
        ready
            .next()
            .map(|record| (record.stream_id(), record.required_insert_count())),
        Some((40, 2))
    );
    assert_eq!(ready.next(), None);
    assert_eq!(ready.next(), None);
    let mut ready = streams.ready(3);
    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(10));

    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(40));
    assert_eq!(ready.next(), None);
    let mut ready = streams.ready(4);
    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(10));
    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(40));
    assert_eq!(ready.next().map(QpackBlockedStream::stream_id), Some(30));
    assert_eq!(ready.next(), None);
    assert_eq!(streams.len(), 3);
    for stream_id in [10, 30, 40] {
        assert!(streams.contains(stream_id));
    }

    let copied = {
        let mut ready = streams.ready(3);
        ready.next().expect("ready record")
    };
    assert_eq!(
        (copied.stream_id(), copied.required_insert_count()),
        (10, 3)
    );
    assert!(streams.remove(copied.stream_id()));
    assert_eq!(streams.len(), 2);
    assert!(!streams.contains(10));
}
