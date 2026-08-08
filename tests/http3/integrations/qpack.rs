use net_wire::http3::{
    Http3ErrorCode, Http3Headers, Http3PushId, Http3PushPromise, Http3QpackFieldSectionError,
};
use net_wire::qpack::{
    QpackDecodedFieldEntry, QpackDynamicTable, QpackDynamicTableEntry,
    QpackFieldSectionDecodeError, QpackFieldSectionDecodeOutcome, QpackFieldSectionDecoder,
    QpackFieldSectionOutput, QpackFieldSectionPrefixParseError, QpackIntegerParseError,
};

#[test]
fn http3_qpack_field_section_handoff_decodes_headers_and_push_promise() {
    let root_error: Http3QpackFieldSectionError = Http3QpackFieldSectionError::OutputProvisioning(
        QpackFieldSectionDecodeError::OutputBytesTooShort {
            required: 1,
            available: 0,
        },
    );
    assert_eq!(Http3QpackFieldSectionError::error_code(root_error), None);
    let module_error: Http3QpackFieldSectionError =
        Http3QpackFieldSectionError::DecompressionFailed(
            QpackFieldSectionDecodeError::StaticIndexOutOfRange { index: 99 },
        );
    assert_eq!(
        Http3QpackFieldSectionError::error_code(module_error),
        Some(Http3ErrorCode::QPACK_DECOMPRESSION_FAILED)
    );

    let mut storage = [];
    let mut table_entries = [];
    let table = QpackDynamicTable::new(&mut storage, &mut table_entries);
    let decoder = QpackFieldSectionDecoder::new(128);

    let headers_wire = [0x01, 0x03, 0x00, 0x00, 0xc0];
    let headers = Http3Headers::parse(&headers_wire, 3).unwrap();
    let mut header_bytes = [0xaa; 10];
    let mut header_fields = [QpackDecodedFieldEntry::EMPTY; 1];
    {
        let mut output = QpackFieldSectionOutput::new(&mut header_bytes, &mut header_fields);
        let decoded = match headers
            .decode_field_section(&decoder, &table, &mut output)
            .unwrap()
        {
            QpackFieldSectionDecodeOutcome::Decoded(decoded) => decoded,
            QpackFieldSectionDecodeOutcome::Blocked(_) => panic!("static section is ready"),
        };
        assert_eq!((decoded.required_insert_count(), decoded.base()), (0, 0));
        assert_eq!(
            decoded.get(0).map(|field| (field.name(), field.value())),
            Some((b":authority" as &[u8], b"" as &[u8]))
        );
        assert_eq!(decoded.get(1), None);
    }
    assert_eq!(headers.as_bytes(), &headers_wire);
    assert_eq!(headers.encoded_field_section(), &[0x00, 0x00, 0xc0]);

    let promise_wire = [0x05, 0x04, 0x2a, 0x00, 0x00, 0xc0];
    let promise: Http3PushPromise<'_> = Http3PushPromise::parse(&promise_wire, 4).unwrap();
    let mut promise_bytes = [0xaa; 10];
    let mut promise_fields = [QpackDecodedFieldEntry::EMPTY; 1];
    {
        let mut output = QpackFieldSectionOutput::new(&mut promise_bytes, &mut promise_fields);
        let decoded = match promise
            .decode_field_section(&decoder, &table, &mut output)
            .unwrap()
        {
            QpackFieldSectionDecodeOutcome::Decoded(decoded) => decoded,
            QpackFieldSectionDecodeOutcome::Blocked(_) => panic!("push ID is not QPACK input"),
        };
        assert_eq!(
            decoded.get(0).map(|field| (field.name(), field.value())),
            Some((b":authority" as &[u8], b"" as &[u8]))
        );
    }
    assert_eq!(promise.push_id(), Http3PushId::new(42));
    assert_eq!(promise.as_bytes(), &promise_wire);
    assert_eq!(promise.encoded_field_section(), &[0x00, 0x00, 0xc0]);
}

#[test]
fn http3_qpack_field_section_blocking_and_peer_decompression_errors_are_exact() {
    let mut storage = [0; 36];
    let mut table_entries = [QpackDynamicTableEntry::EMPTY; 2];
    let mut table = QpackDynamicTable::new(&mut storage, &mut table_entries);
    assert_eq!(table.set_capacity(68, |_| true), Ok(()));
    let decoder = QpackFieldSectionDecoder::new(128);

    let blocked_wire = [0x01, 0x03, 0x02, 0x00, 0x80];
    let blocked = Http3Headers::parse(&blocked_wire, 3).unwrap();
    let mut blocked_bytes = [0xaa; 16];
    let mut blocked_fields = [QpackDecodedFieldEntry::EMPTY; 2];
    let before_blocked_bytes = blocked_bytes;
    let before_blocked_fields = blocked_fields;
    {
        let mut output = QpackFieldSectionOutput::new(&mut blocked_bytes, &mut blocked_fields);
        assert!(matches!(
            blocked.decode_field_section(&decoder, &table, &mut output),
            Ok(QpackFieldSectionDecodeOutcome::Blocked(blocked))
                if blocked.required_insert_count() == 1 && blocked.base() == 1
        ));
        assert_eq!(output.len(), 0);
    }
    assert_eq!(
        (blocked_bytes, blocked_fields),
        (before_blocked_bytes, before_blocked_fields)
    );

    for (wire, expected) in [
        (
            &[0x01, 0x01, 0x00][..],
            QpackFieldSectionDecodeError::Prefix(QpackFieldSectionPrefixParseError::DeltaBase(
                QpackIntegerParseError::Incomplete {
                    required: 1,
                    available: 0,
                },
            )),
        ),
        (
            &[0x01, 0x04, 0x00, 0x00, 0xff, 0x24][..],
            QpackFieldSectionDecodeError::StaticIndexOutOfRange { index: 99 },
        ),
    ] {
        let headers = Http3Headers::parse(wire, wire.len() - 2).unwrap();
        let mut bytes = [0xaa; 16];
        let mut fields = [QpackDecodedFieldEntry::EMPTY; 2];
        let error = {
            let mut output = QpackFieldSectionOutput::new(&mut bytes, &mut fields);
            headers
                .decode_field_section(&decoder, &table, &mut output)
                .unwrap_err()
        };
        assert_eq!(
            error,
            Http3QpackFieldSectionError::DecompressionFailed(expected)
        );
        assert_eq!(
            error.error_code(),
            Some(Http3ErrorCode::QPACK_DECOMPRESSION_FAILED)
        );
        assert_eq!(
            core::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<QpackFieldSectionDecodeError>()),
            Some(&expected)
        );
        assert!(error.to_string().contains("decompression failed"));
        assert!(!error.to_string().contains("failed locally"));
    }
}

#[test]
fn http3_qpack_field_section_output_provisioning_is_local_and_atomic() {
    let mut storage = [];
    let mut table_entries = [];
    let table = QpackDynamicTable::new(&mut storage, &mut table_entries);
    let decoder = QpackFieldSectionDecoder::new(128);
    let wire = [0x05, 0x04, 0x2a, 0x00, 0x00, 0xc0];
    let promise = Http3PushPromise::parse(&wire, 4).unwrap();

    for (byte_len, field_len, expected) in [
        (
            9,
            1,
            QpackFieldSectionDecodeError::OutputBytesTooShort {
                required: 10,
                available: 9,
            },
        ),
        (
            10,
            0,
            QpackFieldSectionDecodeError::OutputFieldsTooShort {
                required: 1,
                available: 0,
            },
        ),
    ] {
        let mut bytes = [0xaa; 10];
        let mut fields = [QpackDecodedFieldEntry::EMPTY; 1];
        let before_bytes = bytes;
        let before_fields = fields;
        let error = {
            let mut output =
                QpackFieldSectionOutput::new(&mut bytes[..byte_len], &mut fields[..field_len]);
            promise
                .decode_field_section(&decoder, &table, &mut output)
                .unwrap_err()
        };
        assert_eq!(
            error,
            Http3QpackFieldSectionError::OutputProvisioning(expected)
        );
        assert_eq!(error.error_code(), None);
        assert_eq!(
            core::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<QpackFieldSectionDecodeError>()),
            Some(&expected)
        );
        assert!(
            error
                .to_string()
                .contains("output provisioning failed locally")
        );
        assert!(!error.to_string().contains("decompression failed"));
        assert_eq!((bytes, fields), (before_bytes, before_fields));
    }
}
