use net_wire::ethernet::{EtherType, EthernetFrameBuildError, EthernetFrameBuilder};

use super::fixtures::{DESTINATION, SOURCE};

#[test]
fn rfc_894_builder_writes_header_only_and_limits_returned_view() {
    let mut bytes = [
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xa1,
        0xb2, 0xc3, 0xee, 0xff,
    ];

    {
        let frame = EthernetFrameBuilder::new(&mut bytes, 3)
            .destination(DESTINATION)
            .source(SOURCE)
            .ether_type(EtherType::IPV4)
            .build()
            .unwrap();

        assert_eq!(
            frame.as_bytes(),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
                0xa1, 0xb2, 0xc3,
            ]
        );
    }
    assert_eq!(bytes[17..], [0xee, 0xff]);
}

#[test]
fn builder_insufficient_buffer_writes_nothing() {
    let mut bytes = [0xa5; 16];

    let result = EthernetFrameBuilder::new(&mut bytes, 3)
        .destination(DESTINATION)
        .source(SOURCE)
        .ether_type(EtherType::IPV4)
        .build();

    assert_eq!(
        result,
        Err(EthernetFrameBuildError::BufferTooShort {
            required: 17,
            available: 16,
        })
    );
    assert_eq!(bytes, [0xa5; 16]);
}

#[test]
fn builder_length_overflow_writes_nothing() {
    let mut bytes = [0xa5; 14];

    let result = EthernetFrameBuilder::new(&mut bytes, usize::MAX)
        .destination(DESTINATION)
        .source(SOURCE)
        .ether_type(EtherType::IPV4)
        .build();

    assert_eq!(
        result,
        Err(EthernetFrameBuildError::LengthOverflow {
            header_length: 14,
            payload_length: usize::MAX,
        })
    );
    assert_eq!(bytes, [0xa5; 14]);
}

#[test]
fn builder_missing_destination_writes_nothing() {
    let mut bytes = [0xa5; 14];

    let result = EthernetFrameBuilder::new(&mut bytes, 0)
        .source(SOURCE)
        .ether_type(EtherType::IPV4)
        .build();

    assert_eq!(result, Err(EthernetFrameBuildError::MissingDestination));
    assert_eq!(bytes, [0xa5; 14]);
}

#[test]
fn builder_missing_source_writes_nothing() {
    let mut bytes = [0xa5; 14];

    let result = EthernetFrameBuilder::new(&mut bytes, 0)
        .destination(DESTINATION)
        .ether_type(EtherType::IPV4)
        .build();

    assert_eq!(result, Err(EthernetFrameBuildError::MissingSource));
    assert_eq!(bytes, [0xa5; 14]);
}

#[test]
fn builder_missing_ether_type_writes_nothing() {
    let mut bytes = [0xa5; 14];

    let result = EthernetFrameBuilder::new(&mut bytes, 0)
        .destination(DESTINATION)
        .source(SOURCE)
        .build();

    assert_eq!(result, Err(EthernetFrameBuildError::MissingEtherType));
    assert_eq!(bytes, [0xa5; 14]);
}
