use net_wire::ethernet::{EtherType, EthernetFrameBuilder, EthernetFrameWriteError};

use super::fixtures::{DESTINATION, SOURCE};

#[test]
fn rfc_894_builder_writes_complete_frame_and_preserves_capacity_suffix() {
    let mut bytes = [0x55; 19];
    let payload = [0xa1, 0xb2, 0xc3];
    let (frame, suffix) = EthernetFrameBuilder::new()
        .destination(DESTINATION)
        .source(SOURCE)
        .ether_type(EtherType::IPV4)
        .payload(&payload)
        .build_into(&mut bytes)
        .unwrap();
    assert_eq!(
        frame.as_bytes(),
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
            0xa1, 0xb2, 0xc3,
        ]
    );
    assert_eq!(suffix, [0x55, 0x55]);
}

#[test]
fn builder_failures_are_atomic_for_capacity_and_every_required_field() {
    let initial = [0xa5; 16];
    let payload = [1, 2, 3];

    let mut bytes = initial;
    assert!(matches!(
        EthernetFrameBuilder::new()
            .destination(DESTINATION)
            .source(SOURCE)
            .ether_type(EtherType::IPV4)
            .payload(&payload)
            .build_into(&mut bytes),
        Err(EthernetFrameWriteError::OutputTooShort {
            expected: 17,
            actual: 16,
        })
    ));
    assert_eq!(bytes, initial);

    let mut bytes = initial;
    assert!(matches!(
        EthernetFrameBuilder::new()
            .source(SOURCE)
            .ether_type(EtherType::IPV4)
            .payload(&[])
            .build_into(&mut bytes),
        Err(EthernetFrameWriteError::MissingField {
            field: "destination",
        })
    ));
    assert_eq!(bytes, initial);

    let mut bytes = initial;
    assert!(matches!(
        EthernetFrameBuilder::new()
            .destination(DESTINATION)
            .ether_type(EtherType::IPV4)
            .payload(&[])
            .build_into(&mut bytes),
        Err(EthernetFrameWriteError::MissingField { field: "source" })
    ));
    assert_eq!(bytes, initial);

    let mut bytes = initial;
    assert!(matches!(
        EthernetFrameBuilder::new()
            .destination(DESTINATION)
            .source(SOURCE)
            .payload(&[])
            .build_into(&mut bytes),
        Err(EthernetFrameWriteError::MissingField {
            field: "ether_type",
        })
    ));
    assert_eq!(bytes, initial);

    let mut bytes = initial;
    assert!(matches!(
        EthernetFrameBuilder::new()
            .destination(DESTINATION)
            .source(SOURCE)
            .ether_type(EtherType::IPV4)
            .build_into(&mut bytes),
        Err(EthernetFrameWriteError::MissingField { field: "payload" })
    ));
    assert_eq!(bytes, initial);
}
