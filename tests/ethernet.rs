use net_wire::{
    EtherType, EthernetFrame, EthernetFrameBuildError, EthernetFrameBuilder, EthernetFrameMut,
    MacAddress, ParseError,
};

const DESTINATION: MacAddress = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
const SOURCE: MacAddress = MacAddress::new([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);

#[test]
fn rfc_894_layout_accepts_a_14_octet_empty_payload_frame() {
    // RFC 894 defines destination, source, and type in this order. These manually
    // reviewed bytes instantiate that layout; RFC 894 does not provide this fixture.
    let bytes = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
    ];

    let frame = EthernetFrame::parse(&bytes).unwrap();

    assert_eq!(frame.destination(), DESTINATION);
    assert_eq!(frame.source(), SOURCE);
    assert_eq!(frame.ether_type(), EtherType::IPV4);
    assert_eq!(frame.payload(), []);
    assert_eq!(frame.as_bytes(), bytes);
}

#[test]
fn rfc_894_layout_preserves_field_offsets_and_payload_borrowing() {
    // RFC 894 defines destination (0..6), source (6..12), type (12..14), then data.
    let bytes = [
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0xca,
        0xfe, 0xba, 0xbe,
    ];

    let frame = EthernetFrame::parse(&bytes).unwrap();

    assert_eq!(
        frame.destination(),
        MacAddress::new([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])
    );
    assert_eq!(
        frame.source(),
        MacAddress::new([0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
    );
    assert_eq!(frame.ether_type(), EtherType::new(0x0800));
    assert_eq!(frame.payload(), [0xca, 0xfe, 0xba, 0xbe]);
    assert_eq!(frame.payload().as_ptr(), bytes[14..].as_ptr());
}

#[test]
fn rfc_894_fixed_header_rejects_thirteen_octets() {
    let bytes = [0_u8; 13];

    assert_eq!(
        EthernetFrame::parse(&bytes),
        Err(ParseError::Truncated {
            minimum: 14,
            available: 13,
        })
    );
}

#[test]
fn rfc_894_mutable_setters_change_only_their_header_fields() {
    let mut bytes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x08, 0x06, 0xaa,
        0xbb,
    ];

    let mut frame = EthernetFrameMut::parse(&mut bytes).unwrap();
    frame.set_destination(MacAddress::new([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]));
    frame.set_source(MacAddress::new([0x20, 0x21, 0x22, 0x23, 0x24, 0x25]));
    frame.set_ether_type(EtherType::IPV6);

    assert_eq!(
        frame.destination(),
        MacAddress::new([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])
    );
    assert_eq!(
        frame.source(),
        MacAddress::new([0x20, 0x21, 0x22, 0x23, 0x24, 0x25])
    );
    assert_eq!(frame.ether_type(), EtherType::IPV6);
    assert_eq!(
        frame.as_bytes(),
        [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x86, 0xdd,
            0xaa, 0xbb,
        ]
    );
}

#[test]
fn rfc_894_mutable_payload_and_byte_slices_update_the_backing_frame() {
    let mut bytes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x08, 0x06, 0xaa,
        0xbb,
    ];

    let mut frame = EthernetFrameMut::parse(&mut bytes).unwrap();
    frame.payload_mut().copy_from_slice(&[0xca, 0xfe]);
    frame.as_bytes_mut()[0] = 0xde;

    assert_eq!(frame.payload(), [0xca, 0xfe]);
    assert_eq!(
        frame.as_bytes(),
        [
            0xde, 0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x08, 0x06,
            0xca, 0xfe,
        ]
    );
}

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
