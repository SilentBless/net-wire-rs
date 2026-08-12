use net_wire::ethernet::{
    EtherType, EthernetFrameError, EthernetFrameView, EthernetFrameViewMut, MacAddress,
};

use super::fixtures::{DESTINATION, SOURCE};

#[test]
fn rfc_894_layout_accepts_a_14_octet_empty_payload_frame() {
    let bytes = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
    ];
    let frame = EthernetFrameView::parse_exact(&bytes).unwrap();
    assert_eq!(frame.destination(), DESTINATION);
    assert_eq!(frame.source(), SOURCE);
    assert_eq!(frame.ether_type(), EtherType::IPV4);
    assert_eq!(frame.payload(), []);
    assert_eq!(frame.as_bytes(), bytes);
}

#[test]
fn rfc_894_layout_preserves_offsets_and_caller_bounded_payload() {
    let bytes = [
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x88, 0xb5, 0xca,
        0xfe, 0xba, 0xbe,
    ];
    let (frame, suffix) = EthernetFrameView::parse_prefix(&bytes).unwrap();
    assert!(suffix.is_empty());
    assert_eq!(
        frame.destination(),
        MacAddress::new([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])
    );
    assert_eq!(
        frame.source(),
        MacAddress::new([0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
    );
    assert_eq!(frame.ether_type(), EtherType::new(0x88b5));
    assert_eq!(frame.payload(), [0xca, 0xfe, 0xba, 0xbe]);
    assert_eq!(frame.payload().as_ptr(), bytes[14..].as_ptr());
}

#[test]
fn rfc_894_fixed_header_rejects_thirteen_octets() {
    assert!(matches!(
        EthernetFrameView::parse_exact(&[0_u8; 13]),
        Err(EthernetFrameError::InputTooShort {
            position: 3,
            expected: 2,
            available: 1,
        })
    ));
}

#[test]
fn rfc_894_mutable_setters_and_payload_preserve_the_frame_boundary() {
    let mut bytes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x08, 0x06, 0xaa,
        0xbb,
    ];
    let mut frame = EthernetFrameViewMut::parse_exact_mut(&mut bytes).unwrap();
    frame
        .set_destination(MacAddress::new([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]))
        .unwrap();
    frame
        .set_source(MacAddress::new([0x20, 0x21, 0x22, 0x23, 0x24, 0x25]))
        .unwrap();
    frame.set_ether_type(EtherType::IPV6).unwrap();
    frame.payload_mut().copy_from_slice(&[0xca, 0xfe]);
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
            0xca, 0xfe,
        ]
    );
}
