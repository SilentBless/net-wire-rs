use net_wire::ParseError;
use net_wire::ethernet::{EthernetFrame, EthernetFrameMut, MacAddress};

fn frame(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 14];
    bytes[12..14].copy_from_slice(&ether_type.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn arp_dispatch_validates_ether_type_and_mac_helpers() {
    let arp = [
        0, 1, 8, 0, 6, 4, 0, 1, 1, 2, 3, 4, 5, 6, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2,
    ];
    assert_eq!(
        EthernetFrame::parse(&frame(0x0800, &arp))
            .unwrap()
            .arp()
            .unwrap(),
        None
    );

    let bytes = frame(0x0806, &arp);
    let packet = EthernetFrame::parse(&bytes)
        .unwrap()
        .arp()
        .unwrap()
        .unwrap();
    assert_eq!(
        packet.sender_mac_address(),
        Some(MacAddress::new([1, 2, 3, 4, 5, 6]))
    );
    assert_eq!(packet.target_mac_address(), Some(MacAddress::new([0; 6])));

    assert_eq!(
        EthernetFrame::parse(&frame(0x0806, &arp[..7]))
            .unwrap()
            .arp(),
        Err(ParseError::Truncated {
            minimum: 8,
            available: 7
        })
    );

    let wrong_hardware_type = [
        0, 2, 8, 0, 6, 4, 0, 1, 1, 2, 3, 4, 5, 6, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2,
    ];
    assert_eq!(
        EthernetFrame::parse(&frame(0x0806, &wrong_hardware_type))
            .unwrap()
            .arp()
            .unwrap()
            .unwrap()
            .sender_mac_address(),
        None
    );

    let short_hardware_address = [
        0, 1, 8, 0, 5, 4, 0, 1, 1, 2, 3, 4, 5, 192, 0, 2, 1, 0, 0, 0, 0, 0, 192, 0, 2, 2,
    ];
    assert_eq!(
        EthernetFrame::parse(&frame(0x0806, &short_hardware_address))
            .unwrap()
            .arp()
            .unwrap()
            .unwrap()
            .target_mac_address(),
        None
    );
}

#[test]
fn mutable_arp_dispatch_writes_frame_payload() {
    let mut bytes = frame(
        0x0806,
        &[0, 1, 8, 0, 1, 4, 0, 1, 9, 192, 0, 2, 1, 8, 192, 0, 2, 2],
    );
    let mut frame = EthernetFrameMut::parse(&mut bytes).unwrap();
    frame
        .arp_mut()
        .unwrap()
        .unwrap()
        .sender_protocol_address_mut()[3] = 9;
    assert_eq!(bytes[26], 9);
}
