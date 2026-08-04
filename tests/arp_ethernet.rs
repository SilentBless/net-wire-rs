#![cfg(all(feature = "arp", feature = "ethernet"))]
use net_wire::*;
fn frame(t: u16, p: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 14];
    b[12..14].copy_from_slice(&t.to_be_bytes());
    b.extend_from_slice(p);
    b
}
#[test]
fn arp_dispatch_and_mac_gating() {
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
    let p = EthernetFrame::parse(&bytes)
        .unwrap()
        .arp()
        .unwrap()
        .unwrap();
    assert_eq!(p.as_bytes().len(), 28);
    assert_eq!(
        p.sender_mac_address(),
        Some(MacAddress::new([1, 2, 3, 4, 5, 6]))
    );
    assert_eq!(p.target_mac_address(), Some(MacAddress::new([0; 6])));
    assert_eq!(
        EthernetFrame::parse(&frame(0x0806, &arp[..7]))
            .unwrap()
            .arp(),
        Err(ParseError::Truncated {
            minimum: 8,
            available: 7
        })
    );
    let wrong_hw = [
        0, 2, 8, 0, 6, 4, 0, 1, 1, 2, 3, 4, 5, 6, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2,
    ];
    assert_eq!(
        EthernetFrame::parse(&frame(0x0806, &wrong_hw))
            .unwrap()
            .arp()
            .unwrap()
            .unwrap()
            .sender_mac_address(),
        None
    );
    let short_hw = [
        0, 1, 8, 0, 5, 4, 0, 1, 1, 2, 3, 4, 5, 192, 0, 2, 1, 0, 0, 0, 0, 0, 192, 0, 2, 2,
    ];
    assert_eq!(
        EthernetFrame::parse(&frame(0x0806, &short_hw))
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
    let mut b = frame(
        0x0806,
        &[0, 1, 8, 0, 1, 4, 0, 1, 9, 192, 0, 2, 1, 8, 192, 0, 2, 2],
    );
    let mut f = EthernetFrameMut::parse(&mut b).unwrap();
    f.arp_mut().unwrap().unwrap().sender_protocol_address_mut()[3] = 9;
    assert_eq!(b[26], 9);
}
