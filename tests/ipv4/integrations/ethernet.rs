use crate::fixtures::BASIC;
use net_wire::ParseError;
use net_wire::ethernet::{EthernetFrameView, EthernetFrameViewMut};

fn frame(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        (ether_type >> 8) as u8,
        ether_type as u8,
    ];
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn ipv4_dispatch_matches_ether_type_and_writes_through() {
    assert!(
        EthernetFrameView::parse_exact(&frame(0x0800, &BASIC[..20]))
            .unwrap()
            .ipv4()
            .unwrap()
            .is_some()
    );
    assert_eq!(
        EthernetFrameView::parse_exact(&frame(0x86dd, &BASIC[..20]))
            .unwrap()
            .ipv4(),
        Ok(None)
    );
    assert_eq!(
        EthernetFrameView::parse_exact(&frame(0x0800, &BASIC[..19]))
            .unwrap()
            .ipv4(),
        Err(ParseError::Truncated {
            minimum: 20,
            available: 19,
        })
    );

    let mut bytes = frame(0x0800, &BASIC[..20]);
    let mut ethernet = EthernetFrameViewMut::parse_exact_mut(&mut bytes).unwrap();
    ethernet.ipv4_mut().unwrap().unwrap().set_ttl(1);
    assert_eq!(ethernet.payload()[8], 1);
}
