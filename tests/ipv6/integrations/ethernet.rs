use crate::fixtures::WIRE;
use net_wire::ParseError;
use net_wire::ethernet::{EthernetFrame, EthernetFrameViewMut};

fn frame(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 14];
    bytes[12..14].copy_from_slice(&ether_type.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn ipv6_dispatch_contract() {
    let ip = &WIRE[..43];
    assert_eq!(
        EthernetFrame::view(&frame(0x0800, ip))
            .without_trailing()
            .unwrap()
            .ipv6()
            .unwrap(),
        None
    );

    let bytes = frame(0x86dd, ip);
    let packet = EthernetFrame::view(&bytes)
        .without_trailing()
        .unwrap()
        .ipv6()
        .unwrap()
        .unwrap();
    assert_eq!((packet.as_bytes(), packet.next_header().raw()), (ip, 0xfd));

    assert_eq!(
        EthernetFrame::view(&frame(0x86dd, &ip[..40]))
            .without_trailing()
            .unwrap()
            .ipv6(),
        Err(ParseError::Truncated {
            minimum: 43,
            available: 40
        })
    );
}

#[test]
fn mutable_ipv6_dispatch_writes_frame_payload() {
    let mut bytes = frame(0x86dd, &WIRE[..43]);
    let mut frame = EthernetFrameViewMut::parse_exact_mut(&mut bytes).unwrap();
    frame.ipv6_mut().unwrap().unwrap().payload_mut()[1] = 9;
    assert_eq!(bytes[14 + 41], 9);
}
