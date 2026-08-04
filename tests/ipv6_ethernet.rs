#![cfg(all(feature = "ipv6", feature = "ethernet"))]
use net_wire::*;
fn frame(t: u16, p: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 14];
    b[12..14].copy_from_slice(&t.to_be_bytes());
    b.extend_from_slice(p);
    b
}
const IP: [u8; 43] = [
    0x60, 0, 0, 0, 0, 3, 0xfd, 64, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x20,
    1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 2, 3,
];
#[test]
fn ipv6_dispatch_contract() {
    assert_eq!(
        EthernetFrame::parse(&frame(0x0800, &IP))
            .unwrap()
            .ipv6()
            .unwrap(),
        None
    );
    let bytes = frame(0x86dd, &IP);
    let p = EthernetFrame::parse(&bytes)
        .unwrap()
        .ipv6()
        .unwrap()
        .unwrap();
    assert_eq!((p.as_bytes(), p.next_header().raw()), (&IP[..], 0xfd));
    assert_eq!(
        EthernetFrame::parse(&frame(0x86dd, &IP[..40]))
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
    let mut b = frame(0x86dd, &IP);
    let mut f = EthernetFrameMut::parse(&mut b).unwrap();
    f.ipv6_mut().unwrap().unwrap().payload_mut()[1] = 9;
    assert_eq!(b[14 + 41], 9);
}
