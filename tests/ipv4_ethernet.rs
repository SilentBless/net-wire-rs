#![cfg(all(feature = "ipv4", feature = "ethernet"))]
use net_wire::*;
fn frame(t: u16, p: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 14];
    b[12..14].copy_from_slice(&t.to_be_bytes());
    b.extend_from_slice(p);
    b
}
const IP: [u8; 20] = [
    0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0xf6, 0xe0, 192, 0, 2, 1, 192, 0, 2, 2,
];
#[test]
fn ipv4_dispatch_contract() {
    assert_eq!(
        EthernetFrame::parse(&frame(0x86dd, &IP))
            .unwrap()
            .ipv4()
            .unwrap(),
        None
    );
    let bytes = frame(0x0800, &IP);
    let p = EthernetFrame::parse(&bytes)
        .unwrap()
        .ipv4()
        .unwrap()
        .unwrap();
    assert_eq!((p.as_bytes(), p.ttl()), (&IP[..], 64));
    assert_eq!(
        EthernetFrame::parse(&frame(0x0800, &IP[..19]))
            .unwrap()
            .ipv4(),
        Err(ParseError::Truncated {
            minimum: 20,
            available: 19
        })
    );
}
#[test]
fn mutable_ipv4_dispatch_writes_frame_payload() {
    let mut b = frame(0x0800, &IP);
    let mut f = EthernetFrameMut::parse(&mut b).unwrap();
    f.ipv4_mut().unwrap().unwrap().set_ttl(1);
    assert_eq!(b[14 + 8], 1);
}
