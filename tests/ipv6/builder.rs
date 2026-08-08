use crate::fixtures::WIRE;
use net_wire::ipv6::{
    Ipv6Address, Ipv6NextHeader, Ipv6PacketBuildError, Ipv6PacketBuilder, Ipv6PacketMut,
};

const ZERO_WIRE: [u8; 40] = [
    0x6a, 0xbc, 0xde, 0xef, 0, 0, 0xfd, 64, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
];

fn complete<'a>(b: &'a mut [u8], n: usize) -> Result<Ipv6PacketMut<'a>, Ipv6PacketBuildError> {
    Ipv6PacketBuilder::new(b, n)
        .next_header(Ipv6NextHeader::new(0xfd))
        .hop_limit(64)
        .source(Ipv6Address::new([
            0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]))
        .destination(Ipv6Address::new([
            0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]))
        .traffic_class(0xab)
        .flow_label(0xcdeef)
        .build()
}

#[test]
fn builder_is_exact_and_atomic() {
    let mut zero = [0xa5; 40];
    let p = complete(&mut zero, 0).unwrap();
    assert_eq!(p.as_bytes(), &ZERO_WIRE);
    let mut b = [0xa5; 46];
    let p = complete(&mut b, 3).unwrap();
    assert_eq!(&p.as_bytes()[..40], &WIRE[..40]);
    assert_eq!(p.payload(), &[0xa5; 3]);
    assert_eq!(&b[40..], &[0xa5; 6]);
    macro_rules! e {
        ($x:expr,$w:expr) => {{
            let mut b = [0xa5; 50];
            let o = b;
            assert_eq!($x(&mut b), Err($w));
            assert_eq!(b, o)
        }};
    }
    fn a(b: &mut [u8]) -> Result<Ipv6PacketMut<'_>, Ipv6PacketBuildError> {
        Ipv6PacketBuilder::new(b, 0).build()
    }
    fn c(b: &mut [u8]) -> Result<Ipv6PacketMut<'_>, Ipv6PacketBuildError> {
        Ipv6PacketBuilder::new(b, 0)
            .next_header(Ipv6NextHeader::new(1))
            .build()
    }
    fn d(b: &mut [u8]) -> Result<Ipv6PacketMut<'_>, Ipv6PacketBuildError> {
        Ipv6PacketBuilder::new(b, 0)
            .next_header(Ipv6NextHeader::new(1))
            .hop_limit(1)
            .build()
    }
    fn e2(b: &mut [u8]) -> Result<Ipv6PacketMut<'_>, Ipv6PacketBuildError> {
        Ipv6PacketBuilder::new(b, 0)
            .next_header(Ipv6NextHeader::new(1))
            .hop_limit(1)
            .source(Ipv6Address::new([1; 16]))
            .build()
    }
    e!(a, Ipv6PacketBuildError::MissingNextHeader);
    e!(c, Ipv6PacketBuildError::MissingHopLimit);
    e!(d, Ipv6PacketBuildError::MissingSource);
    e!(e2, Ipv6PacketBuildError::MissingDestination);
    let mut b = [0xa5; 50];
    let o = b;
    assert_eq!(
        Ipv6PacketBuilder::new(&mut b, 0)
            .next_header(Ipv6NextHeader::new(1))
            .hop_limit(1)
            .source(Ipv6Address::new([1; 16]))
            .destination(Ipv6Address::new([2; 16]))
            .flow_label(0x10_0000)
            .build(),
        Err(Ipv6PacketBuildError::FlowLabelTooLarge)
    );
    assert_eq!(b, o);
    let mut b = [0xa5; 50];
    let o = b;
    assert_eq!(
        Ipv6PacketBuilder::new(&mut b, 65536)
            .next_header(Ipv6NextHeader::new(1))
            .hop_limit(1)
            .source(Ipv6Address::new([1; 16]))
            .destination(Ipv6Address::new([2; 16]))
            .build(),
        Err(Ipv6PacketBuildError::PayloadLengthTooLarge)
    );
    assert_eq!(b, o);
    let mut b = [0xa5; 42];
    let o = b;
    assert_eq!(
        complete(&mut b, 3).map(|_| ()),
        Err(Ipv6PacketBuildError::BufferTooShort {
            required: 43,
            available: 42
        })
    );
    assert_eq!(b, o);
}
