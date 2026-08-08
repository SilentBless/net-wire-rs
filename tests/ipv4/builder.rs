use net_wire::ipv4::{
    Ipv4Address, Ipv4PacketBuildError, Ipv4PacketBuilder, Ipv4PacketMut, Ipv4Protocol,
};

fn complete<'a>(
    b: &'a mut [u8],
    options: &[u8],
) -> Result<Ipv4PacketMut<'a>, Ipv4PacketBuildError> {
    Ipv4PacketBuilder::new(b, 4)
        .source(Ipv4Address::new([192, 0, 2, 1]))
        .destination(Ipv4Address::new([198, 51, 100, 2]))
        .protocol(Ipv4Protocol::new(0xfd))
        .ttl(60)
        .identification(0x1234)
        .flags_fragment_offset(0x2005)
        .dscp_ecn(0xab)
        .options(options)
        .build()
}
fn built_from_local(buffer: &mut [u8]) -> Ipv4PacketMut<'_> {
    let options = [1, 2, 3, 4];
    complete(buffer, &options).unwrap()
}
#[test]
fn builder_is_exact_and_errors_atomic() {
    let mut b = [0xa5; 31];
    let p = built_from_local(&mut b);
    assert_eq!(
        p.as_bytes(),
        &[
            0x46, 0xab, 0, 28, 0x12, 0x34, 0x20, 5, 60, 0xfd, 0x59, 0xc4, 192, 0, 2, 1, 198, 51,
            100, 2, 1, 2, 3, 4, 0xa5, 0xa5, 0xa5, 0xa5,
        ]
    );
    assert_eq!(&b[24..], &[0xa5; 7]);
    macro_rules! e {
        ($x:expr,$want:expr) => {{
            let mut b = [0xa5; 64];
            let old = b;
            assert_eq!($x(&mut b), Err($want));
            assert_eq!(b, old)
        }};
    }
    fn m1(b: &mut [u8]) -> Result<Ipv4PacketMut<'_>, Ipv4PacketBuildError> {
        Ipv4PacketBuilder::new(b, 0).build()
    }
    fn m2(b: &mut [u8]) -> Result<Ipv4PacketMut<'_>, Ipv4PacketBuildError> {
        Ipv4PacketBuilder::new(b, 0)
            .source(Ipv4Address::new([1; 4]))
            .build()
    }
    fn m3(b: &mut [u8]) -> Result<Ipv4PacketMut<'_>, Ipv4PacketBuildError> {
        Ipv4PacketBuilder::new(b, 0)
            .source(Ipv4Address::new([1; 4]))
            .destination(Ipv4Address::new([2; 4]))
            .build()
    }
    fn m4(b: &mut [u8]) -> Result<Ipv4PacketMut<'_>, Ipv4PacketBuildError> {
        Ipv4PacketBuilder::new(b, 0)
            .source(Ipv4Address::new([1; 4]))
            .destination(Ipv4Address::new([2; 4]))
            .protocol(Ipv4Protocol::new(1))
            .build()
    }
    e!(m1, Ipv4PacketBuildError::MissingSource);
    e!(m2, Ipv4PacketBuildError::MissingDestination);
    e!(m3, Ipv4PacketBuildError::MissingProtocol);
    e!(m4, Ipv4PacketBuildError::MissingTtl);
    let mut b = [0xa5; 64];
    let old = b;
    assert_eq!(
        complete(&mut b, &[1, 2, 3]).map(|_| ()),
        Err(Ipv4PacketBuildError::InvalidOptionsLength)
    );
    assert_eq!(b, old);
    let mut b = [0xa5; 64];
    let old = b;
    assert_eq!(
        complete(&mut b, &[0; 44]).map(|_| ()),
        Err(Ipv4PacketBuildError::InvalidOptionsLength)
    );
    assert_eq!(b, old);
    let mut b = [0xa5; 64];
    let old = b;
    assert_eq!(
        Ipv4PacketBuilder::new(&mut b, 0)
            .source(Ipv4Address::new([1; 4]))
            .destination(Ipv4Address::new([2; 4]))
            .protocol(Ipv4Protocol::new(1))
            .ttl(1)
            .flags_fragment_offset(0x8000)
            .build(),
        Err(Ipv4PacketBuildError::ReservedFlagSet)
    );
    assert_eq!(b, old);
    let mut b = [0xa5; 64];
    let old = b;
    assert_eq!(
        Ipv4PacketBuilder::new(&mut b, usize::MAX)
            .source(Ipv4Address::new([1; 4]))
            .destination(Ipv4Address::new([2; 4]))
            .protocol(Ipv4Protocol::new(1))
            .ttl(1)
            .build(),
        Err(Ipv4PacketBuildError::TotalLengthTooLarge)
    );
    assert_eq!(b, old);
    let mut b = [0xa5; 64];
    let old = b;
    assert_eq!(
        Ipv4PacketBuilder::new(&mut b, 65_516)
            .source(Ipv4Address::new([1; 4]))
            .destination(Ipv4Address::new([2; 4]))
            .protocol(Ipv4Protocol::new(1))
            .ttl(1)
            .build(),
        Err(Ipv4PacketBuildError::TotalLengthTooLarge)
    );
    assert_eq!(b, old);
    let mut b = [0xa5; 23];
    let old = b;
    assert_eq!(
        complete(&mut b, &[]).map(|_| ()),
        Err(Ipv4PacketBuildError::BufferTooShort {
            required: 24,
            available: 23
        })
    );
    assert_eq!(b, old);
}
