#![cfg(feature = "ipv4")]
use net_wire::*;
const BASIC: [u8; 21] = [
    0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0xf6, 0xe0, 192, 0, 2, 1, 192, 0, 2, 2, 0xee,
];
const OPTIONS: [u8; 29] = [
    0x46, 0xab, 0, 28, 0x12, 0x34, 0x20, 5, 60, 0xfd, 0x59, 0xc4, 192, 0, 2, 1, 198, 51, 100, 2, 1,
    2, 3, 4, 9, 8, 7, 6, 0xee,
];
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
fn fixed_and_option_layouts_are_bounded_and_valid() {
    let p = Ipv4Packet::parse(&BASIC).unwrap();
    assert_eq!(
        (
            p.dscp_ecn(),
            p.total_length(),
            p.identification(),
            p.flags_fragment_offset(),
            p.ttl(),
            p.protocol().raw(),
            p.header_checksum(),
            p.source(),
            p.destination()
        ),
        (
            0,
            20,
            0,
            0,
            64,
            6,
            0xf6e0,
            Ipv4Address::new([192, 0, 2, 1]),
            Ipv4Address::new([192, 0, 2, 2])
        )
    );
    assert_eq!(
        (
            p.options(),
            p.payload(),
            p.as_bytes(),
            p.checksum_is_valid()
        ),
        (&[][..], &[][..], &BASIC[..20], true)
    );
    let q = Ipv4Packet::parse(&OPTIONS).unwrap();
    assert_eq!(
        (
            q.options(),
            q.payload(),
            q.as_bytes().len(),
            q.protocol().raw(),
            q.checksum_is_valid()
        ),
        (&[1, 2, 3, 4][..], &[9, 8, 7, 6][..], 28, 0xfd, true)
    );
}
#[test]
fn parse_errors_and_permissive_capture_fields() {
    assert_eq!(
        Ipv4Packet::parse(&BASIC[..19]),
        Err(ParseError::Truncated {
            minimum: 20,
            available: 19
        })
    );
    let mut b = BASIC;
    b[0] = 0x55;
    assert_eq!(
        Ipv4Packet::parse(&b),
        Err(ParseError::InvalidVersion {
            expected: 4,
            actual: 5
        })
    );
    b = BASIC;
    b[0] = 0x44;
    assert_eq!(
        Ipv4Packet::parse(&b),
        Err(ParseError::InvalidHeaderLength {
            minimum: 20,
            actual: 16
        })
    );
    let mut option_header = OPTIONS;
    option_header[0] = 0x47;
    assert_eq!(
        Ipv4Packet::parse(&option_header[..24]),
        Err(ParseError::Truncated {
            minimum: 28,
            available: 24
        })
    );
    b = BASIC;
    b[2] = 0;
    b[3] = 19;
    assert_eq!(
        Ipv4Packet::parse(&b),
        Err(ParseError::InvalidTotalLength {
            header_length: 20,
            total_length: 19
        })
    );
    b = BASIC;
    b[2] = 0;
    b[3] = 22;
    assert_eq!(
        Ipv4Packet::parse(&b),
        Err(ParseError::Truncated {
            minimum: 22,
            available: 21
        })
    );
    b = BASIC;
    b[10] ^= 1;
    assert!(!Ipv4Packet::parse(&b).unwrap().checksum_is_valid());
    b = BASIC;
    b[6] = 0x80;
    assert_eq!(
        Ipv4Packet::parse(&b).unwrap().flags_fragment_offset(),
        0x8000
    );
}
#[test]
fn mutable_fields_and_checksum_boundary() {
    let mut b = OPTIONS;
    let mut p = Ipv4PacketMut::parse(&mut b).unwrap();
    assert_eq!(
        (
            p.dscp_ecn(),
            p.total_length(),
            p.identification(),
            p.flags_fragment_offset(),
            p.ttl(),
            p.protocol().raw(),
            p.header_checksum(),
            p.source(),
            p.destination()
        ),
        (
            0xab,
            28,
            0x1234,
            0x2005,
            60,
            0xfd,
            0x59c4,
            Ipv4Address::new([192, 0, 2, 1]),
            Ipv4Address::new([198, 51, 100, 2])
        )
    );
    p.set_dscp_ecn(1);
    p.set_identification(2);
    p.set_flags_fragment_offset(3);
    p.set_ttl(4);
    p.set_protocol(Ipv4Protocol::new(5));
    p.set_source(Ipv4Address::new([1, 1, 1, 1]));
    p.set_destination(Ipv4Address::new([2, 2, 2, 2]));
    p.options_mut()[0] = 9;
    assert!(!p.checksum_is_valid());
    p.update_header_checksum();
    assert!(p.checksum_is_valid());
    let c = p.header_checksum();
    p.payload_mut()[0] = 0;
    assert!(p.checksum_is_valid());
    p.set_header_checksum(c);
    p.as_bytes_mut()[1] = 1;
    assert_eq!(p.options(), &[9, 2, 3, 4]);
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
