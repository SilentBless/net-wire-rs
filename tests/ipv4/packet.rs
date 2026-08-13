use crate::fixtures::{BASIC, OPTIONS};
use net_wire::ParseError;
use net_wire::ipv4::{Ipv4Address, Ipv4Packet, Ipv4PacketMut, Ipv4Protocol};

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
    p.set_dscp_ecn(1).unwrap();
    p.set_identification(2).unwrap();
    p.set_flags_fragment_offset(3).unwrap();
    p.set_ttl(4).unwrap();
    p.set_protocol(Ipv4Protocol::new(5)).unwrap();
    p.set_source(Ipv4Address::new([1, 1, 1, 1])).unwrap();
    p.set_destination(Ipv4Address::new([2, 2, 2, 2])).unwrap();
    p.options_mut()[0] = 9;
    assert!(!p.checksum_is_valid());
    p.update_header_checksum().unwrap();
    assert!(p.checksum_is_valid());
    let c = p.header_checksum();
    p.payload_mut()[0] = 0;
    assert!(p.checksum_is_valid());
    p.set_header_checksum(c).unwrap();
    assert_eq!(p.options(), &[9, 2, 3, 4]);
}
