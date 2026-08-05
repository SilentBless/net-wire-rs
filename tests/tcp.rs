use net_wire::*;

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_with_local_options(buffer: &mut [u8]) -> TcpSegmentMut<'_> {
    let options = [1, 2, 3, 4];
    TcpSegmentBuilder::new(buffer, 1)
        .source_port(1)
        .destination_port(2)
        .options(&options)
        .sequence_number(3)
        .acknowledgment_number(4)
        .flags(TcpFlags::SYN)
        .window_size(5)
        .checksum(0xbeef)
        .urgent_pointer(6)
        .build()
        .unwrap()
}

#[test]
fn layout_all_accessors_mutators_flags_and_builder_errors() {
    assert_eq!(
        TcpSegment::parse(&[0; 19]),
        Err(ParseError::Truncated {
            minimum: 20,
            available: 19
        })
    );
    let mut short = [0; 20];
    short[12] = 0x40;
    assert_eq!(
        TcpSegment::parse(&short),
        Err(ParseError::InvalidHeaderLength {
            minimum: 20,
            actual: 16
        })
    );
    short[12] = 0x60;
    assert_eq!(
        TcpSegment::parse(&short),
        Err(ParseError::Truncated {
            minimum: 24,
            available: 20
        })
    );
    let bytes = [
        0, 1, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0x65, 0xa5, 0, 9, 0x12, 0x34, 0, 7, 1, 2, 3, 4, 9,
    ];
    let p = TcpSegment::parse(&bytes).unwrap();
    assert_eq!(p.source_port(), 1);
    assert_eq!(p.destination_port(), 2);
    assert_eq!(p.sequence_number(), 3);
    assert_eq!(p.acknowledgment_number(), 4);
    assert_eq!(p.data_offset(), 6);
    assert_eq!(p.header_length(), 24);
    assert_eq!(p.reserved(), 5);
    assert_eq!(p.flags().raw(), 0xa5);
    assert_eq!(p.window_size(), 9);
    assert_eq!(p.checksum(), 0x1234);
    assert_eq!(p.urgent_pointer(), 7);
    assert_eq!(p.options(), &[1, 2, 3, 4]);
    assert_eq!(p.payload(), &[9]);
    assert_eq!(p.as_bytes(), &bytes);
    let flags = TcpFlags::SYN.union(TcpFlags::ACK);
    assert!(flags.contains(TcpFlags::SYN | TcpFlags::ACK));
    assert_eq!(flags.raw(), 0x12);
    assert_eq!((TcpFlags::FIN | TcpFlags::CWR).raw(), 0x81);
    assert_eq!(TcpFlags::new(0xff).raw(), 0xff);
    let mut bytes = bytes;
    let mut p = TcpSegmentMut::parse(&mut bytes).unwrap();
    p.set_source_port(9);
    p.set_destination_port(10);
    p.set_sequence_number(11);
    p.set_acknowledgment_number(12);
    p.set_flags(flags);
    assert_eq!(&p.as_bytes()[12..14], &[0x65, 0x12]);
    p.set_window_size(13);
    p.set_checksum(0xbeef);
    p.set_urgent_pointer(14);
    p.options_mut()[0] = 8;
    p.payload_mut()[0] = 7;
    assert_eq!(
        (
            p.source_port(),
            p.destination_port(),
            p.sequence_number(),
            p.acknowledgment_number(),
            p.reserved(),
            p.flags().raw(),
            p.window_size(),
            p.checksum(),
            p.urgent_pointer(),
            p.options(),
            p.payload()
        ),
        (
            9,
            10,
            11,
            12,
            5,
            0x12,
            13,
            0xbeef,
            14,
            &[8, 2, 3, 4][..],
            &[7][..]
        )
    );
    let mut output = [0xa5; 26];
    output[24] = 9;
    let built = build_with_local_options(&mut output);
    assert_eq!(built.options(), &[1, 2, 3, 4]);
    assert_eq!(built.payload(), &[9]);
    assert_eq!(built.checksum(), 0xbeef);
    assert_eq!(&built.as_bytes()[12..14], &[0x60, 0x02]);
    assert_eq!(built.flags(), TcpFlags::SYN);
    assert_eq!(built.reserved(), 0);
    assert_eq!(&output[25..], &[0xa5]);
    let mut buffer = [0xa5; 25];
    let before = buffer;
    assert_eq!(
        TcpSegmentBuilder::new(&mut buffer, 0).build(),
        Err(TcpSegmentBuildError::MissingSourcePort)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        TcpSegmentBuilder::new(&mut buffer, 0)
            .source_port(1)
            .build(),
        Err(TcpSegmentBuildError::MissingDestinationPort)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        TcpSegmentBuilder::new(&mut buffer, 0)
            .source_port(1)
            .destination_port(2)
            .options(&[1])
            .build(),
        Err(TcpSegmentBuildError::InvalidOptionsLength)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        TcpSegmentBuilder::new(&mut buffer, 0)
            .source_port(1)
            .destination_port(2)
            .options(&[0; 44])
            .build(),
        Err(TcpSegmentBuildError::InvalidOptionsLength)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        TcpSegmentBuilder::new(&mut buffer, usize::MAX)
            .source_port(1)
            .destination_port(2)
            .build(),
        Err(TcpSegmentBuildError::SegmentLengthTooLarge)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        TcpSegmentBuilder::new(&mut buffer, 6)
            .source_port(1)
            .destination_port(2)
            .build(),
        Err(TcpSegmentBuildError::BufferTooShort {
            required: 26,
            available: 25
        })
    );
    assert_eq!(buffer, before);
}

#[cfg(feature = "ipv4")]
mod ipv4_checksum {
    use super::*;
    fn pseudo(s: Ipv4Address, d: Ipv4Address, segment: &[u8]) -> u16 {
        let mut bytes = [0u8; 33];
        bytes[..4].copy_from_slice(&s.octets());
        bytes[4..8].copy_from_slice(&d.octets());
        bytes[9] = 6;
        bytes[10..12].copy_from_slice(&(segment.len() as u16).to_be_bytes());
        bytes[12..].copy_from_slice(segment);
        checksum(&bytes)
    }
    #[test]
    fn known_wrong_stale_and_updated() {
        let s = Ipv4Address::new([192, 0, 2, 1]);
        let d = Ipv4Address::new([198, 51, 100, 2]);
        let wrong = Ipv4Address::new([198, 51, 100, 3]);
        let mut b = [
            0x12, 0x34, 0xab, 0xcd, 0, 0, 0, 3, 0, 0, 0, 4, 0x50, 0x12, 0x20, 0, 0, 0, 0, 7, 8,
        ];
        assert_eq!(pseudo(s, d, &b), 0xdd8a);
        let mut p = TcpSegmentMut::parse(&mut b).unwrap();
        p.update_checksum_ipv4(s, d).unwrap();
        assert_eq!(p.checksum(), 0xdd8a);
        assert!(p.checksum_is_valid_ipv4(s, d).unwrap());
        assert!(!p.checksum_is_valid_ipv4(s, wrong).unwrap());
        p.set_source_port(3);
        assert!(!p.checksum_is_valid_ipv4(s, d).unwrap());
        p.update_checksum_ipv4(s, d).unwrap();
        assert!(p.checksum_is_valid_ipv4(s, d).unwrap());
    }
}

#[cfg(feature = "ipv6")]
mod ipv6_checksum {
    use super::*;
    fn pseudo(s: Ipv6Address, d: Ipv6Address, segment: &[u8]) -> u16 {
        let mut bytes = [0u8; 61];
        bytes[..16].copy_from_slice(&s.octets());
        bytes[16..32].copy_from_slice(&d.octets());
        bytes[32..36].copy_from_slice(&(segment.len() as u32).to_be_bytes());
        bytes[39] = 6;
        bytes[40..].copy_from_slice(segment);
        checksum(&bytes)
    }
    #[test]
    fn known_wrong_stale_and_updated() {
        let s = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let d = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let wrong = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        let mut b = [
            0x12, 0x34, 0xab, 0xcd, 0, 0, 0, 3, 0, 0, 0, 4, 0x50, 0x12, 0x20, 0, 0, 0, 0, 7, 8,
        ];
        assert_eq!(pseudo(s, d, &b), 0x6e4d);
        let mut p = TcpSegmentMut::parse(&mut b).unwrap();
        p.update_checksum_ipv6(s, d).unwrap();
        assert_eq!(p.checksum(), 0x6e4d);
        assert!(p.checksum_is_valid_ipv6(s, d).unwrap());
        assert!(!p.checksum_is_valid_ipv6(s, wrong).unwrap());
        p.set_source_port(3);
        assert!(!p.checksum_is_valid_ipv6(s, d).unwrap());
        p.update_checksum_ipv6(s, d).unwrap();
        assert!(p.checksum_is_valid_ipv6(s, d).unwrap());
    }
}
