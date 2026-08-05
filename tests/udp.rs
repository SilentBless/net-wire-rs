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

#[test]
fn parse_mutate_and_build_with_atomic_errors() {
    assert_eq!(
        UdpDatagram::parse(&[0; 7]),
        Err(ParseError::Truncated {
            minimum: 8,
            available: 7
        })
    );
    assert_eq!(
        UdpDatagram::parse(&[0, 1, 0, 2, 0, 7, 0, 0]),
        Err(ParseError::InvalidTotalLength {
            header_length: 8,
            total_length: 7
        })
    );
    assert_eq!(
        UdpDatagram::parse(&[0, 1, 0, 2, 0, 10, 0, 0]),
        Err(ParseError::Truncated {
            minimum: 10,
            available: 8
        })
    );
    let bytes = [0, 1, 0, 2, 0, 9, 0, 0, 7, 0xee];
    let packet = UdpDatagram::parse(&bytes).unwrap();
    assert_eq!(
        (
            packet.source_port(),
            packet.destination_port(),
            packet.length(),
            packet.checksum(),
            packet.payload(),
            packet.as_bytes()
        ),
        (1, 2, 9, 0, &[7][..], &bytes[..9])
    );
    let mut bytes = bytes;
    let mut packet = UdpDatagramMut::parse(&mut bytes).unwrap();
    packet.set_source_port(9);
    packet.set_destination_port(10);
    packet.set_checksum(0xbeef);
    packet.payload_mut()[0] = 4;
    packet.as_bytes_mut()[4..6].copy_from_slice(&9u16.to_be_bytes());
    assert_eq!(packet.as_bytes(), &[0, 9, 0, 10, 0, 9, 0xbe, 0xef, 4]);

    let mut output = [0xa5; 11];
    output[8..10].copy_from_slice(&[1, 2]);
    let built = UdpDatagramBuilder::new(&mut output, 2)
        .source_port(10)
        .destination_port(20)
        .checksum(0xbeef)
        .build()
        .unwrap();
    assert_eq!(built.as_bytes(), &[0, 10, 0, 20, 0, 10, 0xbe, 0xef, 1, 2]);
    assert_eq!(&output[10..], &[0xa5]);

    let mut buffer = [0xa5; 8];
    let before = buffer;
    assert_eq!(
        UdpDatagramBuilder::new(&mut buffer, 0).build(),
        Err(UdpDatagramBuildError::MissingDestinationPort)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        UdpDatagramBuilder::new(&mut buffer, usize::MAX)
            .destination_port(1)
            .build(),
        Err(UdpDatagramBuildError::DatagramLengthTooLarge)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        UdpDatagramBuilder::new(&mut buffer, 65_528)
            .destination_port(1)
            .build(),
        Err(UdpDatagramBuildError::DatagramLengthTooLarge)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        UdpDatagramBuilder::new(&mut buffer, 1)
            .destination_port(1)
            .build(),
        Err(UdpDatagramBuildError::BufferTooShort {
            required: 9,
            available: 8
        })
    );
    assert_eq!(buffer, before);
}

#[cfg(feature = "ipv4")]
mod ipv4_checksum {
    use super::*;
    fn pseudo(source: Ipv4Address, destination: Ipv4Address, datagram: &[u8]) -> u16 {
        let mut bytes = [0u8; 22];
        bytes[..4].copy_from_slice(&source.octets());
        bytes[4..8].copy_from_slice(&destination.octets());
        bytes[9] = 17;
        bytes[10..12].copy_from_slice(&(datagram.len() as u16).to_be_bytes());
        bytes[12..].copy_from_slice(datagram);
        checksum(&bytes)
    }
    #[test]
    fn ipv4_statuses_known_checksum_and_zero_encoding() {
        let source = Ipv4Address::new([192, 0, 2, 1]);
        let destination = Ipv4Address::new([198, 51, 100, 2]);
        let mut bytes = [0x12, 0x34, 0xab, 0xcd, 0, 10, 0, 0, 0xde, 0xad];
        assert_eq!(pseudo(source, destination, &bytes), 0x76f3);
        let mut d = UdpDatagramMut::parse(&mut bytes).unwrap();
        assert_eq!(
            d.checksum_status_ipv4(source, destination),
            UdpChecksumStatus::NotPresent
        );
        d.update_checksum_ipv4(source, destination);
        assert_eq!(d.checksum(), 0x76f3);
        assert_eq!(
            d.checksum_status_ipv4(source, destination),
            UdpChecksumStatus::Valid
        );
        d.set_source_port(3);
        assert_eq!(
            d.checksum_status_ipv4(source, destination),
            UdpChecksumStatus::Invalid
        );
        let mut zero = [0x12, 0x34, 0xab, 0xcd, 0, 10, 0, 0, 0x55, 0xa1];
        assert_eq!(pseudo(source, destination, &zero), 0);
        let mut zero = UdpDatagramMut::parse(&mut zero).unwrap();
        zero.update_checksum_ipv4(source, destination);
        assert_eq!(zero.checksum(), 0xffff);
    }
}

#[cfg(feature = "ipv6")]
mod ipv6_checksum {
    use super::*;
    fn pseudo(source: Ipv6Address, destination: Ipv6Address, datagram: &[u8]) -> u16 {
        let mut bytes = [0u8; 50];
        bytes[..16].copy_from_slice(&source.octets());
        bytes[16..32].copy_from_slice(&destination.octets());
        bytes[32..36].copy_from_slice(&(datagram.len() as u32).to_be_bytes());
        bytes[39] = 17;
        bytes[40..].copy_from_slice(datagram);
        checksum(&bytes)
    }
    #[test]
    fn ipv6_zero_is_invalid_and_update_uses_pseudoheader() {
        let source = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let destination =
            Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut bytes = [0x12, 0x34, 0xab, 0xcd, 0, 10, 0, 0, 0xde, 0xad];
        assert_eq!(pseudo(source, destination, &bytes), 0x07b6);
        let mut d = UdpDatagramMut::parse(&mut bytes).unwrap();
        assert!(!d.checksum_is_valid_ipv6(source, destination));
        d.update_checksum_ipv6(source, destination);
        assert_eq!(d.checksum(), 0x07b6);
        assert!(d.checksum_is_valid_ipv6(source, destination));
        d.set_checksum(1);
        assert!(!d.checksum_is_valid_ipv6(source, destination));
    }
}
