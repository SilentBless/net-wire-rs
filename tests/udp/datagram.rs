use net_wire::{ParseError, udp::*};

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
