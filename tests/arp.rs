use net_wire::*;

const GENERIC: [u8; 21] = [
    0x12, 0x34, 0xbe, 0xef, 3, 2, 0xca, 0xfe, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xee,
];

fn built_from_local<'a>(buffer: &'a mut [u8]) -> ArpPacketMut<'a> {
    let sender_hardware = [1, 2, 3];
    let sender_protocol = [4, 5];
    let target_hardware = [6, 7, 8];
    let target_protocol = [9, 10];
    ArpPacketBuilder::new(buffer)
        .hardware_type(ArpHardwareType::new(0x1234))
        .protocol_type(ArpProtocolType::new(0xbeef))
        .operation(ArpOperation::new(0xcafe))
        .addresses(
            &sender_hardware,
            &sender_protocol,
            &target_hardware,
            &target_protocol,
        )
        .build()
        .unwrap()
}

#[test]
fn generic_rfc826_layout_preserves_unknowns_and_bounds() {
    let packet = ArpPacket::parse(&GENERIC).unwrap();
    assert_eq!(packet.hardware_type().raw(), 0x1234);
    assert_eq!(packet.protocol_type().raw(), 0xbeef);
    assert_eq!(packet.operation().raw(), 0xcafe);
    assert_eq!(
        (
            packet.hardware_address_length(),
            packet.protocol_address_length(),
            packet.hlen(),
            packet.plen()
        ),
        (3, 2, 3, 2)
    );
    assert_eq!(packet.sender_hardware_address(), &[1, 2, 3]);
    assert_eq!(packet.sender_protocol_address(), &[4, 5]);
    assert_eq!(packet.target_hardware_address(), &[6, 7, 8]);
    assert_eq!(packet.target_protocol_address(), &[9, 10]);
    assert_eq!(packet.as_bytes(), &GENERIC[..18]);
}

#[test]
fn parsing_accepts_zero_addresses_and_rejects_short_layouts() {
    assert_eq!(
        ArpPacket::parse(&GENERIC[..7]),
        Err(ParseError::Truncated {
            minimum: 8,
            available: 7
        })
    );
    assert_eq!(
        ArpPacket::parse(&GENERIC[..17]),
        Err(ParseError::Truncated {
            minimum: 18,
            available: 17
        })
    );
    let zero = ArpPacket::parse(&[0, 1, 8, 0, 0, 0, 0, 1, 0xaa]).unwrap();
    assert_eq!(zero.as_bytes(), &[0, 1, 8, 0, 0, 0, 0, 1]);
    assert_eq!(zero.sender_hardware_address(), &[]);
    assert_eq!(zero.target_protocol_address(), &[]);
}

#[test]
fn mutable_view_changes_fields_and_not_lengths() {
    let mut bytes = GENERIC;
    let mut packet = ArpPacketMut::parse(&mut bytes).unwrap();
    assert_eq!(
        (
            packet.hardware_type().raw(),
            packet.protocol_type().raw(),
            packet.operation().raw()
        ),
        (0x1234, 0xbeef, 0xcafe)
    );
    packet.set_hardware_type(ArpHardwareType::ETHERNET);
    packet.set_protocol_type(ArpProtocolType::IPV4);
    packet.set_operation(ArpOperation::REPLY);
    packet
        .sender_hardware_address_mut()
        .copy_from_slice(&[13, 14, 15]);
    packet
        .sender_protocol_address_mut()
        .copy_from_slice(&[16, 17]);
    packet
        .target_hardware_address_mut()
        .copy_from_slice(&[18, 19, 20]);
    packet
        .target_protocol_address_mut()
        .copy_from_slice(&[21, 22]);
    packet.as_bytes_mut()[7] = 1;
    assert_eq!(
        (
            packet.hardware_address_length(),
            packet.protocol_address_length(),
            packet.hlen(),
            packet.plen()
        ),
        (3, 2, 3, 2)
    );
    assert_eq!(packet.sender_hardware_address(), &[13, 14, 15]);
    assert_eq!(packet.sender_protocol_address(), &[16, 17]);
    assert_eq!(packet.target_hardware_address(), &[18, 19, 20]);
    assert_eq!(packet.target_protocol_address(), &[21, 22]);
    assert_eq!(packet.as_bytes().len(), 18);
}

#[test]
fn builder_writes_independent_rfc826_fixture_only() {
    let mut bytes = [0xa5; 23];
    let packet = built_from_local(&mut bytes);
    assert_eq!(packet.as_bytes(), &GENERIC[..18]);
    assert_eq!(packet.as_bytes().len(), 18);
    assert_eq!(&bytes[18..], &[0xa5; 5]);
}

#[test]
fn builder_errors_are_precedence_exact_and_atomic() {
    let hw = [1u8; 3];
    let proto = [2u8; 2];
    let long = [0u8; 256];
    macro_rules! check {
        ($builder:expr, $error:expr) => {{
            let mut b = [0xa5; 32];
            let before = b;
            assert_eq!($builder(&mut b), Err($error));
            assert_eq!(b, before);
        }};
    }
    fn build_missing_hw(b: &mut [u8]) -> Result<ArpPacketMut<'_>, ArpPacketBuildError> {
        ArpPacketBuilder::new(b).build()
    }
    fn build_missing_proto(b: &mut [u8]) -> Result<ArpPacketMut<'_>, ArpPacketBuildError> {
        ArpPacketBuilder::new(b)
            .hardware_type(ArpHardwareType::ETHERNET)
            .build()
    }
    fn build_missing_op(b: &mut [u8]) -> Result<ArpPacketMut<'_>, ArpPacketBuildError> {
        ArpPacketBuilder::new(b)
            .hardware_type(ArpHardwareType::ETHERNET)
            .protocol_type(ArpProtocolType::IPV4)
            .build()
    }
    fn build_missing_addresses(b: &mut [u8]) -> Result<ArpPacketMut<'_>, ArpPacketBuildError> {
        ArpPacketBuilder::new(b)
            .hardware_type(ArpHardwareType::ETHERNET)
            .protocol_type(ArpProtocolType::IPV4)
            .operation(ArpOperation::REQUEST)
            .build()
    }
    check!(build_missing_hw, ArpPacketBuildError::MissingHardwareType);
    check!(
        build_missing_proto,
        ArpPacketBuildError::MissingProtocolType
    );
    check!(build_missing_op, ArpPacketBuildError::MissingOperation);
    check!(
        build_missing_addresses,
        ArpPacketBuildError::MissingAddresses
    );
    let mut b = [0xa5; 32];
    let before = b;
    assert_eq!(
        ArpPacketBuilder::new(&mut b)
            .hardware_type(ArpHardwareType::ETHERNET)
            .protocol_type(ArpProtocolType::IPV4)
            .operation(ArpOperation::REQUEST)
            .addresses(&hw, &proto, &[3; 2], &proto)
            .build(),
        Err(ArpPacketBuildError::AddressLengthMismatch)
    );
    assert_eq!(b, before);
    let mut b = [0xa5; 32];
    let before = b;
    assert_eq!(
        ArpPacketBuilder::new(&mut b)
            .hardware_type(ArpHardwareType::ETHERNET)
            .protocol_type(ArpProtocolType::IPV4)
            .operation(ArpOperation::REQUEST)
            .addresses(&hw, &proto, &hw, &[3])
            .build(),
        Err(ArpPacketBuildError::AddressLengthMismatch)
    );
    assert_eq!(b, before);
    let mut b = [0xa5; 600];
    let before = b;
    assert_eq!(
        ArpPacketBuilder::new(&mut b)
            .hardware_type(ArpHardwareType::ETHERNET)
            .protocol_type(ArpProtocolType::IPV4)
            .operation(ArpOperation::REQUEST)
            .addresses(&long, &proto, &long, &proto)
            .build(),
        Err(ArpPacketBuildError::AddressLengthTooLarge)
    );
    assert_eq!(b, before);
    // A 17-byte caller buffer cannot hold the 18-byte encoded layout.
    let mut short = [0xa5; 17];
    let before = short;
    assert_eq!(
        ArpPacketBuilder::new(&mut short)
            .hardware_type(ArpHardwareType::new(0x1234))
            .protocol_type(ArpProtocolType::new(0xbeef))
            .operation(ArpOperation::new(0xcafe))
            .addresses(&hw, &proto, &hw, &proto)
            .build(),
        Err(ArpPacketBuildError::BufferTooShort {
            required: 18,
            available: 17
        })
    );
    assert_eq!(short, before);
}
#[cfg(feature = "ethernet")]
mod ethernet_dispatch {
    use super::*;

    fn frame(ether_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 14];
        bytes[12..14].copy_from_slice(&ether_type.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn arp_dispatch_validates_ether_type_and_mac_helpers() {
        let arp = [
            0, 1, 8, 0, 6, 4, 0, 1, 1, 2, 3, 4, 5, 6, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2,
        ];
        assert_eq!(
            EthernetFrame::parse(&frame(0x0800, &arp))
                .unwrap()
                .arp()
                .unwrap(),
            None
        );

        let bytes = frame(0x0806, &arp);
        let packet = EthernetFrame::parse(&bytes)
            .unwrap()
            .arp()
            .unwrap()
            .unwrap();
        assert_eq!(
            packet.sender_mac_address(),
            Some(MacAddress::new([1, 2, 3, 4, 5, 6]))
        );
        assert_eq!(packet.target_mac_address(), Some(MacAddress::new([0; 6])));

        assert_eq!(
            EthernetFrame::parse(&frame(0x0806, &arp[..7]))
                .unwrap()
                .arp(),
            Err(ParseError::Truncated {
                minimum: 8,
                available: 7
            })
        );

        let wrong_hardware_type = [
            0, 2, 8, 0, 6, 4, 0, 1, 1, 2, 3, 4, 5, 6, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2,
        ];
        assert_eq!(
            EthernetFrame::parse(&frame(0x0806, &wrong_hardware_type))
                .unwrap()
                .arp()
                .unwrap()
                .unwrap()
                .sender_mac_address(),
            None
        );

        let short_hardware_address = [
            0, 1, 8, 0, 5, 4, 0, 1, 1, 2, 3, 4, 5, 192, 0, 2, 1, 0, 0, 0, 0, 0, 192, 0, 2, 2,
        ];
        assert_eq!(
            EthernetFrame::parse(&frame(0x0806, &short_hardware_address))
                .unwrap()
                .arp()
                .unwrap()
                .unwrap()
                .target_mac_address(),
            None
        );
    }

    #[test]
    fn mutable_arp_dispatch_writes_frame_payload() {
        let mut bytes = frame(
            0x0806,
            &[0, 1, 8, 0, 1, 4, 0, 1, 9, 192, 0, 2, 1, 8, 192, 0, 2, 2],
        );
        let mut frame = EthernetFrameMut::parse(&mut bytes).unwrap();
        frame
            .arp_mut()
            .unwrap()
            .unwrap()
            .sender_protocol_address_mut()[3] = 9;
        assert_eq!(bytes[26], 9);
    }
}

#[cfg(feature = "ipv4")]
mod ipv4_helpers {
    use super::*;

    #[test]
    fn typed_ipv4_helpers_require_ipv4_type_and_four_octets() {
        let wrong_type = [
            0, 1, 0x12, 0x34, 1, 4, 0, 1, 9, 192, 0, 2, 1, 8, 192, 0, 2, 2,
        ];
        let wrong_length = [0, 1, 8, 0, 1, 3, 0, 1, 9, 192, 0, 2, 8, 192, 0, 3];
        assert_eq!(
            ArpPacket::parse(&wrong_type).unwrap().sender_ipv4_address(),
            None
        );
        assert_eq!(
            ArpPacket::parse(&wrong_length)
                .unwrap()
                .target_ipv4_address(),
            None
        );

        let valid = [0, 1, 8, 0, 1, 4, 0, 1, 9, 192, 0, 2, 1, 8, 192, 0, 2, 2];
        let packet = ArpPacket::parse(&valid).unwrap();
        assert_eq!(
            packet.sender_ipv4_address(),
            Some(Ipv4Address::new([192, 0, 2, 1]))
        );
        assert_eq!(
            packet.target_ipv4_address(),
            Some(Ipv4Address::new([192, 0, 2, 2]))
        );
    }
}
