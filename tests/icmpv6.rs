use net_wire::*;

#[test]
fn layout_mutation_and_builder_errors_are_bounded_and_atomic() {
    let bytes = [0xfe, 0xa5, 0x12, 0x34, 1, 2, 3];
    let message = Icmpv6Message::parse(&bytes).unwrap();
    assert_eq!(
        (
            message.message_type().raw(),
            message.code(),
            message.checksum(),
            message.body(),
            message.as_bytes()
        ),
        (0xfe, 0xa5, 0x1234, &[1, 2, 3][..], &bytes[..])
    );
    assert_eq!(
        Icmpv6Message::parse(&bytes[..3]),
        Err(ParseError::Truncated {
            minimum: 4,
            available: 3
        })
    );

    let mut mutable = bytes;
    let mut message = Icmpv6MessageMut::parse(&mut mutable).unwrap();
    message.set_message_type(Icmpv6Type::ECHO_REPLY);
    message.set_code(4);
    message.set_checksum(0xbeef);
    message.body_mut()[2] = 9;
    message.as_bytes_mut()[4] = 7;
    assert_eq!(message.as_bytes(), &[129, 4, 0xbe, 0xef, 7, 2, 9]);

    let mut output = [0xa5; 8];
    output[4..7].copy_from_slice(&[7, 8, 9]);
    let built = Icmpv6MessageBuilder::new(&mut output, 3)
        .message_type(Icmpv6Type::new(250))
        .code(1)
        .checksum(0xbeef)
        .build()
        .unwrap();
    assert_eq!(built.as_bytes(), &[250, 1, 0xbe, 0xef, 7, 8, 9]);
    assert_eq!(&output[7..], &[0xa5]);

    let mut buffer = [0xa5; 8];
    let before = buffer;
    assert_eq!(
        Icmpv6MessageBuilder::new(&mut buffer, 0).build(),
        Err(Icmpv6MessageBuildError::MissingType)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        Icmpv6MessageBuilder::new(&mut buffer, 0)
            .message_type(Icmpv6Type::ECHO_REQUEST)
            .build(),
        Err(Icmpv6MessageBuildError::MissingCode)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        Icmpv6MessageBuilder::new(&mut buffer, usize::MAX)
            .message_type(Icmpv6Type::ECHO_REQUEST)
            .code(0)
            .build(),
        Err(Icmpv6MessageBuildError::MessageLengthTooLarge)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        Icmpv6MessageBuilder::new(&mut buffer, 5)
            .message_type(Icmpv6Type::ECHO_REQUEST)
            .code(0)
            .build(),
        Err(Icmpv6MessageBuildError::BufferTooShort {
            required: 9,
            available: 8
        })
    );
    assert_eq!(buffer, before);
}

#[cfg(feature = "ipv6")]
mod ipv6_checksum {
    use super::*;

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

    fn pseudo(source: Ipv6Address, destination: Ipv6Address, message: &[u8]) -> u16 {
        let mut bytes = [0u8; 49];
        bytes[..16].copy_from_slice(&source.octets());
        bytes[16..32].copy_from_slice(&destination.octets());
        bytes[32..36].copy_from_slice(&(message.len() as u32).to_be_bytes());
        bytes[39] = 58;
        bytes[40..40 + message.len()].copy_from_slice(message);
        checksum(&bytes[..40 + message.len()])
    }

    #[test]
    fn ipv6_checksum_handles_an_odd_message_length() {
        let source = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let destination =
            Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut bytes = [128, 0, 0, 0, 0, 1, 0, 2, 0xaa];
        let expected = pseudo(source, destination, &bytes);
        assert_eq!(expected, 0x7a43);
        bytes[2..4].copy_from_slice(&expected.to_be_bytes());

        assert!(
            Icmpv6Message::parse(&bytes)
                .unwrap()
                .checksum_is_valid_ipv6(source, destination)
                .unwrap()
        );
    }

    #[test]
    fn ipv6_checksum_rejects_wrong_addresses_and_stale_bytes_then_updates() {
        let source = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let destination =
            Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let wrong = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        let mut bytes = [128, 0, 0, 0, 0, 1, 0, 2];
        let want = pseudo(source, destination, &bytes);
        assert_eq!(want, 0x2445);
        bytes[2..4].copy_from_slice(&want.to_be_bytes());
        assert!(
            Icmpv6Message::parse(&bytes)
                .unwrap()
                .checksum_is_valid_ipv6(source, destination)
                .unwrap()
        );
        assert!(
            !Icmpv6Message::parse(&bytes)
                .unwrap()
                .checksum_is_valid_ipv6(source, wrong)
                .unwrap()
        );
        let mut message = Icmpv6MessageMut::parse(&mut bytes).unwrap();
        message.body_mut()[0] = 9;
        assert!(!message.checksum_is_valid_ipv6(source, destination).unwrap());
        message.update_checksum_ipv6(source, destination).unwrap();
        assert_eq!(
            message.checksum(),
            pseudo(source, destination, &[128, 0, 0, 0, 9, 1, 0, 2])
        );
        assert!(message.checksum_is_valid_ipv6(source, destination).unwrap());
    }
}
