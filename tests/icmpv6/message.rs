use net_wire::ParseError;
use net_wire::icmpv6::{
    Icmpv6Message, Icmpv6MessageBuildError, Icmpv6MessageBuilder, Icmpv6MessageMut, Icmpv6Type,
};

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
