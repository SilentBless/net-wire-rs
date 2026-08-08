use net_wire::icmpv4::{Icmpv4MessageBuildError, Icmpv4MessageBuilder, Icmpv4Type};

#[test]
fn builder_is_exact_and_all_failures_are_atomic() {
    let mut output = [0xa5; 8];
    output[4..7].copy_from_slice(&[7, 8, 9]);
    let built = Icmpv4MessageBuilder::new(&mut output, 3)
        .message_type(Icmpv4Type::new(250))
        .code(17)
        .build()
        .unwrap();
    assert_eq!(built.as_bytes(), &[250, 17, 0xf5, 0xe5, 7, 8, 9]);
    assert_eq!(&output[7..], &[0xa5]);

    let mut buffer = [0xa5; 8];
    let before = buffer;
    assert_eq!(
        Icmpv4MessageBuilder::new(&mut buffer, 0).build(),
        Err(Icmpv4MessageBuildError::MissingType)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        Icmpv4MessageBuilder::new(&mut buffer, 0)
            .message_type(Icmpv4Type::ECHO_REQUEST)
            .build(),
        Err(Icmpv4MessageBuildError::MissingCode)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        Icmpv4MessageBuilder::new(&mut buffer, usize::MAX)
            .message_type(Icmpv4Type::ECHO_REQUEST)
            .code(0)
            .build(),
        Err(Icmpv4MessageBuildError::MessageLengthTooLarge)
    );
    assert_eq!(buffer, before);
    assert_eq!(
        Icmpv4MessageBuilder::new(&mut buffer, 5)
            .message_type(Icmpv4Type::ECHO_REQUEST)
            .code(0)
            .build(),
        Err(Icmpv4MessageBuildError::BufferTooShort {
            required: 9,
            available: 8
        })
    );
    assert_eq!(buffer, before);
}
