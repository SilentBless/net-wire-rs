use net_wire::ParseError;
use net_wire::icmpv4::{Icmpv4Message, Icmpv4MessageMut, Icmpv4Type};

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
fn parsing_is_checksum_permissive_and_has_a_known_vector() {
    let invalid = [0xfe, 0xa5, 0x43, 0x56, 1, 2, 3];
    let message = Icmpv4Message::parse(&invalid).unwrap();
    assert_eq!(
        (
            message.message_type().raw(),
            message.code(),
            message.checksum(),
            message.body()
        ),
        (0xfe, 0xa5, 0x4356, &[1, 2, 3][..])
    );
    assert_eq!(message.as_bytes(), &invalid);
    assert!(!message.checksum_is_valid());
    assert_eq!(
        Icmpv4Message::parse(&invalid[..3]),
        Err(ParseError::Truncated {
            minimum: 4,
            available: 3
        })
    );

    let known = [8, 0, 0x4d, 0xfc, 0, 1, 0, 2, 0xaa];
    assert_eq!(checksum(&[8, 0, 0, 0, 0, 1, 0, 2, 0xaa]), 0x4dfc);
    assert!(Icmpv4Message::parse(&known).unwrap().checksum_is_valid());
}

#[test]
fn mutable_setters_and_raw_bytes_leave_checksum_stale_until_updated() {
    let mut bytes = [8, 0, 0x4d, 0xfc, 0, 1, 0, 2, 0xaa];
    let mut message = Icmpv4MessageMut::parse(&mut bytes).unwrap();
    message.set_message_type(Icmpv4Type::ECHO_REPLY);
    message.set_code(9);
    message.set_checksum(0xbeef);
    message.body_mut()[0] = 7;
    message.as_bytes_mut()[8] = 3;
    assert_eq!(message.as_bytes(), &[0, 9, 0xbe, 0xef, 7, 1, 0, 2, 3]);
    assert!(!message.checksum_is_valid());
    message.update_checksum();
    assert_eq!(message.checksum(), checksum(&[0, 9, 0, 0, 7, 1, 0, 2, 3]));
    assert!(message.checksum_is_valid());
}
