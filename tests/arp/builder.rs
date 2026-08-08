use net_wire::arp::{
    ArpHardwareType, ArpOperation, ArpPacketBuildError, ArpPacketBuilder, ArpPacketMut,
    ArpProtocolType,
};

use super::fixtures::GENERIC;

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
