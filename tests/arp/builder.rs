use net_wire::arp::{
    ArpHardwareType, ArpOperation, ArpPacketBuilder, ArpPacketWriteError, ArpProtocolType,
};

use super::fixtures::GENERIC;

fn builder<'a>() -> ArpPacketBuilder<'a> {
    ArpPacketBuilder::new()
        .hardware_type(ArpHardwareType::new(0x1234))
        .protocol_type(ArpProtocolType::new(0xbeef))
        .operation(ArpOperation::new(0xcafe))
        .sender_hardware_address(&[1, 2, 3])
        .sender_protocol_address(&[4, 5])
        .target_hardware_address(&[6, 7, 8])
        .target_protocol_address(&[9, 10])
}

#[test]
fn builder_derives_lengths_and_preserves_output_suffix() {
    let mut bytes = [0xa5; 23];
    let (packet, suffix) = builder().build_into(&mut bytes).unwrap();
    assert_eq!(packet.as_bytes(), &GENERIC[..18]);
    assert_eq!(packet.hardware_type(), ArpHardwareType::new(0x1234));
    assert_eq!(packet.hardware_type_raw(), 0x1234);
    assert_eq!(packet.protocol_type(), ArpProtocolType::new(0xbeef));
    assert_eq!(packet.protocol_type_raw(), 0xbeef);
    assert_eq!(packet.operation(), ArpOperation::new(0xcafe));
    assert_eq!(packet.operation_raw(), 0xcafe);
    assert_eq!(packet.hardware_address_length(), 3);
    assert_eq!(packet.protocol_address_length(), 2);
    assert_eq!(suffix, &[0xa5; 5]);
}

#[test]
fn builder_raw_inputs_replace_semantic_inputs() {
    let mut bytes = [0; 18];
    let (packet, _) = ArpPacketBuilder::new()
        .hardware_type(ArpHardwareType::ETHERNET)
        .hardware_type_raw(0x1234)
        .protocol_type(ArpProtocolType::IPV4)
        .protocol_type_raw(0xbeef)
        .operation(ArpOperation::REQUEST)
        .operation_raw(0xcafe)
        .sender_hardware_address(&[1, 2, 3])
        .sender_protocol_address(&[4, 5])
        .target_hardware_address(&[6, 7, 8])
        .target_protocol_address(&[9, 10])
        .build_into(&mut bytes)
        .unwrap();
    assert_eq!(packet.hardware_type(), ArpHardwareType::new(0x1234));
    assert_eq!(packet.hardware_type_raw(), 0x1234);
    assert_eq!(packet.protocol_type(), ArpProtocolType::new(0xbeef));
    assert_eq!(packet.protocol_type_raw(), 0xbeef);
    assert_eq!(packet.operation(), ArpOperation::new(0xcafe));
    assert_eq!(packet.operation_raw(), 0xcafe);
}

#[test]
fn builder_accepts_zero_lengths_and_rejects_invalid_requests_atomically() {
    let mut zero = [0xa5; 9];
    let (packet, suffix) = ArpPacketBuilder::new()
        .hardware_type(ArpHardwareType::ETHERNET)
        .protocol_type(ArpProtocolType::IPV4)
        .operation(ArpOperation::REQUEST)
        .sender_hardware_address(&[])
        .sender_protocol_address(&[])
        .target_hardware_address(&[])
        .target_protocol_address(&[])
        .build_into(&mut zero)
        .unwrap();
    assert_eq!(packet.as_bytes().len(), 8);
    assert_eq!(suffix, &[0xa5]);

    let mut output = [0xa5; 32];
    let before = output;
    assert!(matches!(
        builder()
            .target_hardware_address(&[6, 7])
            .build_into(&mut output),
        Err(ArpPacketWriteError::ConflictingRangeSources {
            source_position: 3,
            first_range_position: 6,
            conflicting_range_position: 8,
            expected: 3,
            actual: 2,
        })
    ));
    assert_eq!(output, before);

    let mut output = [0xa5; 32];
    let before = output;
    assert!(matches!(
        builder()
            .target_protocol_address(&[9])
            .build_into(&mut output),
        Err(ArpPacketWriteError::ConflictingRangeSources {
            source_position: 4,
            first_range_position: 7,
            conflicting_range_position: 9,
            expected: 2,
            actual: 1,
        })
    ));
    assert_eq!(output, before);

    let long = [0u8; 256];
    let mut output = [0xa5; 600];
    let before = output;
    assert!(matches!(
        builder()
            .sender_hardware_address(&long)
            .target_hardware_address(&long)
            .build_into(&mut output),
        Err(ArpPacketWriteError::InvalidRangeSource {
            position: 6,
            source_position: 3,
            value: 256,
        })
    ));
    assert_eq!(output, before);

    let mut output = [0xa5; 600];
    let before = output;
    assert!(matches!(
        builder()
            .sender_protocol_address(&long)
            .target_protocol_address(&long)
            .build_into(&mut output),
        Err(ArpPacketWriteError::InvalidRangeSource {
            position: 7,
            source_position: 4,
            value: 256,
        })
    ));
    assert_eq!(output, before);

    let mut output = [0xa5; 32];
    let before = output;
    assert!(matches!(
        ArpPacketBuilder::new().build_into(&mut output),
        Err(ArpPacketWriteError::MissingField {
            field: "hardware_type"
        })
    ));
    assert_eq!(output, before);

    let mut short = [0xa5; 17];
    let before = short;
    assert!(matches!(
        builder().build_into(&mut short),
        Err(ArpPacketWriteError::OutputTooShort {
            expected: 18,
            actual: 17,
        })
    ));
    assert_eq!(short, before);
}
