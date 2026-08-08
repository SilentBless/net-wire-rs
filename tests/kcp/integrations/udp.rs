use net_wire::kcp::{KcpSegmentParseError, KcpSegmentsParseError};
use net_wire::udp::UdpDatagram;

use super::fixtures::SEGMENT;

#[test]
fn udp_adapter_validates_exact_complete_kcp_payloads() {
    let datagram = [
        0, 1, 0, 2, 0, 35, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x51, 0x02, 0x66, 0x55, 0xaa, 0x99, 0x88,
        0x77, 0xee, 0xdd, 0xcc, 0xbb, 0x67, 0x45, 0x23, 0x01, 0x03, 0x00, 0x00, 0x00, 0xde, 0xad,
        0xbe,
    ];
    let datagram = UdpDatagram::parse(&datagram).unwrap();
    assert_eq!(datagram.kcp_segments().unwrap().as_bytes(), SEGMENT);

    let empty = UdpDatagram::parse(&[0, 1, 0, 2, 0, 8, 0, 0]).unwrap();
    assert_eq!(
        empty.kcp_segments(),
        Err(KcpSegmentsParseError::EmptySequence)
    );

    let malformed = [
        0, 1, 0, 2, 0, 40, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x51, 0x02, 0x66, 0x55, 0xaa, 0x99, 0x88,
        0x77, 0xee, 0xdd, 0xcc, 0xbb, 0x67, 0x45, 0x23, 0x01, 0x03, 0x00, 0x00, 0x00, 0xde, 0xad,
        0xbe, 0, 0, 0, 0, 0,
    ];
    let malformed = UdpDatagram::parse(&malformed).unwrap();
    assert_eq!(
        malformed.kcp_segments(),
        Err(KcpSegmentsParseError::Segment {
            offset: 27,
            error: KcpSegmentParseError::HeaderTruncated {
                required: 24,
                available: 5
            }
        })
    );
}
