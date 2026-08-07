//! Immutable UDP payload integration for KCP segment sequences.

use crate::udp::UdpDatagram;

use super::{KcpSegments, KcpSegmentsParseError};

impl<'a> UdpDatagram<'a> {
    /// Validates the complete UDP payload as a nonempty KCP segment sequence.
    pub fn kcp_segments(&self) -> Result<KcpSegments<'a>, KcpSegmentsParseError> {
        KcpSegments::parse(self.payload())
    }
}
