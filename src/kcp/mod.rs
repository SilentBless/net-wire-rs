//! Allocation-free KCP wire segment views and stateless scalar helpers.
//!
//! This module intentionally excludes KCP endpoint state, retransmission, timers, congestion
//! control, callbacks, and transport policy. When both KCP and UDP are enabled, it provides only
//! an immutable UDP-payload adapter.

mod builder;
mod error;
mod segment;
mod segments;
mod types;
#[cfg(feature = "udp")]
mod udp;

pub use builder::KcpSegmentBuilder;
pub use error::{KcpSegmentBuildError, KcpSegmentParseError, KcpSegmentsParseError};
pub use segment::{KCP_SEGMENT_HEADER_LEN, KcpSegment, KcpSegmentMut};
pub use segments::{KcpSegmentIter, KcpSegments};
pub use types::{
    KcpCommand, KcpConversationId, KcpFragment, KcpKnownCommand, KcpSequenceNumber, KcpTimestamp,
    KcpUnacknowledged,
};
